use std::{
    mem::{size_of, size_of_val, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INVALID_DATA, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
};

use crate::private_remote_policy::{tailscale_ip, TAILSCALE_INTERFACE_DESCRIPTION};

// default-net 0.14 drops IF_TYPE_PROP_VIRTUAL (53), including Tailscale's adapter.
// Read the OS list directly; identity and address checks still fail closed.
pub(crate) fn for_each_address(mut visit: impl FnMut(IpAddr)) -> Result<(), u32> {
    const ELEMENTS: usize = 16_384 / size_of::<IP_ADAPTER_ADDRESSES_LH>() + 1;
    let mut stack = [MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::uninit(); ELEMENTS];
    let mut heap = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
    let mut buffer = stack.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut capacity = size_of_val(&stack) as u32;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    for _ in 0..3 {
        let mut required = capacity;
        // SAFETY: the buffer is aligned for the API's structs and has capacity bytes.
        let status = unsafe {
            GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buffer), &mut required)
        };
        if status == NO_ERROR.0 {
            // SAFETY: the successful API call initialized this list and its backing data.
            unsafe { visit_adapters(buffer, &mut visit) };
            return Ok(());
        }
        if status == ERROR_NO_DATA.0 {
            return Ok(());
        }
        if status != ERROR_BUFFER_OVERFLOW.0 {
            return Err(status);
        }
        if required == 0 {
            return Err(ERROR_INVALID_DATA.0);
        }
        let elements = (required as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        heap.try_reserve_exact(elements).map_err(|_| ERROR_NOT_ENOUGH_MEMORY.0)?;
        buffer = heap.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        capacity = required;
    }
    Err(ERROR_BUFFER_OVERFLOW.0)
}

fn description_matches(value: &[u16]) -> bool {
    let expected = TAILSCALE_INTERFACE_DESCRIPTION.as_bytes();
    value.len() == expected.len() && value.iter().zip(expected).all(|(&actual, &expected)| {
        actual <= 127 && (actual as u8).eq_ignore_ascii_case(&expected)
    })
}

// The list, strings and socket addresses must remain valid for the entire visit.
unsafe fn visit_adapters(mut adapter: *mut IP_ADAPTER_ADDRESSES_LH, visit: &mut impl FnMut(IpAddr)) {
    while let Some(current) = adapter.as_ref() {
        if !current.Description.is_null() && description_matches(current.Description.as_wide()) {
            let mut address = current.FirstUnicastAddress;
            while let Some(unicast) = address.as_ref() {
                let socket = &unicast.Address;
                if !socket.lpSockaddr.is_null() && socket.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 {
                    let family = (*socket.lpSockaddr).sa_family;
                    let ip = if family == AF_INET {
                        let value = &*socket.lpSockaddr.cast::<SOCKADDR_IN>();
                        Some(IpAddr::V4(Ipv4Addr::from(value.sin_addr.S_un.S_addr.to_ne_bytes())))
                    } else if family == AF_INET6 && socket.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 {
                        let value = &*socket.lpSockaddr.cast::<SOCKADDR_IN6>();
                        Some(IpAddr::V6(Ipv6Addr::from(value.sin6_addr.u.Byte)))
                    } else {
                        None
                    };
                    if let Some(ip) = ip.filter(|ip| tailscale_ip(*ip)) {
                        visit(ip);
                    }
                }
                address = unicast.Next;
            }
        }
        adapter = current.Next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::{core::PWSTR, Win32::{NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
        Networking::WinSock::{SOCKADDR, SOCKET_ADDRESS}}};

    #[test]
    fn virtual_tailscale_type_53_keeps_ipv4_and_ipv6() {
        let mut description: Vec<u16> = "tAiLsCaLe tUnNeL".encode_utf16().chain(Some(0)).collect();
        let mut ipv4 = SOCKADDR_IN { sin_family: AF_INET, ..Default::default() };
        ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([100, 70, 87, 52]);
        let ipv6_bytes = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut ipv6 = SOCKADDR_IN6 { sin6_family: AF_INET6, ..Default::default() };
        ipv6.sin6_addr.u.Byte = ipv6_bytes;
        let mut address6 = IP_ADAPTER_UNICAST_ADDRESS_LH {
            Address: SOCKET_ADDRESS { lpSockaddr: (&mut ipv6 as *mut SOCKADDR_IN6).cast::<SOCKADDR>(),
                iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32 },
            ..Default::default()
        };
        let mut address4 = IP_ADAPTER_UNICAST_ADDRESS_LH {
            Next: &mut address6,
            Address: SOCKET_ADDRESS { lpSockaddr: (&mut ipv4 as *mut SOCKADDR_IN).cast::<SOCKADDR>(),
                iSockaddrLength: size_of::<SOCKADDR_IN>() as i32 },
            ..Default::default()
        };
        let mut adapter = IP_ADAPTER_ADDRESSES_LH {
            IfType: 53, Description: PWSTR(description.as_mut_ptr()), FirstUnicastAddress: &mut address4,
            ..Default::default()
        };
        let mut found = Vec::new();
        // SAFETY: all addresses and UTF-16 storage above outlive this visit.
        unsafe { visit_adapters(&mut adapter, &mut |ip| found.push(ip)) };
        assert_eq!(found, [IpAddr::V4(Ipv4Addr::new(100, 70, 87, 52)),
            IpAddr::V6(Ipv6Addr::from(ipv6_bytes))]);
    }

    #[test]
    fn rejects_physical_public_and_incomplete_addresses() {
        let mut ethernet: Vec<u16> = "Ethernet".encode_utf16().chain(Some(0)).collect();
        let mut tailscale: Vec<u16> = TAILSCALE_INTERFACE_DESCRIPTION.encode_utf16().chain(Some(0)).collect();
        let mut ipv4 = SOCKADDR_IN { sin_family: AF_INET, ..Default::default() };
        ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([100, 70, 87, 52]);
        let mut address = IP_ADAPTER_UNICAST_ADDRESS_LH {
            Address: SOCKET_ADDRESS { lpSockaddr: (&mut ipv4 as *mut SOCKADDR_IN).cast::<SOCKADDR>(),
                iSockaddrLength: size_of::<SOCKADDR_IN>() as i32 },
            ..Default::default()
        };
        let mut adapter = IP_ADAPTER_ADDRESSES_LH {
            IfType: 6, Description: PWSTR(ethernet.as_mut_ptr()), FirstUnicastAddress: &mut address,
            ..Default::default()
        };
        let mut found = Vec::new();
        // SAFETY: these fixtures own all storage used by the linked list.
        unsafe { visit_adapters(&mut adapter, &mut |ip| found.push(ip)) };
        assert!(found.is_empty(), "physical CGNAT addresses must not count as the tunnel");
        adapter.IfType = 53;
        adapter.Description = PWSTR(tailscale.as_mut_ptr());
        ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([203, 0, 113, 1]);
        unsafe { visit_adapters(&mut adapter, &mut |ip| found.push(ip)) };
        assert!(found.is_empty(), "public addresses on the tunnel must not be accepted");
        ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([100, 70, 87, 52]);
        address.Address.iSockaddrLength = 0;
        unsafe { visit_adapters(&mut adapter, &mut |ip| found.push(ip)) };
        assert!(found.is_empty(), "incomplete socket addresses must not be read");
        adapter.Description = PWSTR::null();
        unsafe { visit_adapters(&mut adapter, &mut |ip| found.push(ip)) };
        assert!(found.is_empty(), "an unnamed interface cannot prove tunnel ownership");
    }
}
