use std::net::{IpAddr, SocketAddr};

pub const DIRECT_PORT: u16 = 21118;
pub const DESTINATION_ERROR: &str = "Only a literal Tailscale IP address on TCP port 21118 is allowed (100.64.0.0/10 or fd7a:115c:a1e0::/48); IDs, DNS names and relays are disabled";
pub const SESSION_ERROR: &str = "Only remote desktop sessions are allowed; file transfer, tunnels, camera, terminal and switching sides are disabled";
pub const SETUP_ERROR: &str = "Host is closed: set a new permanent password of at least 20 characters and configure authenticator 2FA in Security settings";

pub fn host_role(role: Option<&str>, windows: bool) -> bool {
    windows && role == Some("host")
}

pub fn tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

pub fn tailscale_interface(description: Option<&str>) -> bool {
    description.map_or(false, |value| value.eq_ignore_ascii_case("Tailscale Tunnel"))
}

pub fn controller_interface(name: &str, description: Option<&str>, windows: bool, android: bool) -> bool {
    if windows {
        return tailscale_interface(description);
    }
    android && name.strip_prefix("tun").map_or(false, |suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

pub fn destination(value: &str) -> Result<SocketAddr, &'static str> {
    let addr = if let Ok(ip) = value.parse::<IpAddr>() {
        SocketAddr::new(ip, DIRECT_PORT)
    } else {
        value.parse::<SocketAddr>().map_err(|_| DESTINATION_ERROR)?
    };
    if !tailscale_ip(addr.ip()) || addr.port() != DIRECT_PORT {
        return Err(DESTINATION_ERROR);
    }
    if let SocketAddr::V6(addr) = addr {
        if addr.scope_id() != 0 || addr.flowinfo() != 0 {
            return Err(DESTINATION_ERROR);
        }
    }
    Ok(addr)
}

pub fn strong_password(value: &str) -> bool {
    value.chars().count() >= 20
        && !value.chars().any(char::is_control)
        && value.chars().any(|c| !c.is_whitespace())
        && value.chars().any(|c| Some(c) != value.chars().next())
}

pub fn credentials_ready(fingerprint: Option<&str>, attestation: &str, totp_configured: bool) -> bool {
    totp_configured && !attestation.is_empty() && fingerprint == Some(attestation)
}

pub fn admission(host: bool, local: SocketAddr, peer: SocketAddr, ready: bool) -> bool {
    host && ready && local.port() == DIRECT_PORT && tailscale_ip(local.ip()) && tailscale_ip(peer.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_literal_tailnet_destinations() {
        for value in ["100.64.0.1", "100.127.255.254:21118", "fd7a:115c:a1e0::1", "[fd7a:115c:a1e0::1]:21118"] {
            assert_eq!(destination(value).unwrap().port(), DIRECT_PORT);
        }
        for value in ["123456789", "host.tailnet.ts.net:21118", "100.63.255.255", "100.128.0.1", "192.168.1.1:21118", "100.64.0.1:21119", "[fd7a:115c:a1e1::1]:21118", "[::ffff:100.64.0.1]:21118", "[fd7a:115c:a1e0::1%3]:21118", "100.64.0.1/r", "100.64.0.1@server", " 100.64.0.1"] {
            assert!(destination(value).is_err(), "{value}");
        }
    }

    #[test]
    fn role_and_admission_fail_closed() {
        for role in [None, Some(""), Some("controller"), Some("HOST"), Some("invalid")] {
            assert!(!host_role(role, true));
        }
        assert!(host_role(Some("host"), true));
        assert!(!host_role(Some("host"), false));
        assert!(tailscale_interface(Some("Tailscale Tunnel")));
        assert!(!tailscale_interface(Some("Ethernet")));
        assert!(!tailscale_interface(Some("WireGuard Tunnel")));
        assert!(!tailscale_interface(None));
        let local = destination("100.64.0.1").unwrap();
        let peer = "100.64.0.2:34567".parse().unwrap();
        assert!(admission(true, local, peer, true));
        assert!(!admission(false, local, peer, true));
        assert!(!admission(true, local, peer, false));
        assert!(!admission(true, "0.0.0.0:21118".parse().unwrap(), peer, true));
        assert!(!admission(true, local, "192.168.1.1:34567".parse().unwrap(), true));
        assert!(!admission(true, "100.64.0.1:21119".parse().unwrap(), peer, true));
    }

    #[test]
    fn password_setup_rejects_short_or_degenerate_values() {
        assert!(strong_password("long test passphrase 123!"));
        for value in ["", "nineteen-characters", "                    ", "aaaaaaaaaaaaaaaaaaaa", "long test passphrase\n123!"] {
            assert!(!strong_password(value));
        }
    }

    #[test]
    fn controllers_reject_carrier_and_physical_interfaces() {
        assert!(controller_interface("adapter", Some("Tailscale Tunnel"), true, false));
        assert!(!controller_interface("Ethernet", Some("Ethernet"), true, false));
        assert!(controller_interface("tun0", None, false, true));
        assert!(controller_interface("tun12", None, false, true));
        assert!(!controller_interface("rmnet_data0", None, false, true));
        assert!(!controller_interface("wlan0", None, false, true));
        assert!(!controller_interface("tun", None, false, true));
        assert!(!controller_interface("tun0", None, false, false));
    }

    #[test]
    fn authentication_setup_requires_current_password_and_totp() {
        assert!(credentials_ready(Some("current"), "current", true));
        assert!(!credentials_ready(Some("current"), "current", false));
        assert!(!credentials_ready(None, "current", true));
        assert!(!credentials_ready(Some("changed"), "old", true));
        assert!(!credentials_ready(Some(""), "", true));
    }
}
