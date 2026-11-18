use crate::private_remote_policy;
use base::message_proto::{message, misc, Message};
use hbb_common::{
    config::{self, Config},
    log,
    sha2::{Digest, Sha256},
};

pub const PUBLIC_NETWORK_DISABLED: bool = true;
pub const PASSWORD_ATTESTATION: &str = "private-password-attestation";

pub fn is_host() -> bool {
    private_remote_policy::host_role(option_env!("PRIVATE_REMOTE_ROLE"), cfg!(target_os = "windows"))
}

pub fn role() -> &'static str {
    if is_host() { "host" } else { "controller" }
}

// Install before any Config/Config2/LocalConfig lazy cache is touched.
pub fn install_settings() {
    *config::APP_NAME.write().unwrap() = "GuvenliBaglanti".to_owned();
    {
        let mut hard = config::HARD_SETTINGS.write().unwrap();
        hard.insert("conn-type".to_owned(), if is_host() { "incoming" } else { "outgoing" }.to_owned());
        hard.remove("password");
        hard.remove("salt");
    }
    {
        let mut settings = config::OVERWRITE_SETTINGS.write().unwrap();
        for key in [
            "enable-clipboard", "enable-file-transfer", "enable-file-copy-paste", "enable-camera",
            "enable-terminal", "enable-audio", "enable-tunnel", "enable-remote-restart",
            "enable-record-session", "enable-block-input", "enable-privacy-mode", "enable-remote-printer",
            "enable-perm-change-in-accept-window", "enable-lan-discovery", "enable-trusted-devices",
            "enable-tcp-punch", "enable-udp-punch", "enable-ipv6-punch", "enable-webrtc",
            "allow-remote-config-modification", "allow-remote-cm-modification", "allow-auto-update",
            "allow-websocket", "allow-insecure-tls-fallback", "allow-hide-cm", "register-device",
        ] {
            settings.insert(key.to_owned(), "N".to_owned());
        }
        for (key, value) in [
            ("enable-keyboard", "Y"), ("access-mode", "custom"),
            ("verification-method", "use-permanent-password"), ("approve-mode", "password"),
            ("direct-access-port", "21118"), ("api-server", ""), ("custom-rendezvous-server", ""),
            ("rendezvous-servers", ""), ("relay-server", ""), ("telegram-bot", ""),
        ] {
            settings.insert(key.to_owned(), value.to_owned());
        }
        for key in ["proxy-url", "proxy-username", "proxy-password", PASSWORD_ATTESTATION] {
            settings.remove(key);
        }
        settings.insert("direct-server".to_owned(), if is_host() { "Y" } else { "N" }.to_owned());
    }
    {
        let mut settings = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
        for key in ["enable-check-update", "allow-auto-update", "sync-ab-with-recent-sessions", "sync-ab-tags"] {
            settings.insert(key.to_owned(), "N".to_owned());
        }
    }
    {
        let mut settings = config::OVERWRITE_DISPLAY_SETTINGS.write().unwrap();
        for (key, value) in [("disable_audio", "Y"), ("disable_clipboard", "Y"), ("enable-file-copy-paste", "N"), ("lock_after_session_end", "Y")] {
            settings.insert(key.to_owned(), value.to_owned());
        }
    }
    let mut builtin = config::BUILTIN_SETTINGS.write().unwrap();
    for (key, value) in [
        ("private-remote-role", role()), ("disable-change-permanent-password", "N"),
        ("allow-logon-screen-password", "N"), ("allow-deep-link-password", "N"),
        ("allow-deep-link-server-settings", "N"), ("allow-remote-config-modification", "N"),
        ("allow-remote-cm-modification", "N"), ("enable-trusted-devices", "N"),
    ] {
        builtin.insert(key.to_owned(), value.to_owned());
    }
}

pub struct RestoreSettings;
impl Drop for RestoreSettings {
    fn drop(&mut self) {
        install_settings();
    }
}

fn password_fingerprint() -> Option<String> {
    let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
    if !config::local_permanent_password_storage_is_usable_for_auth(&storage, &salt) {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(storage.as_bytes());
    digest.update(salt.as_bytes());
    Some(format!("{:x}", digest.finalize()))
}

// Existing hashed credentials do not reveal their original length. Only a password
// accepted by this build's setter attests the current storage; imports fail closed.
pub fn record_password_setup() {
    Config::set_option(PASSWORD_ATTESTATION.to_owned(), password_fingerprint().unwrap_or_default());
}

pub fn host_ready() -> bool {
    if !is_host() {
        return false;
    }
    let fingerprint = password_fingerprint();
    private_remote_policy::credentials_ready(
        fingerprint.as_deref(), &Config::get_option(PASSWORD_ATTESTATION),
        crate::auth_2fa::get_2fa(None).is_some(),
    )
}

pub fn permission_allowed(key: &str) -> bool {
    key == "enable-keyboard"
}

// Shared by both directions: reject optional capabilities before their handlers.
// This predicate borrows the protobuf and never allocates on the video/input path.
pub fn desktop_message_allowed(msg: &Message) -> bool {
    match msg.union.as_ref() {
        Some(message::Union::LoginRequest(lr)) => lr.union.is_none(),
        Some(message::Union::Clipboard(_)) | Some(message::Union::MultiClipboards(_))
        | Some(message::Union::Cliprdr(_)) | Some(message::Union::FileAction(_))
        | Some(message::Union::FileResponse(_)) | Some(message::Union::AudioFrame(_))
        | Some(message::Union::VoiceCallRequest(_)) | Some(message::Union::VoiceCallResponse(_))
        | Some(message::Union::SwitchSidesResponse(_)) | Some(message::Union::PortForwardChannel(_))
        | Some(message::Union::TerminalAction(_)) | Some(message::Union::TerminalResponse(_))
        | Some(message::Union::OsLogin(_)) => false,
        Some(message::Union::Misc(misc)) => matches!(misc.union.as_ref(),
            None | Some(misc::Union::ChatMessage(_)) | Some(misc::Union::SwitchDisplay(_))
            | Some(misc::Union::PermissionInfo(_)) | Some(misc::Union::Option(_))
            | Some(misc::Union::CloseReason(_)) | Some(misc::Union::RefreshVideo(_))
            | Some(misc::Union::VideoReceived(_)) | Some(misc::Union::BackNotification(_))
            | Some(misc::Union::Uac(_)) | Some(misc::Union::ForegroundWindowElevated(_))
            | Some(misc::Union::ElevationResponse(_)) | Some(misc::Union::PortableServiceRunning(_))
            | Some(misc::Union::AutoAdjustFps(_)) | Some(misc::Union::ClientRecordStatus(_))
            | Some(misc::Union::CaptureDisplays(_)) | Some(misc::Union::RefreshVideoDisplay(_))
            | Some(misc::Union::SupportedEncoding(_)) | Some(misc::Union::MessageQuery(_))
            | Some(misc::Union::FollowCurrentDisplay(_)) | Some(misc::Union::RequestCursorData(_))),
        _ => true,
    }
}

#[cfg(not(target_os = "ios"))]
pub async fn run_host(server: crate::server::ServerPtr) {
    if !is_host() {
        return;
    }
    let mut listeners: Vec<(std::net::SocketAddr, hbb_common::tokio::net::TcpListener)> = Vec::new();
    let mut addresses = Vec::new();
    loop {
        let enabled = host_ready() && !Config::get_bool_option("stop-service");
        addresses.clear();
        if enabled {
            addresses.extend(default_net::get_interfaces().into_iter()
                .filter(|interface| private_remote_policy::tailscale_interface(interface.description.as_deref()))
                .flat_map(|interface| {
                interface.ipv4.into_iter().map(|net| std::net::IpAddr::V4(net.addr))
                    .chain(interface.ipv6.into_iter().map(|net| std::net::IpAddr::V6(net.addr)))
            }).filter(|ip| private_remote_policy::tailscale_ip(*ip))
                .map(|ip| std::net::SocketAddr::new(ip, private_remote_policy::DIRECT_PORT)));
        }
        addresses.sort_unstable();
        addresses.dedup();
        listeners.retain(|(address, _)| addresses.contains(address));
        for address in addresses.drain(..) {
            if listeners.iter().any(|(bound, _)| *bound == address) {
                continue;
            }
            match hbb_common::tokio::net::TcpListener::bind(address).await {
                Ok(listener) => listeners.push((address, listener)),
                Err(error) => hbb_common::throttled_log!(std::time::Duration::from_secs(30), warn,
                    "Private host bind failed: {error}"),
            }
        }
        for (_, listener) in &listeners {
            if let Ok(Ok((stream, peer))) = hbb_common::timeout(100, listener.accept()).await {
                let Ok(local) = stream.local_addr() else { continue; };
                if !private_remote_policy::admission(is_host(), local, peer, host_ready()) {
                    continue;
                }
                if let Err(error) = stream.set_nodelay(true) {
                    hbb_common::log::warn!("Private host TCP setup failed: {error}");
                    continue;
                }
                let server = server.clone();
                hbb_common::tokio::spawn(async move {
                    hbb_common::allow_err!(crate::server::create_tcp_connection(
                        server, hbb_common::Stream::from(stream, local), peer, false,
                        crate::server::ConnectionMeta::default(),
                    ).await);
                });
            }
        }
        hbb_common::tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::{LoginRequest, Misc};

    #[test]
    fn desktop_protocol_rejects_optional_capabilities_and_side_switching() {
        let mut message = Message::new();
        message.set_mouse_event(Default::default());
        assert!(desktop_message_allowed(&message));
        message.set_login_request(LoginRequest::new());
        assert!(desktop_message_allowed(&message));
        let mut login = LoginRequest::new();
        login.set_terminal(Default::default());
        message.set_login_request(login);
        assert!(!desktop_message_allowed(&message));
        message.set_clipboard(Default::default());
        assert!(!desktop_message_allowed(&message));
        message.set_switch_sides_response(Default::default());
        assert!(!desktop_message_allowed(&message));
        let mut misc = Misc::new();
        misc.set_stop_service(true);
        message.set_misc(misc);
        assert!(!desktop_message_allowed(&message));
    }
}
