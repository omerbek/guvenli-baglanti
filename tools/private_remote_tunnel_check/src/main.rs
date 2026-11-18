#[cfg(windows)]
#[path = "../../../src/private_remote_policy.rs"]
mod private_remote_policy;
#[cfg(windows)]
#[path = "../../../src/private_remote_windows.rs"]
mod private_remote_windows;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let mut found = false;
    match private_remote_windows::for_each_address(|ip| {
        found = true;
        println!("{ip}");
    }) {
        Ok(()) if found => std::process::ExitCode::SUCCESS,
        Ok(()) => {
            eprintln!("No assigned Tailscale tunnel address found; connect Tailscale first.");
            std::process::ExitCode::FAILURE
        }
        Err(code) => {
            eprintln!("Windows adapter enumeration failed: {code}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("This read-only tunnel check supports Windows only.");
    std::process::ExitCode::FAILURE
}
