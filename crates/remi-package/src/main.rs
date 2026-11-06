//! Debian lifecycle hooks are compiled Rust executables too.
//! dpkg invokes the same small executable as postinst, prerm, or postrm.
use std::{
    env, fs, io,
    path::Path,
    process::{Command, ExitCode},
};

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} returned {status}")))
    }
}
fn account_exists(kind: &str) -> bool {
    Command::new("getent")
        .args([kind, "remi"])
        .output()
        .is_ok_and(|o| o.status.success())
}
fn execute() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let name = Path::new(&args[0])
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let action = args.get(1).map(String::as_str).unwrap_or("");
    let running = Path::new("/run/systemd/system").exists();
    if name.ends_with("postinst") && action == "configure" {
        if !account_exists("group") {
            run("groupadd", &["--system", "remi"])?;
        }
        if !account_exists("passwd") {
            run(
                "useradd",
                &[
                    "--system",
                    "--gid",
                    "remi",
                    "--home-dir",
                    "/var/lib/remi",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "remi",
                ],
            )?;
        }
        for directory in ["/var/lib/remi", "/run/remi"] {
            fs::create_dir_all(directory)?;
            run("chown", &["remi:remi", directory])?;
            run(
                "chmod",
                &[
                    if directory == "/var/lib/remi" {
                        "0700"
                    } else {
                        "0750"
                    },
                    directory,
                ],
            )?;
        }
        let first_install = args.get(2).is_none_or(String::is_empty);
        if first_install {
            run("deb-systemd-helper", &["enable", "remi-agent.service"])?;
        }
        if running {
            run("systemctl", &["daemon-reload"])?;
            run(
                "deb-systemd-invoke",
                &[
                    if first_install {
                        "start"
                    } else {
                        "try-restart"
                    },
                    "remi-agent.service",
                ],
            )?;
        }
        println!(
            "Remi instalado. Autoriza tu cuenta SSH con: sudo remi-agent authorize TU_USUARIO"
        );
    } else if name.ends_with("prerm") && action == "remove" && running {
        run("deb-systemd-invoke", &["stop", "remi-agent.service"])?;
    } else if name.ends_with("postrm") {
        if running {
            run("systemctl", &["daemon-reload"])?;
        }
        if action == "purge" {
            run("deb-systemd-helper", &["purge", "remi-agent.service"])?;
        }
        // Preserve event history and the system account; upgrades/reinstalls must not lose audit data.
    }
    Ok(())
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Remi package configuration failed: {e}");
            ExitCode::FAILURE
        }
    }
}
