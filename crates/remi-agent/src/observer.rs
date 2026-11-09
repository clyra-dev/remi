//! Identify this reader's SSH login without trusting an IP-wide allowlist.
use anyhow::{Context, Result, bail};
use remi_core::{Login, connections::Observer};
use std::{net::IpAddr, path::Path};

pub struct StreamObserver {
    connection: Observer,
    boot_id: String,
    processes: Vec<(u32, u64)>,
}

impl StreamObserver {
    pub fn identify() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let connection = Observer::from_ssh_connection(
                &std::env::var("SSH_CONNECTION").context("Sin contexto SSH")?,
            )?;
            // sysconf has no side effects; a nonpositive result is rejected below.
            let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            Self::read(Path::new("/proc"), connection, std::process::id(), ticks)
        }
        #[cfg(not(target_os = "linux"))]
        bail!("La identificación de sesiones requiere Linux")
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn read(root: &Path, connection: Observer, mut pid: u32, ticks: i64) -> Result<Self> {
        if ticks <= 0 {
            bail!("Reloj de procesos no disponible");
        }
        let boot_id = std::fs::read_to_string(root.join("sys/kernel/random/boot_id"))?
            .trim()
            .replace('-', "")
            .to_ascii_lowercase();
        if boot_id.len() != 32 || !boot_id.bytes().all(|c| c.is_ascii_hexdigit()) {
            bail!("Identidad de arranque inválida");
        }
        let mut processes = Vec::new();
        for _ in 0..64 {
            if pid <= 1 {
                break;
            }
            let stat = std::fs::read_to_string(root.join(format!("{pid}/stat")))
                .context("No se pudo verificar la ascendencia SSH")?;
            let (name, ppid, start) = process_stat(&stat)?;
            if matches!(name, "sshd" | "sshd-session" | "sshd-auth") {
                let micros = start
                    .checked_mul(1_000_000)
                    .context("Reloj de proceso fuera de rango")?
                    / ticks as u64;
                processes.push((pid, micros));
            }
            if ppid == pid {
                bail!("Ascendencia de procesos inválida");
            }
            pid = ppid;
        }
        if processes.is_empty() || pid > 1 {
            bail!("No se pudo verificar el proceso de la sesión SSH");
        }
        Ok(Self {
            connection,
            boot_id,
            processes,
        })
    }

    pub fn matches(&self, event: &Login) -> bool {
        let Some(origin) = &event.origin else {
            // Missing/old metadata must retain normal alerts.
            return false;
        };
        canonical(event.source_ip) == canonical(self.connection.remote.ip())
            && event.source_port == self.connection.remote.port()
            && origin.boot_id == self.boot_id
            && self
                .processes
                .iter()
                .any(|(pid, started)| origin.pid == *pid && origin.monotonic_micros >= *started)
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn process_stat(value: &str) -> Result<(&str, u32, u64)> {
    let (head, tail) = value.rsplit_once(')').context("Estadísticas sin nombre")?;
    let (_, name) = head.split_once('(').context("Nombre de proceso inválido")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Ok((
        name,
        fields.get(1).context("Proceso sin padre")?.parse()?,
        fields
            .get(19)
            .context("Proceso sin fecha de inicio")?
            .parse()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use remi_core::JournalOrigin;

    fn event() -> Login {
        Login {
            sequence: 12,
            timestamp: chrono::Utc::now(),
            user: "admin".into(),
            source_ip: "192.0.2.10".parse().unwrap(),
            source_port: 45000,
            method: "publickey".into(),
            origin: Some(JournalOrigin {
                boot_id: "0123456789abcdef0123456789abcdef".into(),
                pid: 123,
                monotonic_micros: 20_000_000,
            }),
        }
    }

    #[test]
    fn only_this_ssh_process_and_endpoint_match_including_delayed_replay() {
        let observer = StreamObserver {
            connection: Observer::from_ssh_connection("192.0.2.10 45000 192.0.2.20 22").unwrap(),
            boot_id: "0123456789abcdef0123456789abcdef".into(),
            processes: vec![(123, 10_000_000)],
        };
        let login = event();
        assert!(observer.matches(&login));
        let mut other = login.clone();
        other.source_port += 1;
        assert!(!observer.matches(&other));
        other = login.clone();
        other.origin.as_mut().unwrap().pid += 1;
        assert!(!observer.matches(&other));
        other = login.clone();
        other.origin.as_mut().unwrap().boot_id = "f".repeat(32);
        assert!(!observer.matches(&other));
        other = login.clone();
        // Reused PID and source port from an earlier session in this same boot.
        other.origin.as_mut().unwrap().monotonic_micros = 9_999_999;
        assert!(!observer.matches(&other));
        other = login.clone();
        other.origin = None;
        assert!(!observer.matches(&other));
        other = login.clone();
        other.source_ip = "::ffff:192.0.2.10".parse().unwrap();
        assert!(observer.matches(&other));
        other.source_ip = "192.0.2.11".parse().unwrap();
        assert!(!observer.matches(&other));
    }

    #[test]
    fn login_at_the_process_start_tick_is_valid_but_an_earlier_one_is_not() {
        for (pid, started) in [(123, 0), (789, 1), (456, 10_000_000)] {
            let observer = StreamObserver {
                connection: Observer::from_ssh_connection("192.0.2.10 45000 192.0.2.20 22")
                    .unwrap(),
                boot_id: "0123456789abcdef0123456789abcdef".into(),
                processes: vec![(pid, started)],
            };
            let mut login = event();
            login.origin.as_mut().unwrap().pid = pid;
            for timestamp in [started, started + 1] {
                login.origin.as_mut().unwrap().monotonic_micros = timestamp;
                assert!(
                    observer.matches(&login),
                    "Same-process login at tick {timestamp}"
                );
            }
            if let Some(earlier) = started.checked_sub(1) {
                login.origin.as_mut().unwrap().monotonic_micros = earlier;
                assert!(
                    !observer.matches(&login),
                    "PID reuse must not hide an older login"
                );
            }
        }
    }
    #[test]
    fn proc_ancestry_requires_sshd_and_reads_names_with_spaces_or_parentheses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/kernel/random")).unwrap();
        std::fs::write(
            dir.path().join("sys/kernel/random/boot_id"),
            "01234567-89ab-cdef-0123-456789abcdef\n",
        )
        .unwrap();
        for (pid, ppid, name, start) in [(124, 123, "reader (test)", 2000), (123, 1, "sshd", 1000)]
        {
            std::fs::create_dir(dir.path().join(pid.to_string())).unwrap();
            let mut fields = vec!["0".to_string(); 20];
            fields[0] = "S".into();
            fields[1] = ppid.to_string();
            fields[19] = start.to_string();
            std::fs::write(
                dir.path().join(format!("{pid}/stat")),
                format!("{pid} ({name}) {}", fields.join(" ")),
            )
            .unwrap();
        }
        let connection = Observer::from_ssh_connection("192.0.2.10 45000 192.0.2.20 22").unwrap();
        let observer = StreamObserver::read(dir.path(), connection.clone(), 124, 100).unwrap();
        assert!(observer.matches(&event()));
        assert!(StreamObserver::read(dir.path(), connection.clone(), 124, 0).is_err());
        let path = dir.path().join("123/stat");
        std::fs::write(
            &path,
            std::fs::read_to_string(&path)
                .unwrap()
                .replace("sshd", "other"),
        )
        .unwrap();
        assert!(StreamObserver::read(dir.path(), connection, 124, 100).is_err());
    }
}
