//! Linux INET_DIAG, with an exact kernel cookie for every destructive request.
//! UAPI: include/uapi/linux/{inet_diag,sock_diag,netlink}.h; no shell filters.
use anyhow::{Result, bail};
use remi_core::connections::{ConnectionsSnapshot, Observer, SocketKey};

#[cfg(not(target_os = "linux"))]
pub fn snapshot(_: Option<&Observer>, _: bool) -> Result<ConnectionsSnapshot> {
    bail!("La gestión de conexiones requiere un agente en Linux");
}
#[cfg(not(target_os = "linux"))]
pub fn snapshot_port(_: Option<&Observer>, _: bool, _: Option<u16>) -> Result<ConnectionsSnapshot> {
    bail!("La gestión de conexiones requiere un agente en Linux");
}
#[cfg(not(target_os = "linux"))]
pub fn close(_: &SocketKey, _: &Observer) -> Result<()> {
    bail!("La gestión de conexiones requiere un agente en Linux");
}

#[cfg(target_os = "linux")]
pub use linux::{close, snapshot, snapshot_port};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use remi_core::connections::{ProcessInfo, SNAPSHOT_LIMIT, TcpConnection};
    use std::{
        collections::{HashMap, HashSet},
        fs, io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };

    const QUERY: u16 = 20;
    const DESTROY: u16 = 21;
    const REQUEST: u16 = 1;
    const ACK: u16 = 4;
    const DUMP: u16 = 0x300;

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }
    fn address(bytes: &[u8], v6: bool) -> IpAddr {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
        } else {
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
    }
    fn parse_row(bytes: &[u8]) -> Result<TcpConnection> {
        if bytes.len() < 72 || !matches!(bytes[0], 2 | 10) {
            bail!("Respuesta INET_DIAG incompleta o de familia desconocida");
        }
        let interface = u32_at(bytes, 40);
        let endpoint = |offset, port_offset| {
            let ip = address(&bytes[offset..offset + 16], bytes[0] == 10);
            let mut endpoint = SocketAddr::new(
                ip,
                u16::from_be_bytes(bytes[port_offset..port_offset + 2].try_into().unwrap()),
            );
            if let SocketAddr::V6(ref mut v6) = endpoint
                && v6.ip().is_unicast_link_local()
            {
                v6.set_scope_id(interface);
            }
            endpoint
        };
        let uid = u32_at(bytes, 64);
        Ok(TcpConnection {
            key: SocketKey {
                local: endpoint(8, 4),
                remote: endpoint(24, 6),
                interface,
                cookie: [u32_at(bytes, 44), u32_at(bytes, 48)],
                inode: u32_at(bytes, 68),
            },
            state: bytes[1],
            uid,
            user: uid.to_string(),
            processes: vec![],
            protected: false,
            traffic: (bytes[1] != 10)
                .then(|| crate::tcp_info::traffic(&bytes[72..]))
                .flatten(),
        })
    }

    fn request(kind: u16, family: u8, key: Option<&SocketKey>) -> Vec<u8> {
        let mut bytes = vec![0u8; 72];
        bytes[0..4].copy_from_slice(&72u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        let flags = REQUEST | if key.is_none() { DUMP } else { ACK };
        bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
        let req = &mut bytes[16..];
        req[0] = family;
        req[1] = libc::IPPROTO_TCP as u8;
        if kind == QUERY {
            req[2] = 1 << (2 - 1);
        } // INET_DIAG_INFO
        // TIME_WAIT and CLOSED are not live connections and have no actionable process.
        req[4..8].copy_from_slice(&(!(1u32 << 6 | 1 << 7)).to_ne_bytes());
        req[48..56].fill(0xff);
        if let Some(key) = key {
            req[8..10].copy_from_slice(&key.local.port().to_be_bytes());
            req[10..12].copy_from_slice(&key.remote.port().to_be_bytes());
            for (endpoint, offset) in [(key.local, 12), (key.remote, 28)] {
                match endpoint.ip() {
                    IpAddr::V4(ip) => req[offset..offset + 4].copy_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => req[offset..offset + 16].copy_from_slice(&ip.octets()),
                }
            }
            req[44..48].copy_from_slice(&key.interface.to_ne_bytes());
            req[48..52].copy_from_slice(&key.cookie[0].to_ne_bytes());
            req[52..56].copy_from_slice(&key.cookie[1].to_ne_bytes());
        }
        bytes
    }

    fn exchange(kind: u16, family: u8, key: Option<&SocketKey>) -> Result<Vec<TcpConnection>> {
        // SAFETY: libc owns no Rust references; OwnedFd closes every return path.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 4) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let set_timeout = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as _,
            )
        };
        if set_timeout < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let connected = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as _,
            )
        };
        if connected < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let req = request(kind, family, key);
        let sent = unsafe { libc::send(fd.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) };
        if sent != req.len() as isize {
            return Err(io::Error::last_os_error().into());
        }
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut rows = Vec::new();
        let started = Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(4) || rows.len() > 100_000 {
                bail!("La tabla TCP excedió el límite de lectura; vuelve a actualizar");
            }
            let received = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_TRUNC,
                )
            };
            if received < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if received == 0 || received as usize > buffer.len() {
                bail!("Respuesta netlink truncada");
            }
            let mut offset = 0usize;
            while offset < received as usize {
                if offset + 16 > received as usize {
                    bail!("Cabecera netlink truncada");
                }
                let header = &buffer[offset..offset + 16];
                let len = u32_at(header, 0) as usize;
                if len < 16 || offset + len > received as usize {
                    bail!("Longitud netlink inválida");
                }
                let message_type = u16::from_ne_bytes(header[4..6].try_into().unwrap());
                let flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
                if u32_at(header, 8) != 1 || flags & 0x10 != 0 {
                    bail!("La tabla TCP cambió durante la lectura; vuelve a actualizar");
                }
                let payload = &buffer[offset + 16..offset + len];
                match message_type {
                    2 | 3 => {
                        if payload.len() >= 4 {
                            let code = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                            if code != 0 {
                                return Err(
                                    io::Error::from_raw_os_error(code.saturating_neg()).into()
                                );
                            }
                        } else if message_type == 2 {
                            bail!("Confirmación netlink incompleta");
                        }
                        return Ok(rows);
                    }
                    QUERY => {
                        rows.push(parse_row(payload)?);
                        if key.is_some() {
                            return Ok(rows);
                        }
                    }
                    1 => (),
                    _ => bail!("Respuesta netlink inesperada"),
                }
                offset += (len + 3) & !3;
            }
        }
    }

    fn net_admin() -> bool {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            })
            .is_some_and(|caps| caps & (1 << 12) != 0)
    }

    fn destroy_supported() -> bool {
        // A TCP connection cannot have both ports zero. Query this impossible tuple
        // with a non-wildcard cookie: ENOENT proves the handler exists without
        // touching any socket. LinuxKit may compile INET_DIAG without DESTROY.
        let impossible = SocketKey {
            local: "0.0.0.0:0".parse().unwrap(),
            remote: "0.0.0.0:0".parse().unwrap(),
            interface: 0,
            cookie: [0, 0],
            inode: 0,
        };
        exchange(DESTROY, 2, Some(&impossible))
            .err()
            .is_some_and(|error| {
                error.downcast_ref::<io::Error>().is_some_and(|error| {
                    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
                })
            })
    }
    fn describe_processes(rows: &mut [TcpConnection]) -> bool {
        let wanted: HashSet<_> = rows
            .iter()
            .map(|row| row.key.inode)
            .filter(|i| *i != 0)
            .collect();
        let mut owners: HashMap<u32, Vec<ProcessInfo>> = HashMap::new();
        let start = Instant::now();
        let mut incomplete = false;
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if start.elapsed() > Duration::from_secs(2) {
                    incomplete = true;
                    break;
                }
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                    continue;
                };
                for (index, fd) in fds.flatten().enumerate() {
                    if index > 65_536 || start.elapsed() > Duration::from_secs(2) {
                        incomplete = true;
                        break;
                    }
                    let Ok(link) = fs::read_link(fd.path()) else {
                        continue;
                    };
                    let link = link.to_string_lossy();
                    let Some(inode) = link
                        .strip_prefix("socket:[")
                        .and_then(|v| v.strip_suffix(']'))
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|i| wanted.contains(i))
                    else {
                        continue;
                    };
                    let processes = owners.entry(inode).or_default();
                    if processes.len() < 3 && !processes.iter().any(|p| p.pid == pid) {
                        let name = fs::read_to_string(entry.path().join("comm"))
                            .unwrap_or_default()
                            .trim()
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(64)
                            .collect();
                        processes.push(ProcessInfo { pid, name });
                    }
                }
            }
        }
        let users: HashMap<u32, String> = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                Some((
                    fields.get(2)?.parse().ok()?,
                    fields
                        .first()?
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(64)
                        .collect(),
                ))
            })
            .collect();
        for row in rows {
            if let Some(user) = users.get(&row.uid) {
                row.user.clone_from(user);
            }
            row.processes = owners.remove(&row.key.inode).unwrap_or_default();
            row.processes.sort_by_key(|p| p.pid);
        }
        incomplete
    }

    pub fn snapshot(observer: Option<&Observer>, privileged: bool) -> Result<ConnectionsSnapshot> {
        snapshot_port(observer, privileged, None)
    }

    pub fn snapshot_port(
        observer: Option<&Observer>,
        privileged: bool,
        port: Option<u16>,
    ) -> Result<ConnectionsSnapshot> {
        if port == Some(0) {
            bail!("El puerto debe estar entre 1 y 65535");
        }
        let mut rows = exchange(QUERY, 2, None).context("No se pudo leer TCP IPv4")?;
        match exchange(QUERY, 10, None) {
            Ok(v6) => rows.extend(v6),
            Err(e)
                if e.downcast_ref::<io::Error>().is_some_and(|e| {
                    matches!(
                        e.raw_os_error(),
                        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
                    )
                }) => {}
            Err(e) => return Err(e.context("No se pudo leer TCP IPv6")),
        }
        for row in &mut rows {
            row.protected = observer.is_some_and(|o| o.protects(&row.key));
        }
        let mut overview = remi_core::services::ServiceOverview::from_rows(&rows);
        let total = rows
            .iter()
            .filter(|r| port.is_none_or(|p| r.key.local.port() == p))
            .count();
        // Count first, then sample. Retain listener metadata even for a scoped request.
        if let Some(port) = port {
            rows.retain(|r| r.state == 10 || r.key.local.port() == port);
        }
        remi_core::services::prioritize(&mut rows, &overview);
        rows.truncate(SNAPSHOT_LIMIT);
        let incomplete = describe_processes(&mut rows);
        overview.enrich(&rows);
        let nginx = port.and_then(|p| {
            overview
                .service(p)
                .filter(|s| s.is_nginx())
                .map(|_| crate::nginx::inspect(std::path::Path::new("/etc/nginx"), p))
        });
        tracing::debug!(
            action = "tcp_recognition_snapshot",
            port,
            total,
            traffic_available = rows.iter().filter(|r| r.traffic.is_some()).count(),
            nginx = nginx.is_some()
        );
        if let Some(port) = port {
            rows.retain(|r| r.key.local.port() == port);
        }
        let has_net_admin = privileged && net_admin();
        let supports_close = has_net_admin && destroy_supported();
        let can_close = supports_close && observer.is_some();
        let mut limitations = Vec::new();
        if !privileged {
            limitations.push("Solo lectura: cerrar conexiones requiere sudo sin contraseña para el ayudante de Remi; algunos procesos no son visibles");
        } else if !net_admin() {
            limitations.push("Solo lectura: falta CAP_NET_ADMIN en este entorno");
        } else if !supports_close {
            limitations.push(
                "Solo lectura: este kernel no admite el cierre TCP mediante INET_DIAG_DESTROY",
            );
        }
        if observer.is_none() {
            limitations.push("Cierre deshabilitado: no se identificó la sesión SSH de Remi");
        }
        if incomplete {
            limitations.push("La lectura de procesos llegó a su límite de tiempo; algunos nombres no están disponibles");
        }
        Ok(ConnectionsSnapshot {
            captured_at: chrono::Utc::now(),
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_default()
                .trim()
                .chars()
                .take(128)
                .collect(),
            connections: rows,
            total,
            can_close,
            limitation: (!limitations.is_empty()).then(|| limitations.join(". ")),
            overview: Some(overview),
            port,
            nginx,
        })
    }

    pub fn close(key: &SocketKey, observer: &Observer) -> Result<()> {
        key.validate_close()?;
        if observer.protects(key) {
            bail!("La conexión que mantiene Remi conectado está protegida");
        }
        if !net_admin() {
            bail!("Cerrar conexiones requiere CAP_NET_ADMIN mediante sudo");
        }
        let family = if key.local.is_ipv4() { 2 } else { 10 };
        let rows = exchange(QUERY, family, Some(key))
            .context("La conexión cambió o ya no existe; actualiza la lista")?;
        let row = rows
            .into_iter()
            .find(|row| row.key == *key)
            .context("La conexión cambió o ya no existe; no se cerró ninguna otra")?;
        if !row.closable() {
            bail!(
                "Este estado TCP no permite cerrar una conexión; los puertos en escucha se conservan"
            );
        }
        // The kernel rechecks the cookie atomically, closing the TOCTOU reuse window.
        if let Err(error) = exchange(DESTROY, family, Some(key)) {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.raw_os_error() == Some(libc::EOPNOTSUPP))
            {
                bail!("El kernel no admite INET_DIAG_DESTROY; la conexión sigue abierta");
            }
            return Err(error.context("El kernel no confirmó el cierre de esta conexión"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        #[test]
        fn malformed_diagnostics_are_rejected() {
            assert!(parse_row(&[0; 71]).is_err());
            assert!(parse_row(&[0; 72]).is_err());
        }

        #[test]
        fn kernel_payload_recency_moves_from_unused_to_quiet_and_back_to_recent() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let recency = || {
                exchange(QUERY, 2, None)
                    .unwrap()
                    .into_iter()
                    .find(|r| {
                        r.key.local == server.local_addr().unwrap()
                            && r.key.remote == client.local_addr().unwrap()
                    })
                    .unwrap()
                    .traffic
                    .expect("The request must enable TCP_INFO")
            };
            assert_eq!(recency().last_data_ago_ms, None);
            // Capture addresses before mutably borrowing the streams.
            let local = server.local_addr().unwrap();
            let remote = client.local_addr().unwrap();
            let age = || {
                exchange(QUERY, 2, None)
                    .unwrap()
                    .into_iter()
                    .find(|r| r.key.local == local && r.key.remote == remote)
                    .unwrap()
                    .traffic
                    .unwrap()
                    .last_data_ago_ms
                    .unwrap()
            };
            client.write_all(b"hello").unwrap();
            server.read_exact(&mut [0; 5]).unwrap();
            let first = age();
            assert!(first < 2000);
            std::thread::sleep(Duration::from_millis(150));
            let quiet = age();
            assert!(quiet >= first + 100);
            client.write_all(b"again").unwrap();
            server.read_exact(&mut [0; 5]).unwrap();
            assert!(age() < quiet, "New payload must reset the age");
        }

        #[test]
        fn capability_probe_preserves_existing_connections() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            let observer = Observer {
                local: server.local_addr().unwrap(),
                remote: client.local_addr().unwrap(),
            };
            let supported = destroy_supported();
            let snapshot = snapshot(Some(&observer), true).unwrap();
            assert_eq!(snapshot.can_close, net_admin() && supported);
            assert!(snapshot.connections.iter().any(|row| row.protected));
            client.write_all(b"still alive").unwrap();
            let mut bytes = [0; 11];
            server.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"still alive");
        }

        #[test]
        fn kernel_lists_real_ipv4_and_ipv6_with_process_identity() {
            for address in ["127.0.0.1:0", "[::1]:0"] {
                let listener = TcpListener::bind(address).unwrap();
                let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (server, _) = listener.accept().unwrap();
                let snapshot = snapshot(None, false).unwrap();
                let row = snapshot
                    .connections
                    .iter()
                    .find(|r| {
                        r.key.local == server.local_addr().unwrap()
                            && r.key.remote == client.local_addr().unwrap()
                    })
                    .unwrap();
                assert_eq!(row.state, 1);
                assert!(row.processes.iter().any(|p| p.pid == std::process::id()));
                assert_ne!(row.key.cookie, [u32::MAX; 2]);
                assert!(!snapshot.can_close);
            }
        }

        #[test]
        #[ignore = "Requires CAP_NET_ADMIN; run only in an isolated disposable Linux test container"]
        fn exact_close_preserves_other_sockets_listener_and_observer() {
            for address in ["127.0.0.1:0", "[::1]:0"] {
                let listener = TcpListener::bind(address).unwrap();
                let mut first = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (first_server, _) = listener.accept().unwrap();
                let mut second = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (mut second_server, _) = listener.accept().unwrap();
                let observer = Observer {
                    local: second_server.local_addr().unwrap(),
                    remote: second.local_addr().unwrap(),
                };
                let list = snapshot(Some(&observer), true).unwrap();
                let target = list
                    .connections
                    .iter()
                    .find(|r| {
                        r.key.local == first_server.local_addr().unwrap()
                            && r.key.remote == first.local_addr().unwrap()
                    })
                    .unwrap();
                let protected = list
                    .connections
                    .iter()
                    .find(|r| r.key.local == observer.local && r.key.remote == observer.remote)
                    .unwrap();
                assert!(protected.protected);
                assert!(close(&protected.key, &observer).is_err());
                let mut wrong_cookie = target.key.clone();
                wrong_cookie.cookie[0] ^= 1;
                assert!(close(&wrong_cookie, &observer).is_err());
                close(&target.key, &observer).unwrap();
                assert!(close(&target.key, &observer).is_err());
                first
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert!(first.read(&mut [0; 1]).is_err());
                second.write_all(b"ok").unwrap();
                let mut bytes = [0; 2];
                second_server.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"ok");
                TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            }
        }
    }
}
