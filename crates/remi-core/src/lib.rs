//! Shared, versioned event contract, SSH parsing, policy and durable file writes.
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, net::IpAddr, path::Path};

pub mod connections;

pub const PROTOCOL: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<String>> {
    read_line_bounded(reader, MAX_FRAME_BYTES).await
}

pub async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<String>> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("Flujo interrumpido a mitad de un mensaje");
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map(|n| n + 1).unwrap_or(available.len());
        if line.len() + take > limit {
            bail!("Mensaje excede el límite del protocolo");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(String::from_utf8(line)?));
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Login {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub method: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamRequest {
    pub protocol: u32,
    pub after: u64,
    pub instance: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Hello {
        protocol: u32,
        version: String,
        instance: String,
        hostname: String,
        oldest: u64,
        latest: u64,
        journal_ready: bool,
        resync: bool,
        gap: bool,
        simulated: bool,
    },
    Login {
        event: Login,
    },
    Heartbeat {
        latest: u64,
        journal_ready: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    All,
    #[default]
    OutsideAllowlist,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Policy {
    pub mode: AlertMode,
    pub allowed: Vec<IpNet>,
}

impl Policy {
    pub fn parse(mode: AlertMode, lines: &str) -> Result<Self> {
        let mut allowed = Vec::new();
        for entry in lines
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
        {
            let network = entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .with_context(|| format!("IP o red inválida: {entry}"))?;
            allowed.push(network);
        }
        Ok(Self { mode, allowed })
    }
    pub fn expected(&self, address: IpAddr) -> bool {
        // OpenSSH may report IPv4 peers using IPv4-mapped IPv6 notation.
        let normalized = match address {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
            _ => address,
        };
        self.allowed
            .iter()
            .any(|net| net.contains(&address) || net.contains(&normalized))
    }
    pub fn notify(&self, address: IpAddr) -> bool {
        self.mode == AlertMode::All || !self.expected(address)
    }
}

/// Only root-owned OpenSSH journal records are accepted; SYSLOG_IDENTIFIER is not trusted.
pub fn parse_journal(value: &serde_json::Value) -> Option<(String, Login)> {
    let comm = value.get("_COMM")?.as_str()?;
    if !matches!(comm, "sshd" | "sshd-session" | "sshd-auth") || value.get("_UID")?.as_str()? != "0"
    {
        return None;
    }
    let cursor = value.get("__CURSOR")?.as_str()?;
    if cursor.is_empty() || cursor.len() > 4096 {
        return None;
    }
    let message = value.get("MESSAGE")?.as_str()?;
    // Tokens deliberately stop at ssh2; fingerprints and raw messages are never retained.
    let fields: Vec<_> = message.split_whitespace().take(10).collect();
    if fields.len() < 9
        || fields[0] != "Accepted"
        || fields[2] != "for"
        || fields[4] != "from"
        || fields[6] != "port"
        || !matches!(fields[8], "ssh2" | "ssh2:")
    {
        return None;
    }
    if !matches!(
        fields[1],
        "publickey"
            | "password"
            | "keyboard-interactive"
            | "keyboard-interactive/pam"
            | "hostbased"
            | "gssapi-with-mic"
    ) {
        return None;
    }
    if fields[3].len() > 256 || fields[3].chars().any(char::is_control) {
        return None;
    }
    let micros = value
        .get("__REALTIME_TIMESTAMP")?
        .as_str()?
        .parse::<i64>()
        .ok()?;
    let timestamp = DateTime::from_timestamp_micros(micros)?;
    Some((
        cursor.to_string(),
        Login {
            sequence: 0,
            timestamp,
            user: fields[3].to_string(),
            source_ip: fields[5].parse().ok()?,
            source_port: fields[7].parse::<u16>().ok().filter(|port| *port > 0)?,
            method: fields[1].to_string(),
        },
    ))
}

/// Replace atomically and durably on the same filesystem; private by default.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("El archivo necesita un directorio padre")?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, max_bytes: u64) -> Result<Option<T>> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() > max_bytes => bail!("Archivo demasiado grande: {}", path.display()),
        Ok(_) => Ok(Some(
            serde_json::from_slice(&fs::read(path)?)
                .with_context(|| format!("Archivo inválido: {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(message: &str) -> serde_json::Value {
        serde_json::json!({"_COMM":"sshd-session","_UID":"0","__CURSOR":"s=abc;i=123","__REALTIME_TIMESTAMP":"1735689600000000","MESSAGE":message})
    }
    #[test]
    fn parses_both_address_families_without_retaining_key_material() {
        let (_, login) = parse_journal(&record("Accepted publickey for deploy from 2001:db8::1 port 60000 ssh2: ED25519 SHA256:private-context")).unwrap();
        assert_eq!(login.user, "deploy");
        assert_eq!(login.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(
            !serde_json::to_string(&login)
                .unwrap()
                .contains("private-context")
        );
        assert!(
            parse_journal(&record(
                "Accepted password for root from 192.0.2.4 port 22 ssh2"
            ))
            .is_some()
        );
    }
    #[test]
    fn rejects_failed_logins_spoofed_journal_metadata_and_malformed_records() {
        assert!(
            parse_journal(&record(
                "Failed password for root from 192.0.2.4 port 22 ssh2"
            ))
            .is_none()
        );
        let mut v = record("Accepted publickey for root from 192.0.2.4 port 22 ssh2");
        v["_UID"] = "1000".into();
        assert!(parse_journal(&v).is_none());
        v["_UID"] = "0".into();
        v["_COMM"] = "logger".into();
        assert!(parse_journal(&v).is_none());
        assert!(
            parse_journal(&record(
                "Accepted publickey for root from not-an-ip port 70000 ssh2"
            ))
            .is_none()
        );
    }
    #[test]
    fn policies_handle_ipv4_ipv6_mapped_addresses_and_empty_lists() {
        let p = Policy::parse(
            AlertMode::OutsideAllowlist,
            "10.0.0.0/8, 2001:db8::/32\n192.0.2.4",
        )
        .unwrap();
        for s in ["10.2.3.4", "::ffff:10.2.3.4", "2001:db8::2", "192.0.2.4"] {
            assert!(!p.notify(s.parse().unwrap()));
        }
        assert!(p.notify("203.0.113.5".parse().unwrap()));
        assert!(Policy::default().notify("127.0.0.1".parse().unwrap()));
        assert!(Policy::parse(AlertMode::All, "oops").is_err());
        assert!(
            Policy::parse(AlertMode::All, "0.0.0.0/0")
                .unwrap()
                .notify("1.2.3.4".parse().unwrap())
        );
    }
    #[test]
    fn persistence_replaces_validates_and_stays_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"{\"ok\":true}").unwrap();
        assert_eq!(
            read_json::<serde_json::Value>(&path, 100).unwrap().unwrap()["ok"],
            true
        );
        assert!(read_json::<serde_json::Value>(&path, 2).is_err());
        atomic_write(&path, b"broken").unwrap();
        assert!(read_json::<serde_json::Value>(&path, 100).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[tokio::test]
    async fn protocol_reader_handles_fragmentation_and_clean_eof() {
        let mut reader = tokio::io::BufReader::with_capacity(2, &b"one\ntwo\n"[..]);
        assert_eq!(
            read_line(&mut reader).await.unwrap().as_deref(),
            Some("one\n")
        );
        assert_eq!(
            read_line(&mut reader).await.unwrap().as_deref(),
            Some("two\n")
        );
        assert!(read_line(&mut reader).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn protocol_reader_rejects_partial_oversized_and_invalid_utf8_frames() {
        for bytes in [
            b"partial".to_vec(),
            vec![b'x'; MAX_FRAME_BYTES + 1],
            vec![255, b'\n'],
        ] {
            let mut reader = tokio::io::BufReader::new(bytes.as_slice());
            assert!(read_line(&mut reader).await.is_err());
        }
    }
    #[test]
    fn parser_rejects_invalid_ports_versions_and_missing_trusted_fields() {
        for message in [
            "Accepted publickey for user from 192.0.2.1 port 0 ssh2",
            "Accepted publickey for user from 192.0.2.1 port 65536 ssh2",
            "Accepted publickey for user from 192.0.2.1 port 50 ssh2-fake",
            "Accepted mystery for user from 192.0.2.1 port 50 ssh2",
        ] {
            assert!(parse_journal(&record(message)).is_none());
        }
        let mut data = record("Accepted publickey for user from 192.0.2.1 port 50 ssh2");
        data.as_object_mut().unwrap().remove("_UID");
        assert!(parse_journal(&data).is_none());
    }
}
