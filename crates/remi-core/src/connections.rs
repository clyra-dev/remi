//! TCP control messages use a separate SSH channel from login observation.
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub const CONTROL_PROTOCOL: u32 = 1;
pub const CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const CONTROL_REQUEST_BYTES: usize = 4096;
pub const SNAPSHOT_LIMIT: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketKey {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub interface: u32,
    /// Kernel identity prevents closing a replacement socket with the same endpoints.
    pub cookie: [u32; 2],
    pub inode: u32,
}
impl SocketKey {
    pub fn validate_close(&self) -> Result<()> {
        if self.local.is_ipv4() != self.remote.is_ipv4()
            || self.local.port() == 0
            || self.remote.port() == 0
            || self.remote.ip().is_unspecified()
            || self.inode == 0
            || self.cookie == [u32::MAX; 2]
        {
            bail!("La conexión no tiene una identidad válida para cerrarla");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observer {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
impl Observer {
    pub fn from_ssh_connection(value: &str) -> Result<Self> {
        let parts: Vec<_> = value.split_whitespace().collect();
        if parts.len() != 4 {
            bail!("No se pudo identificar la conexión SSH de Remi");
        }
        let observer = Self {
            remote: SocketAddr::new(parts[0].parse()?, parts[1].parse()?),
            local: SocketAddr::new(parts[2].parse()?, parts[3].parse()?),
        };
        if observer.local.port() == 0 || observer.remote.port() == 0 {
            bail!("La conexión SSH tiene un puerto inválido");
        }
        Ok(observer)
    }
    pub fn protects(&self, key: &SocketKey) -> bool {
        fn canonical(ip: IpAddr) -> IpAddr {
            match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                _ => ip,
            }
        }
        fn same(a: SocketAddr, b: SocketAddr) -> bool {
            canonical(a.ip()) == canonical(b.ip()) && a.port() == b.port()
        }
        // Protect both sides when the observer connects through loopback.
        (same(self.local, key.local) && same(self.remote, key.remote))
            || (same(self.local, key.remote) && same(self.remote, key.local))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// Kernel TCP payload recency at capture time; neither HTTP activity nor client identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpTraffic {
    /// None means TCP_INFO reports zero data segments in both directions.
    pub last_data_ago_ms: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpConnection {
    pub key: SocketKey,
    pub state: u8,
    pub uid: u32,
    pub user: String,
    pub processes: Vec<ProcessInfo>,
    pub protected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TcpTraffic>,
}
impl TcpConnection {
    pub fn state_label(&self) -> &'static str {
        match self.state {
            1 => "Establecida",
            2 | 3 | 12 => "Conectando",
            4 | 5 | 9 | 11 => "Cerrando",
            6 => "Espera TCP",
            7 => "Cerrada",
            8 => "Espera de cierre",
            10 => "En escucha",
            _ => "Desconocido",
        }
    }
    pub fn closable(&self) -> bool {
        !self.protected
            && matches!(self.state, 1..=5 | 8 | 9 | 11)
            && self.key.validate_close().is_ok()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionsSnapshot {
    pub captured_at: DateTime<Utc>,
    pub hostname: String,
    pub connections: Vec<TcpConnection>,
    pub total: usize,
    pub can_close: bool,
    pub limitation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overview: Option<crate::services::ServiceOverview>,
    /// None is the server-wide technical sample; Some limits detail to one local port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nginx: Option<crate::services::NginxContext>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlAction {
    List,
    ListService { port: u16 },
    Close { key: SocketKey },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub id: u64,
    pub action: ControlAction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlReply {
    pub id: u64,
    pub result: ControlResult,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResult {
    Ready { protocol: u32 },
    Snapshot { snapshot: ConnectionsSnapshot },
    Closed { key: SocketKey },
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pre_recognition_snapshots_remain_readable_without_inventing_metadata() {
        let input = r#"{"captured_at":"2026-01-01T00:00:00Z","hostname":"test","connections":[{"key":{"local":"127.0.0.1:22","remote":"127.0.0.1:40000","interface":0,"cookie":[1,2],"inode":3},"state":1,"uid":0,"user":"root","processes":[],"protected":true}],"total":1,"can_close":false,"limitation":null,"port":22,"overview":{"services":[{"port":22,"addresses":["0.0.0.0:22"],"programs":["sshd"],"connections":1,"clients":1}],"total_services":1,"connections":1,"other_connections":0}}"#;
        let snapshot: ConnectionsSnapshot = serde_json::from_str(input).unwrap();
        assert!(snapshot.nginx.is_none());
        assert!(snapshot.connections[0].traffic.is_none());
        assert!(
            snapshot
                .overview
                .unwrap()
                .service(22)
                .unwrap()
                .traffic
                .is_none()
        );
    }
    #[test]
    fn protects_observer_and_loopback_reverse_with_mapped_ipv4() {
        let observer = Observer::from_ssh_connection("192.0.2.1 54321 192.0.2.2 22").unwrap();
        let mut key = SocketKey {
            local: "[::ffff:192.0.2.2]:22".parse().unwrap(),
            remote: "[::ffff:192.0.2.1]:54321".parse().unwrap(),
            interface: 0,
            cookie: [1, 2],
            inode: 100,
        };
        assert!(observer.protects(&key));
        std::mem::swap(&mut key.local, &mut key.remote);
        assert!(observer.protects(&key));
        key.local.set_port(54322);
        assert!(!observer.protects(&key));
        assert!(Observer::from_ssh_connection("192.0.2.1 0 192.0.2.2 22").is_err());
    }
    #[test]
    fn rejects_wildcards_missing_cookies_and_listener_closure() {
        let mut row = TcpConnection {
            key: SocketKey {
                local: "127.0.0.1:8080".parse().unwrap(),
                remote: "127.0.0.1:45000".parse().unwrap(),
                interface: 0,
                cookie: [1, 0],
                inode: 5,
            },
            state: 1,
            uid: 1,
            user: "test".into(),
            processes: vec![],
            protected: false,
            traffic: None,
        };
        assert!(row.closable());
        row.state = 10;
        assert!(!row.closable());
        row.state = 1;
        row.protected = true;
        assert!(!row.closable());
        row.protected = false;
        row.key.cookie = [u32::MAX; 2];
        assert!(!row.closable());
        row.key.cookie = [1, 0];
        row.key.inode = 0;
        assert!(!row.closable(), "A missing inode cannot identify a socket");
        row.key.inode = 5;
        assert!(row.closable(), "Other identity fields remain valid");
        row.key.remote = "0.0.0.0:0".parse().unwrap();
        assert!(!row.closable());
    }
}
