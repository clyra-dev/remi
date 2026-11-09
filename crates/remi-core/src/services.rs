//! A compact view of listening ports, counted before the detail sample is bounded.
use crate::connections::TcpConnection;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

pub const SERVICE_LIMIT: usize = 256;
pub const RECENT_TRAFFIC_MS: u32 = 10_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficSummary {
    pub recent: usize,
    pub quiet: usize,
    pub transitioning: usize,
    pub unavailable: usize,
}
impl TrafficSummary {
    fn add(&mut self, row: &TcpConnection) {
        if row.state != 1 {
            self.transitioning += 1;
        } else if let Some(traffic) = &row.traffic {
            if traffic
                .last_data_ago_ms
                .is_some_and(|ms| ms < RECENT_TRAFFIC_MS)
            {
                self.recent += 1;
            } else {
                self.quiet += 1;
            }
        } else {
            self.unavailable += 1;
        }
    }
}

/// A bounded catalog from configuration on disk, never per-connection attribution.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NginxContext {
    pub sites: Vec<NginxSite>,
    pub files_read: usize,
    pub partial: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NginxSite {
    pub source: String,
    pub names: Vec<String>,
    pub tls: bool,
    pub backends: Vec<String>,
}

pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpService {
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
    pub programs: Vec<String>,
    pub connections: usize,
    pub clients: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficSummary>,
}
impl TcpService {
    pub fn is_nginx(&self) -> bool {
        self.programs.iter().any(|name| name == "nginx")
    }
    pub fn purpose(&self) -> &'static str {
        if self.is_nginx() {
            "Web y proxy inverso"
        } else if self
            .programs
            .iter()
            .any(|n| matches!(n.as_str(), "sshd" | "sshd-session"))
        {
            "Administración remota"
        } else if self
            .programs
            .iter()
            .any(|n| matches!(n.as_str(), "postgres" | "mysqld" | "mariadbd" | "mongod"))
        {
            "Base de datos"
        } else if self
            .programs
            .iter()
            .any(|n| matches!(n.as_str(), "redis-server" | "memcached"))
        {
            "Almacenamiento en memoria"
        } else {
            "Servicio TCP · propósito sin identificar"
        }
    }
    pub fn local_only(&self) -> bool {
        !self.addresses.is_empty()
            && self
                .addresses
                .iter()
                .all(|a| canonical(a.ip()).is_loopback())
    }
    pub fn name(&self) -> String {
        if self
            .programs
            .iter()
            .any(|n| matches!(n.as_str(), "sshd" | "sshd-session"))
        {
            "SSH".into()
        } else if self.is_nginx() {
            "Nginx".into()
        } else if self.programs.is_empty() {
            "Servicio TCP".into()
        } else {
            self.programs
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join(" / ")
        }
    }
    pub fn accepts(&self, row: &TcpConnection) -> bool {
        self.port == row.key.local.port()
            && self.addresses.iter().any(|a| {
                let bind = canonical(a.ip());
                let local = canonical(row.key.local.ip());
                bind == local || (bind.is_unspecified() && (bind.is_ipv6() || local.is_ipv4()))
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceOverview {
    pub services: Vec<TcpService>,
    pub total_services: usize,
    pub connections: usize,
    pub other_connections: usize,
}
impl ServiceOverview {
    pub fn from_rows(rows: &[TcpConnection]) -> Self {
        let mut services = BTreeMap::<u16, TcpService>::new();
        for row in rows.iter().filter(|r| r.state == 10) {
            let service = services
                .entry(row.key.local.port())
                .or_insert_with(|| TcpService {
                    port: row.key.local.port(),
                    addresses: vec![],
                    programs: vec![],
                    connections: 0,
                    clients: 0,
                    traffic: Some(TrafficSummary::default()),
                });
            if !service.addresses.contains(&row.key.local) {
                service.addresses.push(row.key.local);
                service.addresses.sort();
            }
        }
        let mut clients = BTreeMap::<u16, BTreeSet<IpAddr>>::new();
        let mut other_connections = 0;
        let mut connections = 0;
        for row in rows.iter().filter(|r| r.state != 10) {
            if let Some(service) = services
                .get_mut(&row.key.local.port())
                .filter(|s| s.accepts(row))
            {
                service.connections += 1;
                service.traffic.as_mut().unwrap().add(row);
                clients
                    .entry(service.port)
                    .or_default()
                    .insert(canonical(row.key.remote.ip()));
                connections += 1;
            } else {
                other_connections += 1;
            }
        }
        for (port, service) in &mut services {
            service.clients = clients.get(port).map_or(0, BTreeSet::len);
        }
        let total_services = services.len();
        let mut overview = Self {
            services: services.into_values().take(SERVICE_LIMIT).collect(),
            total_services,
            connections,
            other_connections,
        };
        overview.enrich(rows);
        overview
    }
    pub fn service(&self, port: u16) -> Option<&TcpService> {
        self.services
            .binary_search_by_key(&port, |s| s.port)
            .ok()
            .map(|i| &self.services[i])
    }
    pub fn enrich(&mut self, rows: &[TcpConnection]) {
        // Metadata is read only for the bounded detail sample, with listeners prioritized.
        for row in rows.iter().filter(|r| r.state == 10) {
            if let Ok(i) = self
                .services
                .binary_search_by_key(&row.key.local.port(), |s| s.port)
            {
                let programs = &mut self.services[i].programs;
                for process in &row.processes {
                    if programs.len() < 8 && !programs.contains(&process.name) {
                        programs.push(process.name.clone());
                    }
                }
                programs.sort();
            }
        }
    }
}

pub fn prioritize(rows: &mut [TcpConnection], overview: &ServiceOverview) {
    rows.sort_by_key(|row| {
        let rank = if row.protected {
            0
        } else if row.state == 10 {
            1
        } else if overview
            .service(row.key.local.port())
            .is_some_and(|s| s.accepts(row))
        {
            2
        } else {
            3
        };
        (
            rank,
            row.key.local.port(),
            row.key.local,
            row.key.remote,
            row.key.cookie,
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::{ProcessInfo, SNAPSHOT_LIMIT, SocketKey};
    #[test]
    fn traffic_counts_follow_payload_age_boundary_and_keep_unknown_separate() {
        let mut rows = vec![row("0.0.0.0:443", "0.0.0.0:0", 10)];
        for age in [Some(0), Some(9999), Some(10000), Some(10001), None] {
            let mut r = row("192.0.2.1:443", "198.51.100.1:45000", 1);
            r.traffic = Some(crate::connections::TcpTraffic {
                last_data_ago_ms: age,
            });
            rows.push(r);
        }
        rows.push(row("192.0.2.1:443", "198.51.100.2:45000", 1));
        rows.push(row("192.0.2.1:443", "198.51.100.3:45000", 8));
        let overview = ServiceOverview::from_rows(&rows);
        let service = overview.service(443).unwrap();
        assert_eq!(service.connections, 7);
        assert_eq!(
            service.traffic,
            Some(TrafficSummary {
                recent: 2,
                quiet: 3,
                transitioning: 1,
                unavailable: 1
            })
        );
        assert_eq!(
            service.purpose(),
            "Servicio TCP · propósito sin identificar"
        );
        let mut service = service.clone();
        service.programs = vec!["nginx".into()];
        assert_eq!(service.name(), "Nginx");
        assert_eq!(service.purpose(), "Web y proxy inverso");
        service.programs = vec!["not-nginx".into()];
        assert!(!service.is_nginx());
    }
    fn row(local: &str, remote: &str, state: u8) -> TcpConnection {
        TcpConnection {
            key: SocketKey {
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
                interface: 0,
                cookie: [1, 2],
                inode: 20,
            },
            state,
            uid: 0,
            user: "root".into(),
            processes: vec![],
            protected: false,
            traffic: None,
        }
    }
    #[test]
    fn groups_dual_stack_ports_and_counts_clients_without_assuming_public_exposure() {
        let mut rows = vec![
            row("0.0.0.0:22", "0.0.0.0:0", 10),
            row("[::]:22", "[::]:0", 10),
            row("192.0.2.1:22", "198.51.100.2:40000", 1),
            row("[::ffff:192.0.2.1]:22", "[::ffff:198.51.100.2]:40001", 1),
            row("[::ffff:127.0.0.1]:9000", "[::]:0", 10),
            row("127.0.0.1:9000", "127.0.0.1:45000", 1),
            row("192.0.2.1:9000", "198.51.100.2:45000", 1),
        ];
        rows[0].processes.push(ProcessInfo {
            pid: 10,
            name: "sshd".into(),
        });
        let overview = ServiceOverview::from_rows(&rows);
        assert_eq!(overview.total_services, 2);
        let ssh = overview.service(22).unwrap();
        assert_eq!(ssh.name(), "SSH");
        assert_eq!(
            (ssh.connections, ssh.clients, ssh.addresses.len()),
            (2, 1, 2)
        );
        assert!(!ssh.local_only());
        assert!(overview.service(9000).unwrap().local_only());
        assert_eq!((overview.connections, overview.other_connections), (3, 1));
    }
    #[test]
    fn mixed_bindings_remain_visible_and_summary_bounds_preserve_full_counts() {
        for port in [22, 443, 53000] {
            let rows = [
                row(&format!("127.0.0.1:{port}"), "0.0.0.0:0", 10),
                row(&format!("192.0.2.1:{port}"), "0.0.0.0:0", 10),
            ];
            let overview = ServiceOverview::from_rows(&rows);
            assert!(!overview.service(port).unwrap().local_only());
            let only_loopback = ServiceOverview::from_rows(&rows[..1]);
            assert!(only_loopback.service(port).unwrap().local_only());
        }
        for count in [0, 1, SERVICE_LIMIT - 1, SERVICE_LIMIT, SERVICE_LIMIT + 17] {
            let mut rows = Vec::new();
            for i in 0..count {
                let port = 10000 + i;
                rows.push(row(&format!("0.0.0.0:{port}"), "0.0.0.0:0", 10));
                rows.push(row(&format!("192.0.2.1:{port}"), "198.51.100.1:45000", 1));
            }
            let overview = ServiceOverview::from_rows(&rows);
            assert_eq!(overview.total_services, count);
            assert_eq!(overview.services.len(), count.min(SERVICE_LIMIT));
            assert_eq!(
                overview.connections, count,
                "Counts include omitted services"
            );
            assert_eq!(overview.other_connections, 0);
            assert!(
                overview
                    .services
                    .iter()
                    .all(|s| s.connections == 1 && s.clients == 1)
            );
        }
    }
    #[test]
    fn full_counts_and_listeners_survive_a_large_background_sample() {
        let mut rows = (0..1500)
            .map(|i| row(&format!("192.0.2.1:{}", 30000 + i), "198.51.100.1:443", 1))
            .collect::<Vec<_>>();
        rows.push(row("0.0.0.0:22", "0.0.0.0:0", 10));
        rows.push(row("192.0.2.1:22", "198.51.100.2:45000", 1));
        let overview = ServiceOverview::from_rows(&rows);
        assert_eq!(
            (
                overview.total_services,
                overview.connections,
                overview.other_connections
            ),
            (1, 1, 1500)
        );
        prioritize(&mut rows, &overview);
        rows.truncate(SNAPSHOT_LIMIT);
        assert_eq!(rows[0].state, 10);
        assert_eq!(rows[1].key.local.port(), 22);
        assert_eq!(overview.other_connections, 1500);
    }
}
