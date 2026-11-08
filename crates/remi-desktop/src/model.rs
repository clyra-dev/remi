use anyhow::{Context, Result, bail};
use remi_core::{AlertMode, Login, Policy, atomic_write, read_json};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    std::env::var_os("REMI_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("Library/Application Support/Remi")
        })
}
pub fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        std::env::home_dir().unwrap_or_default().join(rest)
    } else {
        PathBuf::from(path)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub name: String,
    pub host: String,
    pub port: String,
    pub user: String,
    pub key_path: String,
    pub known_hosts: String,
    pub use_agent: bool,
    pub allowed: String,
    pub alert_mode: AlertMode,
    pub auto_connect: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            name: "Mi servidor".into(),
            host: String::new(),
            port: "22".into(),
            user: String::new(),
            key_path: "~/.ssh/id_ed25519".into(),
            known_hosts: "~/.ssh/known_hosts".into(),
            use_agent: true,
            allowed: String::new(),
            alert_mode: AlertMode::OutsideAllowlist,
            auto_connect: true,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "'\";|&$`/".contains(c))
        {
            bail!("Escribe una dirección IP o un nombre de host válido");
        }
        if self.port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
            bail!("El puerto debe estar entre 1 y 65535");
        }
        if self.user.is_empty()
            || self.user.len() > 64
            || self
                .user
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            bail!("Escribe el usuario SSH");
        }
        if self.name.trim().is_empty() || self.name.len() > 80 {
            bail!("El nombre debe tener entre 1 y 80 caracteres");
        }
        if !self.use_agent && !expand_path(&self.key_path).is_file() {
            bail!("No se encontró el archivo de llave SSH");
        }
        self.policy()?;
        Ok(())
    }
    pub fn policy(&self) -> Result<Policy> {
        Policy::parse(self.alert_mode.clone(), &self.allowed)
    }
    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub server: String,
    pub event: Login,
    pub expected: bool,
    pub notified: bool,
    pub simulated: bool,
    #[serde(default)]
    pub observer: bool,
}

impl HistoryEntry {
    pub fn needs_attention(&self) -> bool {
        !self.expected && !self.observer
    }

    pub fn alert_reason(&self, policy: &Policy, initial_backlog: u64) -> &'static str {
        if self.observer {
            "observer_session"
        } else if self.event.sequence <= initial_backlog {
            "initial_history"
        } else if !policy.notify(self.event.source_ip) {
            "allowed_source"
        } else {
            "alert"
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum NotificationTarget {
    History,
    Demo,
    Test,
    Missing,
}

pub fn notification_target(
    id: &str,
    history: &[HistoryEntry],
    demo: &[HistoryEntry],
) -> NotificationTarget {
    if id == "remi-test" {
        NotificationTarget::Test
    } else if history.iter().any(|event| event.id == id) {
        NotificationTarget::History
    } else if demo.iter().any(|event| event.id == id) {
        NotificationTarget::Demo
    } else {
        NotificationTarget::Missing
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DesktopState {
    pub settings: Settings,
    pub endpoint: String,
    pub instance: Option<String>,
    pub cursor: u64,
    pub history: Vec<HistoryEntry>,
}
impl DesktopState {
    pub fn load(path: &Path) -> Result<Self> {
        read_json(path, 32 * 1024 * 1024)
            .context("No se pudo leer el historial; el archivo original se conserva")
            .map(|state| state.unwrap_or_default())
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        atomic_write(path, &serde_json::to_vec_pretty(self)?)
    }
    pub fn add(&mut self, entry: HistoryEntry) -> bool {
        if self.history.iter().any(|e| e.id == entry.id) {
            return false;
        }
        self.history.insert(0, entry);
        self.history.truncate(2000);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_do_not_contain_credentials_and_validate_networks() {
        let mut s = Settings {
            host: "127.0.0.1".into(),
            user: "reader".into(),
            ..Default::default()
        };
        assert!(s.validate().is_ok());
        s.allowed = "not-a-network".into();
        assert!(s.validate().is_err());
        s.allowed.clear();
        s.port = "0".into();
        assert!(s.validate().is_err());
        assert!(!serde_json::to_string(&s).unwrap().contains("passphrase"));
    }
    fn entry(id: &str) -> HistoryEntry {
        HistoryEntry {
            id: id.into(),
            server: "test".into(),
            expected: false,
            notified: false,
            simulated: id.starts_with("demo-"),
            observer: false,
            event: Login {
                sequence: 1,
                timestamp: chrono::Utc::now(),
                user: "reader".into(),
                source_ip: "192.0.2.1".parse().unwrap(),
                source_port: 45000,
                method: "publickey".into(),
                origin: None,
            },
        }
    }
    #[test]
    fn notification_navigation_distinguishes_demo_real_test_and_evicted_events() {
        let history = [entry("server:1")];
        let demo = [entry("demo-1")];
        assert_eq!(
            notification_target("server:1", &history, &demo),
            NotificationTarget::History
        );
        assert_eq!(
            notification_target("demo-1", &history, &demo),
            NotificationTarget::Demo
        );
        assert_eq!(
            notification_target("remi-test", &history, &demo),
            NotificationTarget::Test
        );
        assert_eq!(
            notification_target("server:old", &history, &demo),
            NotificationTarget::Missing
        );
    }
    #[test]
    fn own_login_stays_in_history_without_alerting_but_same_ip_other_session_alerts() {
        let mut own = entry("server:1");
        own.observer = true;
        let other = entry("server:2");
        for mode in [AlertMode::All, AlertMode::OutsideAllowlist] {
            let policy = Policy::parse(mode, "").unwrap();
            assert_eq!(own.alert_reason(&policy, 0), "observer_session");
            assert!(!own.needs_attention());
            assert_eq!(other.event.source_ip, own.event.source_ip);
            assert_eq!(other.alert_reason(&policy, 0), "alert");
            assert!(other.needs_attention());
            assert_eq!(other.alert_reason(&policy, 1), "initial_history");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = DesktopState::default();
        assert!(state.add(own));
        assert!(state.add(other));
        state.save(&path).unwrap();
        let restored = DesktopState::load(&path).unwrap();
        assert_eq!(restored.history.len(), 2);
        assert!(!restored.history[0].observer);
        assert!(restored.history[1].observer);
        assert!(!restored.history[1].notified);
    }

    #[test]
    fn old_history_is_not_reclassified_and_allowlist_modes_are_preserved() {
        let old = entry("old");
        let mut value = serde_json::to_value(&old).unwrap();
        value.as_object_mut().unwrap().remove("observer");
        value["event"].as_object_mut().unwrap().remove("origin");
        let restored: HistoryEntry = serde_json::from_value(value).unwrap();
        assert!(!restored.observer);
        assert!(restored.needs_attention());
        let allow = old.event.source_ip.to_string();
        assert_eq!(
            restored.alert_reason(
                &Policy::parse(AlertMode::OutsideAllowlist, &allow).unwrap(),
                0
            ),
            "allowed_source"
        );
        assert_eq!(
            restored.alert_reason(&Policy::parse(AlertMode::All, &allow).unwrap(), 0),
            "alert"
        );
    }
    #[test]
    fn desktop_history_is_bounded_deduplicated_and_survives_restart() {
        let mut state = DesktopState::default();
        for index in 0..2005 {
            assert!(state.add(entry(&format!("event-{index}"))));
        }
        assert_eq!(state.history.len(), 2000);
        assert!(!state.add(entry("event-2004")));
        assert_eq!(state.history.last().unwrap().id, "event-5");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        state.save(&path).unwrap();
        assert_eq!(DesktopState::load(&path).unwrap().history.len(), 2000);
        std::fs::write(&path, b"corrupted").unwrap();
        assert!(DesktopState::load(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"corrupted");
    }
}
