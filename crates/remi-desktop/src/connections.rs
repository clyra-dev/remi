use eframe::egui::{self, Color32, RichText};
use remi_core::connections::*;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub struct Connections {
    sender: Option<tokio::sync::mpsc::Sender<ControlRequest>>,
    snapshot: Option<ConnectionsSnapshot>,
    busy: Option<ControlRequest>,
    next_id: u64,
    pending: Option<TcpConnection>,
    filter: String,
    listeners: bool,
    auto_refresh: bool,
    last_attempt: Instant,
    last_received: Option<Instant>,
    error: Option<String>,
    notice: Option<String>,
}

impl Default for Connections {
    fn default() -> Self {
        Self {
            sender: None,
            snapshot: None,
            busy: None,
            next_id: 0,
            pending: None,
            filter: String::new(),
            listeners: true,
            auto_refresh: true,
            last_attempt: Instant::now() - Duration::from_secs(10),
            last_received: None,
            error: None,
            notice: None,
        }
    }
}
impl Connections {
    pub fn reset(&mut self) {
        self.sender = None;
        self.snapshot = None;
        self.busy = None;
        self.pending = None;
        self.last_received = None;
        self.error = None;
        self.notice = None;
    }
    pub fn ready(&mut self, sender: tokio::sync::mpsc::Sender<ControlRequest>) {
        self.sender = Some(sender);
        self.error = None;
        self.last_attempt = Instant::now() - Duration::from_secs(10);
    }
    pub fn unavailable(&mut self, message: String) {
        self.reset();
        self.error = Some(message);
    }
    fn request(&mut self, action: ControlAction) {
        if self.busy.is_some() {
            return;
        }
        let Some(sender) = &self.sender else { return };
        self.next_id += 1;
        let request = ControlRequest {
            id: self.next_id,
            action,
        };
        match sender.try_send(request.clone()) {
            Ok(()) => {
                self.last_attempt = Instant::now();
                self.busy = Some(request);
                self.error = None;
            }
            Err(_) => {
                self.unavailable("El canal de conexiones se cerró; vuelve a conectar Remi".into());
            }
        }
    }
    pub fn reply(&mut self, reply: ControlReply) {
        let Some(request) = self.busy.take() else {
            return;
        };
        if reply.id != request.id {
            self.unavailable("La respuesta no corresponde a la operación pendiente".into());
            return;
        }
        match (request.action, reply.result) {
            (ControlAction::List, ControlResult::Snapshot { snapshot }) => {
                info!(
                    action = "connections_refreshed",
                    request_id = reply.id,
                    count = snapshot.total,
                    can_close = snapshot.can_close
                );
                self.last_received = Some(Instant::now());
                self.snapshot = Some(snapshot);
            }
            (ControlAction::Close { key: expected }, ControlResult::Closed { key })
                if key == expected =>
            {
                info!(action = "connection_closed_confirmed", request_id = reply.id, local = %key.local, remote = %key.remote);
                self.notice = Some(format!("Conexión cerrada: {} ↔ {}", key.local, key.remote));
                if let Some(snapshot) = &mut self.snapshot {
                    let previous = snapshot.connections.len();
                    snapshot.connections.retain(|row| row.key != key);
                    snapshot.total = snapshot
                        .total
                        .saturating_sub(previous - snapshot.connections.len());
                }
                // Read the kernel again even when periodic refresh is disabled.
                self.request(ControlAction::List);
            }
            (_, ControlResult::Error { message }) => {
                warn!(action = "connection_operation_failed", request_id = reply.id, error = %message);
                self.error = Some(message);
                self.last_received = None; // Any destructive action now requires a fresh snapshot.
            }
            _ => self.unavailable("El servidor devolvió un resultado incompatible".into()),
        }
    }
    pub fn show(&mut self, ui: &mut egui::Ui, connected: bool, server_name: &str) {
        ui.heading(RichText::new("Conexiones, en vivo.").size(27.));
        ui.label(format!("{server_name} · TCP IPv4 / IPv6 del servidor"));
        ui.add_space(12.);
        if let Some(error) = &self.error {
            ui.colored_label(Color32::from_rgb(165, 91, 30), error);
        }
        if !connected {
            ui.label("Conecta el servidor para consultar y gestionar sus conexiones reales.");
            return;
        }
        if self.sender.is_none() {
            if self.error.is_none() {
                ui.label("Preparando el canal de conexiones…");
            }
            return;
        }
        if self.busy.is_none()
            && self.pending.is_none()
            && self.last_attempt.elapsed() >= Duration::from_secs(5)
            && (self.auto_refresh || self.snapshot.is_none())
        {
            self.request(ControlAction::List);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.busy.is_none() && self.pending.is_none(),
                    egui::Button::new("Actualizar conexiones"),
                )
                .clicked()
            {
                self.request(ControlAction::List);
            }
            ui.checkbox(&mut self.auto_refresh, "Actualizar cada 5 s");
            if self.busy.is_some() {
                ui.spinner();
                ui.label("Consultando al servidor…");
            }
        });
        if let Some(notice) = &self.notice {
            ui.colored_label(Color32::from_rgb(38, 102, 83), notice);
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let fresh = self
            .last_received
            .is_some_and(|t| t.elapsed() < Duration::from_secs(15));
        let can_close = snapshot.can_close && fresh && self.busy.is_none();
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "{} sockets · {} · {}",
                snapshot.total,
                snapshot.hostname,
                snapshot
                    .captured_at
                    .with_timezone(&chrono::Local)
                    .format("%H:%M:%S")
            ));
            if !fresh {
                ui.colored_label(
                    Color32::from_rgb(165, 91, 30),
                    "Datos pendientes de actualizar",
                );
            }
        });
        if let Some(limitation) = &snapshot.limitation {
            ui.label(RichText::new(limitation).small());
        }
        if snapshot.total > snapshot.connections.len() {
            ui.label(format!(
                "Mostrando {} de {} sockets; la tabla alcanzó el límite de esta versión.",
                snapshot.connections.len(),
                snapshot.total
            ));
        }
        ui.add_space(8.);
        ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text("Buscar IP, puerto, proceso o usuario")
                .desired_width(380.),
        );
        ui.checkbox(&mut self.listeners, "Incluir puertos en escucha");
        ui.label(
            RichText::new(
                "Cerrar corta esa conexión; la aplicación remota puede volver a conectarse.",
            )
            .small(),
        );
        let filter = self.filter.to_lowercase();
        let mut visible = 0;
        egui::ScrollArea::vertical().id_salt("tcp-connections").max_height(430.).show(ui, |ui| {
            for row in &snapshot.connections {
                let process = row.processes.iter().map(|p| format!("{} · PID {}", p.name, p.pid)).collect::<Vec<_>>().join(", ");
                if (!self.listeners && row.state == 10) || !format!("{} {} {} {} {}", row.key.local, row.key.remote, row.user, process, row.state_label()).to_lowercase().contains(&filter) { continue; }
                visible += 1;
                ui.push_id((&row.key.cookie, row.key.local, row.key.remote), |ui| {
                    egui::Frame::new().fill(Color32::WHITE).corner_radius(8).inner_margin(12).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(row.state_label()).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if row.protected { ui.label("Remi · protegida"); }
                                else if row.state == 10 { ui.label("Puerto en escucha"); }
                                else if ui.add_enabled(can_close && row.closable(), egui::Button::new("Cerrar conexión")).clicked() {
                                    info!(action = "connection_close_review", local = %row.key.local, remote = %row.key.remote);
                                    self.pending = Some(row.clone());
                                }
                            });
                        });
                        ui.label(format!("Servidor: {}", row.key.local));
                        if row.state != 10 { ui.label(format!("Remoto: {}", row.key.remote)); }
                        ui.label(RichText::new(format!("Usuario del socket: {} · {}", row.user,
                            if process.is_empty() { "Proceso no disponible" } else { &process })).small());
                    });
                });
                ui.add_space(7.);
            }
        });
        if visible == 0 {
            ui.label("No hay conexiones que coincidan con este filtro.");
        }
        if let Some(target) = self.pending.clone() {
            egui::Modal::new(egui::Id::new("confirm-close-connection")).show(ui.ctx(), |ui| {
                ui.set_max_width(430.);
                ui.heading("Cerrar esta conexión");
                ui.label(server_name);
                ui.monospace(format!("{} ↔ {}", target.key.local, target.key.remote));
                ui.label("La sesión se interrumpirá y cualquier transferencia en curso puede fallar.");
                ui.label("El proceso seguirá ejecutándose y podrá abrir otra conexión.");
                ui.horizontal(|ui| {
                    if ui.button("Cancelar").clicked() {
                        self.pending = None;
                        info!(action = "connection_close_cancelled");
                    }
                    if ui.add_enabled(can_close && target.closable(), egui::Button::new("Confirmar cierre")).clicked() {
                        self.pending = None;
                        self.notice = None;
                        info!(action = "connection_close_confirmed_by_user", local = %target.key.local, remote = %target.key.remote);
                        self.request(ControlAction::Close { key: target.key });
                    }
                });
                if !fresh { ui.label("La lista caducó; cancela y actualiza antes de cerrar."); }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmed_close_updates_count_and_requests_a_fresh_snapshot() {
        let key = SocketKey {
            local: "127.0.0.1:22".parse().unwrap(),
            remote: "127.0.0.1:45000".parse().unwrap(),
            interface: 0,
            cookie: [1, 2],
            inode: 50,
        };
        let mut page = Connections::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.snapshot = Some(ConnectionsSnapshot {
            captured_at: chrono::Utc::now(),
            hostname: "test".into(),
            total: 1,
            can_close: true,
            limitation: None,
            connections: vec![TcpConnection {
                key: key.clone(),
                state: 1,
                uid: 0,
                user: "root".into(),
                processes: vec![],
                protected: false,
            }],
        });
        page.request(ControlAction::Close { key: key.clone() });
        let request = rx.try_recv().unwrap();
        page.reply(ControlReply {
            id: request.id,
            result: ControlResult::Closed { key },
        });
        let snapshot = page.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.total, 0);
        assert!(snapshot.connections.is_empty());
        assert!(matches!(rx.try_recv().unwrap().action, ControlAction::List));
        assert!(page.notice.as_ref().unwrap().contains("Conexión cerrada"));
    }
    #[test]
    fn disconnected_or_unconfirmed_operations_are_never_replayed() {
        let mut page = Connections::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.request(ControlAction::List);
        let request = rx.try_recv().unwrap();
        page.reply(ControlReply {
            id: request.id,
            result: ControlResult::Error {
                message: "lost confirmation".into(),
            },
        });
        assert!(page.busy.is_none());
        assert!(page.last_received.is_none());
        assert!(rx.try_recv().is_err());
        page.reset();
        page.request(ControlAction::List);
        assert!(rx.try_recv().is_err());
        assert!(page.snapshot.is_none());
    }
    #[test]
    fn wrong_response_id_invalidates_control() {
        let mut page = Connections::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.request(ControlAction::List);
        page.reply(ControlReply {
            id: 999,
            result: ControlResult::Error {
                message: "wrong request".into(),
            },
        });
        assert!(page.sender.is_none());
        assert!(page.error.is_some());
    }
}
