use eframe::egui::{self, Color32, RichText};
use remi_core::{
    connections::*,
    services::{ServiceOverview, TcpService},
};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PAGE_SIZE: usize = 6;
const GREEN: Color32 = Color32::from_rgb(38, 102, 83);
const MUTED: Color32 = Color32::from_rgb(112, 123, 120);
const AMBER: Color32 = Color32::from_rgb(165, 91, 30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Services,
    Port(u16),
    Technical,
}

pub struct Connections {
    sender: Option<tokio::sync::mpsc::Sender<ControlRequest>>,
    snapshot: Option<ConnectionsSnapshot>,
    overview: Option<ServiceOverview>,
    scoped_reads: bool,
    busy: Option<ControlRequest>,
    next_id: u64,
    pending: Option<TcpConnection>,
    view: View,
    page: usize,
    filter: String,
    port_query: String,
    internal: bool,
    auto_refresh: bool,
    needs_refresh: bool,
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
            overview: None,
            scoped_reads: false,
            busy: None,
            next_id: 0,
            pending: None,
            view: View::Services,
            page: 0,
            filter: String::new(),
            port_query: String::new(),
            internal: false,
            auto_refresh: true,
            needs_refresh: true,
            last_attempt: Instant::now(),
            last_received: None,
            error: None,
            notice: None,
        }
    }
}
impl Connections {
    /// Invalidate actions, but keep the last view readable during reconnects.
    pub fn reset(&mut self) {
        self.sender = None;
        self.busy = None;
        self.pending = None;
        self.last_received = None;
        self.needs_refresh = true;
    }
    /// Cached data must never cross server identities.
    pub fn clear(&mut self) {
        *self = Self::default();
        info!(action = "connections_server_changed");
    }
    pub fn ready(&mut self, sender: tokio::sync::mpsc::Sender<ControlRequest>) {
        self.sender = Some(sender);
        self.error = None;
        self.needs_refresh = true;
    }
    pub fn unavailable(&mut self, message: String) {
        self.reset();
        self.error = Some(message);
    }
    fn read_action(&self) -> ControlAction {
        match self.view {
            View::Port(port) if self.scoped_reads => ControlAction::ListService { port },
            _ => ControlAction::List,
        }
    }
    fn change_view(&mut self, view: View) {
        if self.view == view {
            return;
        }
        self.view = view;
        self.page = 0;
        self.filter.clear();
        self.needs_refresh = true;
        self.pending = None;
        self.notice = None;
        info!(action = "connections_view_changed", view = ?view);
    }
    fn should_refresh(&self) -> bool {
        self.sender.is_some()
            && self.busy.is_none()
            && self.pending.is_none()
            && (self.needs_refresh
                || (self.view == View::Services
                    && self.auto_refresh
                    && self.last_attempt.elapsed() >= Duration::from_secs(10)))
    }
    fn request(&mut self, action: ControlAction) {
        if self.busy.is_some() {
            return;
        }
        let Some(sender) = &self.sender else {
            return;
        };
        self.next_id += 1;
        let request = ControlRequest {
            id: self.next_id,
            action,
        };
        match sender.try_send(request.clone()) {
            Ok(()) => {
                self.last_attempt = Instant::now();
                self.needs_refresh = false;
                self.busy = Some(request);
                self.error = None;
            }
            Err(_) => self.unavailable("El canal se cerró; reconecta Remi para continuar".into()),
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
            (
                action @ (ControlAction::List | ControlAction::ListService { .. }),
                ControlResult::Snapshot { snapshot },
            ) => {
                let expected_port = match action {
                    ControlAction::ListService { port } => Some(port),
                    _ => None,
                };
                if snapshot.port != expected_port {
                    self.unavailable(
                        "La respuesta corresponde a otro puerto; vuelve a conectar".into(),
                    );
                    return;
                }
                self.scoped_reads = snapshot.overview.is_some();
                let overview = snapshot
                    .overview
                    .clone()
                    .unwrap_or_else(|| ServiceOverview::from_rows(&snapshot.connections));
                debug!(action = "connections_refreshed", request_id = reply.id, port = ?snapshot.port,
                    count = snapshot.total, services = overview.total_services, can_close = snapshot.can_close);
                if self.overview.as_ref().map(|s| s.total_services) != Some(overview.total_services)
                {
                    info!(
                        action = "service_inventory_changed",
                        services = overview.total_services,
                        other_connections = overview.other_connections
                    );
                }
                self.overview = Some(overview);
                self.last_received = Some(Instant::now());
                self.error = None;
                self.snapshot = Some(snapshot);
            }
            (ControlAction::Close { key: expected }, ControlResult::Closed { key })
                if key == expected =>
            {
                info!(action = "connection_closed_confirmed", request_id = reply.id, local = %key.local, remote = %key.remote);
                self.notice = Some(format!("Conexión cerrada: {}", key.remote));
                if let Some(snapshot) = &mut self.snapshot {
                    let previous = snapshot.connections.len();
                    snapshot.connections.retain(|row| row.key != key);
                    snapshot.total = snapshot
                        .total
                        .saturating_sub(previous - snapshot.connections.len());
                }
                self.request(self.read_action());
            }
            (_, ControlResult::Error { message }) => {
                warn!(action = "connection_operation_failed", request_id = reply.id, error = %message);
                self.error = Some(message);
                self.last_received = None;
            }
            _ => self.unavailable("El servidor devolvió un resultado incompatible".into()),
        }
    }
    fn matches_view(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| match self.view {
            View::Services => true,
            View::Port(port) => s.port == Some(port) || (!self.scoped_reads && s.port.is_none()),
            View::Technical => s.port.is_none(),
        })
    }
    fn can_close(&self, connected: bool) -> bool {
        connected
            && self.sender.is_some()
            && self.last_received.is_some()
            && self.busy.is_none()
            && self.matches_view()
            && self.snapshot.as_ref().is_some_and(|s| s.can_close)
    }
    fn services(&self) -> Vec<TcpService> {
        let query = self.filter.to_lowercase();
        self.overview
            .as_ref()
            .map(|o| {
                o.services
                    .iter()
                    .filter(|s| {
                        (self.internal || !s.local_only())
                            && format!("{} {} {:?}", s.port, s.name(), s.addresses)
                                .to_lowercase()
                                .contains(&query)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    fn rows(&self) -> Vec<TcpConnection> {
        if !self.matches_view() {
            return vec![];
        }
        let query = self.filter.to_lowercase();
        let mut rows: Vec<_> = self
            .snapshot
            .as_ref()
            .into_iter()
            .flat_map(|s| &s.connections)
            .filter(|r| {
                let matches_port = match self.view {
                    View::Port(port) => r.key.local.port() == port && r.state != 10,
                    _ => true,
                };
                matches_port
                    && format!(
                        "{} {} {} {}",
                        r.key.local,
                        r.key.remote,
                        r.user,
                        r.processes
                            .iter()
                            .map(|p| p.name.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                    .to_lowercase()
                    .contains(&query)
            })
            .cloned()
            .collect();
        // Counters and TCP state changes never decide a row's position.
        rows.sort_by_key(|r| (r.key.remote, r.key.local, r.key.cookie));
        rows
    }
    pub fn show(&mut self, ui: &mut egui::Ui, connected: bool, server_name: &str) {
        ui.heading(RichText::new("Administra tus conexiones.").size(27.));
        ui.label(
            RichText::new(format!(
                "{server_name} · Elige un servicio para ver quién está conectado."
            ))
            .color(MUTED),
        );
        ui.add_space(10.);
        ui.horizontal(|ui| {
            if ui
                .selectable_label(self.view == View::Services, "Servicios")
                .clicked()
            {
                self.change_view(View::Services);
            }
            if ui
                .selectable_label(self.view == View::Technical, "Vista técnica")
                .clicked()
            {
                self.change_view(View::Technical);
            }
            if let View::Port(port) = self.view {
                ui.label(format!("/ Puerto {port}"));
            }
        });
        if connected && self.should_refresh() {
            self.request(self.read_action());
        }
        if let Some(error) = &self.error {
            ui.colored_label(AMBER, error);
        }
        if !connected || self.sender.is_none() {
            ui.colored_label(
                AMBER,
                if self.snapshot.is_some() {
                    "Sin conexión · conservamos la última vista; las acciones están deshabilitadas."
                } else {
                    "Conecta el servidor para consultar sus servicios."
                },
            );
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    connected
                        && self.sender.is_some()
                        && self.busy.is_none()
                        && self.pending.is_none(),
                    egui::Button::new("Actualizar"),
                )
                .clicked()
            {
                info!(action = "connections_refresh_requested", view = ?self.view);
                self.request(self.read_action());
            }
            if self.view == View::Services {
                if ui
                    .checkbox(&mut self.auto_refresh, "Actualizar cada 10 s")
                    .changed()
                {
                    info!(
                        action = "connections_auto_refresh_changed",
                        enabled = self.auto_refresh
                    );
                }
            } else {
                ui.label(
                    RichText::new("Vista fija para revisar con calma")
                        .small()
                        .color(MUTED),
                );
            }
            if self.busy.is_some() {
                ui.spinner();
            }
            if let Some(snapshot) = &self.snapshot {
                ui.label(
                    RichText::new(format!(
                        "Actualizado {}",
                        snapshot
                            .captured_at
                            .with_timezone(&chrono::Local)
                            .format("%H:%M:%S")
                    ))
                    .small()
                    .color(MUTED),
                );
            }
        });
        if let Some(notice) = &self.notice {
            ui.colored_label(GREEN, notice);
        }
        if let Some(snapshot) = &self.snapshot {
            if let Some(limitation) = &snapshot.limitation {
                ui.label(RichText::new(limitation).small().color(AMBER));
            }
            if !self.scoped_reads {
                ui.label(RichText::new("Resumen parcial: actualiza el agente a 0.3.0 para consultar servicios completos.").small().color(AMBER));
            }
        } else {
            ui.label("Preparando el resumen de servicios…");
            return;
        }
        ui.add_space(10.);
        match self.view {
            View::Services => self.show_services(ui),
            View::Port(_) | View::Technical => self.show_rows(ui, connected),
        }
        self.confirm_close(ui, connected, server_name);
    }
    fn show_services(&mut self, ui: &mut egui::Ui) {
        let Some(overview) = &self.overview else {
            return;
        };
        let network = overview.services.iter().filter(|s| !s.local_only()).count();
        let internal = overview.services.len() - network;
        let incoming = overview.connections;
        let other = overview.other_connections;
        let truncated = overview.total_services > overview.services.len();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{network} servicios de red")).strong());
            ui.label(format!("{incoming} conexiones a servicios"));
            ui.label(
                RichText::new(format!("{other} otras conexiones en segundo plano"))
                    .small()
                    .color(MUTED),
            );
        });
        if truncated {
            ui.colored_label(AMBER, "El resumen alcanzó su límite de servicios; consulta un puerto desde la vista técnica.");
        }
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Buscar servicio o puerto")
                        .desired_width(250.),
                )
                .changed()
            {
                self.page = 0;
            }
            if ui
                .checkbox(&mut self.internal, format!("Incluir internos ({internal})"))
                .changed()
            {
                self.page = 0;
                info!(
                    action = "internal_services_visibility_changed",
                    visible = self.internal
                );
            }
        });
        let services = self.services();
        let total = services.len();
        self.clamp_page(total);
        egui::ScrollArea::vertical()
            .id_salt("service-overview")
            .max_height((ui.available_height() - 45.).max(120.))
            .show(ui, |ui| {
                for service in services.iter().skip(self.page * PAGE_SIZE).take(PAGE_SIZE) {
                    ui.push_id(("service", service.port), |ui| {
                        egui::Frame::new()
                            .fill(Color32::WHITE)
                            .corner_radius(8)
                            .inner_margin(10)
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new(format!(
                                                "{} · {}",
                                                service.name(),
                                                service.port
                                            ))
                                            .strong(),
                                        );
                                        ui.label(
                                            RichText::new(if service.local_only() {
                                                "Solo este servidor"
                                            } else {
                                                "Escuchando en la red"
                                            })
                                            .small()
                                            .color(MUTED),
                                        );
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button("Ver conexiones").clicked() {
                                                self.change_view(View::Port(service.port));
                                            }
                                            ui.label(format!(
                                                "{} conexiones · {} IP",
                                                service.connections, service.clients
                                            ));
                                        },
                                    );
                                });
                            });
                    });
                    ui.add_space(4.);
                }
            });
        if total == 0 {
            ui.label("No hay servicios que coincidan; puedes incluir los internos o abrir la vista técnica.");
        }
        self.pagination(ui, total);
    }
    fn show_rows(&mut self, ui: &mut egui::Ui, connected: bool) {
        if let View::Port(port) = self.view {
            let service = self.overview.as_ref().and_then(|o| o.service(port));
            ui.label(
                RichText::new(format!(
                    "{} · Puerto {port}",
                    service
                        .map(TcpService::name)
                        .unwrap_or_else(|| "Servicio".into())
                ))
                .strong(),
            );
            if let Some(service) = service {
                ui.label(
                    RichText::new(format!(
                        "Escucha en {}",
                        service
                            .addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .small()
                    .color(MUTED),
                );
            } else {
                ui.colored_label(AMBER, "Este puerto ya no aparece en escucha.");
            }
        } else {
            ui.label(
                RichText::new("Detalle TCP del servidor · incluye conexiones internas y de salida")
                    .small()
                    .color(MUTED),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.port_query)
                        .hint_text("Puerto, p. ej. 443")
                        .desired_width(140.),
                );
                let port = self.port_query.parse::<u16>().ok().filter(|p| *p > 0);
                if ui
                    .add_enabled(port.is_some(), egui::Button::new("Consultar puerto"))
                    .clicked()
                {
                    self.change_view(View::Port(port.unwrap()));
                }
            });
        }
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Buscar IP, puerto o proceso")
                    .desired_width(320.),
            )
            .changed()
        {
            self.page = 0;
        }
        if !self.matches_view() {
            ui.label("Cargando las conexiones de esta vista…");
            return;
        }
        let rows = self.rows();
        let total = rows.len();
        let partial = self
            .snapshot
            .as_ref()
            .is_some_and(|s| s.total > s.connections.len());
        if partial {
            ui.label(
                RichText::new(
                    "Detalle parcial: hay más conexiones que el límite de esta consulta.",
                )
                .small()
                .color(AMBER),
            );
        }
        self.clamp_page(total);
        let can_close = self.can_close(connected);
        let id = format!("connection-detail-{:?}-{}", self.view, self.page);
        egui::ScrollArea::vertical().id_salt(id).max_height((ui.available_height() - 45.).max(120.)).show(ui, |ui| {
            for row in rows.iter().skip(self.page * PAGE_SIZE).take(PAGE_SIZE) {
                ui.push_id((&row.key.cookie, row.key.local, row.key.remote), |ui| {
                    egui::Frame::new().fill(Color32::WHITE).corner_radius(8).inner_margin(10).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(if row.state == 10 { format!("Puerto {} en escucha", row.key.local.port()) } else { format!("{} · {}", row.key.remote.ip(), row.state_label()) }).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if row.protected { ui.colored_label(GREEN, "Remi · protegida"); }
                                else if row.state != 10 && ui.add_enabled(can_close && row.closable(), egui::Button::new("Cerrar conexión")).clicked() {
                                    info!(action = "connection_close_review", local = %row.key.local, remote = %row.key.remote);
                                    self.pending = Some(row.clone());
                                }
                            });
                        });
                        ui.label(RichText::new(format!("{} ↔ {}", row.key.local, row.key.remote)).small().color(MUTED));
                        ui.collapsing("Detalles", |ui| {
                            ui.label(format!("Usuario del proceso: {}", row.user));
                            for process in &row.processes { ui.label(format!("{} · PID {}", process.name, process.pid)); }
                            if row.processes.is_empty() { ui.label("Proceso no disponible"); }
                        });
                    });
                });
                ui.add_space(4.);
            }
        });
        if total == 0 {
            ui.label("No hay conexiones que coincidan con esta vista.");
        }
        self.pagination(ui, total);
    }
    fn clamp_page(&mut self, count: usize) {
        self.page = self.page.min(count.saturating_sub(1) / PAGE_SIZE);
    }
    fn pagination(&mut self, ui: &mut egui::Ui, count: usize) {
        let pages = count.div_ceil(PAGE_SIZE).max(1);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.page > 0, egui::Button::new("Anterior"))
                .clicked()
            {
                self.page -= 1;
            }
            ui.label(format!(
                "Página {} de {pages} · {count} resultados",
                self.page + 1
            ));
            if ui
                .add_enabled(self.page + 1 < pages, egui::Button::new("Siguiente"))
                .clicked()
            {
                self.page += 1;
            }
        });
    }
    fn confirm_close(&mut self, ui: &mut egui::Ui, connected: bool, server_name: &str) {
        let Some(target) = self.pending.clone() else {
            return;
        };
        let still_listed = self.snapshot.as_ref().is_some_and(|s| {
            s.connections
                .iter()
                .any(|r| r.key == target.key && r.closable())
        });
        let can_close = self.can_close(connected) && still_listed;
        egui::Modal::new(egui::Id::new("confirm-close-connection")).show(ui.ctx(), |ui| {
            ui.set_max_width(430.);
            ui.heading("Cerrar esta conexión");
            ui.label(server_name);
            ui.monospace(format!("{} ↔ {}", target.key.local, target.key.remote));
            ui.label("La sesión se interrumpirá y cualquier transferencia en curso puede fallar.");
            ui.label("El servicio seguirá ejecutándose; el cliente podrá volver a conectarse.");
            ui.horizontal(|ui| {
                if ui.button("Cancelar").clicked() { self.pending = None; info!(action = "connection_close_cancelled"); }
                if ui.add_enabled(can_close, egui::Button::new("Confirmar cierre")).clicked() {
                    self.pending = None; self.notice = None;
                    info!(action = "connection_close_confirmed_by_user", local = %target.key.local, remote = %target.key.remote);
                    self.request(ControlAction::Close { key: target.key });
                }
            });
            if !can_close { ui.label("Reconecta y actualiza antes de cerrar; esta vista no permite acciones ahora."); }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> ConnectionsSnapshot {
        ConnectionsSnapshot {
            captured_at: chrono::Utc::now(),
            hostname: "test".into(),
            total: 1,
            can_close: true,
            limitation: None,
            port: None,
            overview: None,
            connections: vec![TcpConnection {
                key: SocketKey {
                    local: "127.0.0.1:22".parse().unwrap(),
                    remote: "127.0.0.1:45000".parse().unwrap(),
                    interface: 0,
                    cookie: [1, 2],
                    inode: 50,
                },
                state: 1,
                uid: 0,
                user: "root".into(),
                processes: vec![],
                protected: false,
            }],
        }
    }
    #[test]
    fn confirmed_close_updates_count_and_requests_a_fresh_snapshot() {
        let mut page = Connections::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.snapshot = Some(snapshot());
        let key = page.snapshot.as_ref().unwrap().connections[0].key.clone();
        page.request(ControlAction::Close { key: key.clone() });
        let request = rx.try_recv().unwrap();
        page.reply(ControlReply {
            id: request.id,
            result: ControlResult::Closed { key },
        });
        assert_eq!(page.snapshot.as_ref().unwrap().total, 0);
        assert!(page.snapshot.as_ref().unwrap().connections.is_empty());
        assert!(matches!(rx.try_recv().unwrap().action, ControlAction::List));
    }
    #[test]
    fn disconnect_preserves_display_but_disables_actions_and_never_replays_a_close() {
        let mut page = Connections::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.snapshot = Some(snapshot());
        page.last_received = Some(Instant::now());
        let key = page.snapshot.as_ref().unwrap().connections[0].key.clone();
        page.request(ControlAction::Close { key });
        rx.try_recv().unwrap();
        page.reset();
        assert!(page.snapshot.is_some());
        assert!(!page.can_close(true));
        assert!(rx.try_recv().is_err());
        page.ready(tokio::sync::mpsc::channel(2).0);
        assert!(page.should_refresh());
        assert!(!page.can_close(true));
        assert!(matches!(page.read_action(), ControlAction::List));
        page.clear();
        assert!(page.snapshot.is_none());
    }
    #[test]
    fn detail_stays_fixed_and_reconnect_refreshes_only_the_selected_port() {
        let mut page = Connections::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        page.ready(tx);
        page.scoped_reads = true;
        page.change_view(View::Port(22));
        page.request(page.read_action());
        let request = rx.try_recv().unwrap();
        assert!(matches!(
            request.action,
            ControlAction::ListService { port: 22 }
        ));
        let mut s = snapshot();
        s.port = Some(22);
        s.overview = Some(ServiceOverview::from_rows(&s.connections));
        page.reply(ControlReply {
            id: request.id,
            result: ControlResult::Snapshot { snapshot: s },
        });
        page.last_attempt = Instant::now() - Duration::from_secs(60);
        page.last_received = Some(Instant::now() - Duration::from_secs(60));
        assert!(!page.should_refresh());
        assert!(page.can_close(true));
        page.reset();
        assert!(!page.can_close(true));
        page.ready(tokio::sync::mpsc::channel(2).0);
        assert!(page.should_refresh());
        assert!(matches!(
            page.read_action(),
            ControlAction::ListService { port: 22 }
        ));
    }
    #[test]
    fn scope_mismatch_and_wrong_request_ids_preserve_cache_without_enabling_actions() {
        for wrong_id in [false, true] {
            let mut page = Connections::default();
            let (tx, mut rx) = tokio::sync::mpsc::channel(2);
            page.ready(tx);
            page.snapshot = Some(snapshot());
            page.request(ControlAction::ListService { port: 22 });
            let request = rx.try_recv().unwrap();
            page.reply(ControlReply {
                id: if wrong_id { request.id + 1 } else { request.id },
                result: ControlResult::Snapshot {
                    snapshot: snapshot(),
                },
            });
            assert!(page.sender.is_none());
            assert!(page.snapshot.is_some());
            assert!(!page.can_close(true));
        }
    }
    #[test]
    fn refresh_and_search_preserve_selection_and_pagination_is_bounded() {
        let mut page = Connections {
            snapshot: Some(snapshot()),
            filter: "45000".into(),
            view: View::Port(22),
            page: 100,
            ..Default::default()
        };
        assert_eq!(page.rows().len(), 1);
        page.clamp_page(1);
        assert_eq!(page.page, 0);
        page.filter = "does-not-exist".into();
        assert!(page.rows().is_empty());
        page.change_view(View::Services);
        assert!(page.filter.is_empty());
        assert!(page.needs_refresh);
    }
}
