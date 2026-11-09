use crate::{
    model::{DesktopState, HistoryEntry, NotificationTarget, Settings, notification_target},
    notifications::Notifications,
    transport::{self, Cursor, Envelope, Update, Updates},
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use remi_core::{AlertMode, Frame, Login, PROTOCOL};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering, mpsc},
    time::{Duration, Instant},
};
use tracing::{info, warn};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

const INK: Color32 = Color32::from_rgb(31, 48, 46);
const ACCENT: Color32 = Color32::from_rgb(38, 102, 83);
const MUTED: Color32 = Color32::from_rgb(112, 123, 120);
const PAPER: Color32 = Color32::from_rgb(247, 248, 245);
const AMBER: Color32 = Color32::from_rgb(165, 91, 30);

#[derive(PartialEq)]
enum Page {
    Activity,
    Connections,
    Server,
    Preferences,
}
struct PendingHost {
    host: String,
    port: u16,
    fingerprint: String,
    key: String,
}
struct Tray {
    _icon: TrayIcon,
    open: MenuItem,
    status: MenuItem,
    quit: MenuItem,
}

pub struct Remi {
    connections: crate::connections::Connections,
    state: DesktopState,
    draft: Settings,
    path: PathBuf,
    writable: bool,
    page: Page,
    error: Option<String>,
    notice: Option<String>,
    passphrase: String,
    tx: mpsc::Sender<Envelope>,
    rx: mpsc::Receiver<Envelope>,
    task: Option<tokio::task::JoinHandle<()>>,
    generation: u64,
    cursor: Arc<Mutex<Cursor>>,
    status: String,
    connected: bool,
    last_heartbeat: Option<Instant>,
    initial_backlog: u64,
    simulated_agent: bool,
    observer_identified: bool,
    demo: bool,
    demo_events: Vec<HistoryEntry>,
    demo_counter: u64,
    selected: Option<String>,
    scroll_to_selected: bool,
    filter: String,
    only_alerts: bool,
    notifications: Notifications,
    last_permission_check: Instant,
    pending: Vec<HistoryEntry>,
    last_notification: Instant,
    pending_host: Option<PendingHost>,
    tray: Option<Tray>,
    tray_attempted: bool,
    quit: bool,
    menu_events: Arc<Mutex<Vec<tray_icon::menu::MenuId>>>,
}

impl Remi {
    pub fn new(cc: &eframe::CreationContext<'_>, directory: PathBuf) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::light();
        style.visuals.panel_fill = PAPER;
        style.visuals.window_fill = Color32::WHITE;
        style.visuals.override_text_color = Some(INK);
        style.visuals.selection.bg_fill = Color32::from_rgb(211, 232, 220);
        style.visuals.selection.stroke.color = INK;
        style.spacing.item_spacing = Vec2::new(12., 10.);
        style.spacing.button_padding = Vec2::new(14., 9.);
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.));
        cc.egui_ctx.set_style(style);
        let path = directory.join("state.json");
        let (state, error, writable) = match DesktopState::load(&path) {
            Ok(s) => (s, None, true),
            Err(e) => (DesktopState::default(), Some(format!("{e:#}")), false),
        };
        let (tx, rx) = mpsc::channel();
        let cursor = Arc::new(Mutex::new(Cursor {
            instance: state.instance.clone(),
            sequence: state.cursor,
        }));
        let auto_connect =
            state.settings.auto_connect && !state.settings.host.is_empty() && writable;
        let mut app = Self {
            connections: crate::connections::Connections::default(),
            draft: state.settings.clone(),
            state,
            path,
            writable,
            page: Page::Activity,
            error,
            notice: None,
            passphrase: String::new(),
            tx,
            rx,
            task: None,
            generation: 0,
            cursor,
            status: "Sin conectar".into(),
            connected: false,
            last_heartbeat: None,
            initial_backlog: 0,
            simulated_agent: false,
            observer_identified: false,
            demo: false,
            demo_events: Vec::new(),
            demo_counter: 0,
            selected: None,
            scroll_to_selected: false,
            filter: String::new(),
            only_alerts: false,
            notifications: Notifications::new(cc.egui_ctx.clone()),
            last_permission_check: Instant::now(),
            pending: Vec::new(),
            last_notification: Instant::now() - Duration::from_secs(10),
            pending_host: None,
            tray: None,
            tray_attempted: false,
            quit: false,
            menu_events: Arc::new(Mutex::new(Vec::new())),
        };
        if auto_connect {
            app.connect(&cc.egui_ctx);
        }
        app
    }
    fn save(&mut self) -> bool {
        if !self.writable {
            return false;
        }
        match self.state.save(&self.path) {
            Ok(_) => true,
            Err(e) => {
                self.error = Some(format!("No se pudo guardar: {e}"));
                warn!(action = "desktop_persist_failed", error = %e);
                false
            }
        }
    }
    fn disconnect(&mut self) {
        self.connections.reset();
        self.generation += 1;
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.connected = false;
        self.observer_identified = false;
        self.last_heartbeat = None;
        self.status = "Sin conectar".into();
        self.pending.clear();
        info!(action = "desktop_disconnected");
    }
    fn connect(&mut self, ctx: &egui::Context) {
        if !self.writable {
            return;
        }
        if let Err(e) = self.draft.validate() {
            self.error = Some(e.to_string());
            return;
        }
        self.disconnect();
        self.demo = false;
        self.simulated_agent = false;
        self.pending_host = None;
        let endpoint = self.draft.endpoint();
        if endpoint != self.state.endpoint {
            self.connections.clear();
            self.state.instance = None;
            self.state.cursor = 0;
        }
        self.state.endpoint = endpoint;
        self.state.settings = self.draft.clone();
        if !self.save() {
            return;
        }
        *self.cursor.lock().unwrap() = Cursor {
            instance: self.state.instance.clone(),
            sequence: self.state.cursor,
        };
        self.error = None;
        self.notice = None;
        self.status = "Conectando…".into();
        self.task = Some(transport::start(
            self.state.settings.clone(),
            self.passphrase.clone(),
            self.cursor.clone(),
            Updates {
                tx: self.tx.clone(),
                context: ctx.clone(),
                generation: self.generation,
            },
        ));
        self.page = Page::Activity;
    }
    fn process(&mut self) {
        while let Ok(envelope) = self.rx.try_recv() {
            if envelope.generation != self.generation {
                continue;
            }
            match envelope.update {
                Update::Connecting => {
                    self.observer_identified = false;
                    self.connections.reset();
                    self.connected = false;
                    self.status = "Conectando…".into();
                }
                Update::Disconnected(error) => {
                    self.observer_identified = false;
                    self.connections.reset();
                    self.connected = false;
                    self.status = "Sin conexión".into();
                    self.error = Some(error);
                }
                Update::HostKey {
                    host,
                    port,
                    fingerprint,
                    key,
                } => {
                    self.status = "Verifica la identidad".into();
                    self.connected = false;
                    self.pending_host = Some(PendingHost {
                        host,
                        port,
                        fingerprint,
                        key,
                    });
                    self.page = Page::Server;
                }
                Update::Frame(frame) => self.receive(frame),
                Update::ControlReady(sender) => self.connections.ready(sender),
                Update::ControlReply(reply) => self.connections.reply(reply),
                Update::ControlUnavailable(message) => self.connections.unavailable(message),
            }
        }
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            self.task = None;
        }
        if !self.demo
            && self.connected
            && self
                .last_heartbeat
                .is_some_and(|t| t.elapsed() > Duration::from_secs(15))
        {
            self.connected = false;
            self.status = "Esperando al agente".into();
        }
    }
    fn receive(&mut self, frame: Frame) {
        match frame {
            Frame::Hello {
                protocol,
                instance,
                latest,
                resync,
                gap,
                journal_ready,
                simulated,
                observer_identified,
                ..
            } => {
                if protocol != PROTOCOL {
                    self.error = Some("Actualiza Remi: protocolo incompatible".into());
                    self.disconnect();
                    return;
                }
                self.initial_backlog = if resync { latest } else { 0 };
                if resync {
                    self.state.cursor = 0;
                }
                self.state.instance = Some(instance);
                self.simulated_agent = simulated;
                self.observer_identified = observer_identified && !simulated;
                if !self.save() {
                    self.disconnect();
                    return;
                }
                *self.cursor.lock().unwrap() = Cursor {
                    instance: self.state.instance.clone(),
                    sequence: self.state.cursor,
                };
                self.error = None;
                self.notice = if gap {
                    Some("Hay un intervalo fuera del historial disponible; se recuperaron los eventos conservados".into())
                } else if resync && latest > 0 {
                    Some("Historial recuperado; los accesos anteriores a esta primera conexión no generan avisos".into())
                } else if !simulated && !observer_identified {
                    Some("No se pudo identificar la sesión de Remi; sus accesos también pueden generar avisos".into())
                } else {
                    None
                };
                self.connected = journal_ready;
                self.last_heartbeat = Some(Instant::now());
                self.status = if journal_ready {
                    "Vigilando"
                } else {
                    "Colector iniciando"
                }
                .into();
                info!(
                    action = "agent_connected",
                    resumed = !resync,
                    gap,
                    simulated
                );
                info!(
                    action = "observer_identity_received",
                    identified = self.observer_identified
                );
            }
            Frame::Heartbeat { journal_ready, .. } => {
                self.last_heartbeat = Some(Instant::now());
                self.connected = journal_ready;
                self.status = if journal_ready {
                    "Vigilando"
                } else {
                    "Colector no disponible"
                }
                .into();
            }
            Frame::Login { event, observer } => {
                if event.sequence <= self.state.cursor {
                    return;
                }
                if event.user.len() > 256
                    || event.user.chars().any(char::is_control)
                    || event.method.len() > 64
                {
                    self.error = Some("Evento inválido del agente".into());
                    self.disconnect();
                    return;
                }
                let policy = match self.state.settings.policy() {
                    Ok(p) => p,
                    Err(e) => {
                        self.error = Some(e.to_string());
                        self.disconnect();
                        return;
                    }
                };
                let entry = HistoryEntry {
                    id: format!(
                        "{}:{}:{}",
                        self.state.endpoint,
                        self.state.instance.as_deref().unwrap_or("unknown"),
                        event.sequence
                    ),
                    server: self.state.settings.name.clone(),
                    expected: policy.expected(event.source_ip),
                    notified: false,
                    simulated: self.simulated_agent,
                    observer: observer && self.observer_identified,
                    event,
                };
                let reason = entry.alert_reason(&policy, self.initial_backlog);
                let should_notify = reason == "alert";
                // Preserve both event and cursor in one atomic snapshot before acknowledging receipt.
                let previous = self.state.clone();
                self.state.cursor = entry.event.sequence;
                let added = self.state.add(entry.clone());
                if !self.save() {
                    self.state = previous;
                    self.disconnect();
                    return;
                }
                *self.cursor.lock().unwrap() = Cursor {
                    instance: self.state.instance.clone(),
                    sequence: self.state.cursor,
                };
                if added && should_notify {
                    self.pending.push(entry.clone());
                }
                info!(
                    action = "login_evaluated",
                    sequence = entry.event.sequence,
                    expected = entry.expected,
                    observer = entry.observer,
                    reason,
                    alert = should_notify
                );
            }
            Frame::Error { message } => {
                self.error = Some(message);
                self.disconnect();
            }
        }
    }
    fn notifications(&mut self) {
        if self.last_permission_check.elapsed() > Duration::from_secs(15) {
            self.notifications.refresh();
            self.last_permission_check = Instant::now();
        }
        if self.pending.is_empty() || self.last_notification.elapsed() < Duration::from_secs(8) {
            return;
        }
        let latest = self.pending.last().unwrap();
        let title = if latest.simulated {
            "Remi · Demostración".to_string()
        } else if self.pending.len() > 1 {
            format!("Remi · {} accesos SSH", self.pending.len())
        } else {
            format!("Remi · {}", latest.server)
        };
        let body = if self.pending.len() > 1 {
            format!(
                "{} accesos requieren tu atención. Abre Remi para verlos.",
                self.pending.len()
            )
        } else {
            format!(
                "{} inició sesión desde {}. {}",
                latest.event.user,
                latest.event.source_ip,
                if latest.expected {
                    "Aviso de todos los accesos activado."
                } else {
                    "Fuera de tu lista permitida."
                }
            )
        };
        let sent = self.notifications.send(&latest.id, &title, &body);
        info!(
            action = "notification_batch",
            count = self.pending.len(),
            submitted = sent,
            simulated = latest.simulated
        );
        if sent {
            for pending in &self.pending {
                if let Some(entry) = self.state.history.iter_mut().find(|e| e.id == pending.id) {
                    entry.notified = true;
                }
            }
            self.save();
        }
        self.pending.clear();
        self.last_notification = Instant::now();
    }
    fn demo_event(&mut self, expected: bool) {
        self.demo_counter += 1;
        let event = Login {
            sequence: self.demo_counter,
            timestamp: chrono::Utc::now(),
            user: if expected { "deploy" } else { "root" }.into(),
            source_ip: if expected {
                "192.0.2.12"
            } else {
                "203.0.113.42"
            }
            .parse()
            .unwrap(),
            source_port: 51432,
            method: "publickey".into(),
            origin: None,
        };
        let entry = HistoryEntry {
            id: format!("demo-{}", uuid::Uuid::new_v4()),
            server: "Debian · demo".into(),
            event,
            expected,
            notified: false,
            simulated: true,
            observer: false,
        };
        if !expected {
            self.pending.push(entry.clone());
        }
        self.demo_events.insert(0, entry);
        self.demo_events.truncate(50);
        info!(action = "demo_login_generated", expected);
    }
    fn init_tray(&mut self, ctx: &egui::Context) {
        if self.tray_attempted {
            return;
        }
        self.tray_attempted = true;
        let menu = Menu::new();
        let status = MenuItem::new("Remi · Sin conectar", false, None);
        let open = MenuItem::new("Abrir Remi", true, None);
        let quit = MenuItem::new("Salir de Remi", true, None);
        let result = (|| -> anyhow::Result<Tray> {
            menu.append_items(&[&status, &PredefinedMenuItem::separator(), &open, &quit])?;
            let rgba = icon_pixels(32);
            let icon = tray_icon::Icon::from_rgba(rgba, 32, 32)?;
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_icon(icon)
                .with_tooltip("Remi · Tu servidor, a la vista")
                .build()?;
            Ok(Tray {
                _icon: tray,
                status,
                open,
                quit,
            })
        })();
        match result {
            Ok(tray) => {
                self.tray = Some(tray);
                info!(action = "tray_ready");
            }
            Err(e) => {
                warn!(action = "tray_failed", error = %e);
                self.error =
                    Some("No se pudo crear el icono de barra; mantén abierta esta ventana".into());
            }
        }
        let context = ctx.clone();
        let events = self.menu_events.clone();
        MenuEvent::set_event_handler(Some(move |event: tray_icon::menu::MenuEvent| {
            if let Ok(mut queue) = events.lock() {
                queue.push(event.id);
            }
            context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            context.request_repaint();
        }));
    }
    fn raise(ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .exact_width(180.)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(237, 241, 235))
                    .inner_margin(22),
            )
            .show(ctx, |ui| {
                ui.add_space(18.);
                ui.label(RichText::new("remi").size(38.).strong().color(INK));
                ui.label(
                    RichText::new("TU SERVIDOR, A LA VISTA")
                        .size(9.)
                        .color(MUTED),
                );
                ui.add_space(42.);
                for (page, title) in [
                    (Page::Activity, "Actividad"),
                    (Page::Connections, "Conexiones"),
                    (Page::Server, "Servidor"),
                    (Page::Preferences, "Preferencias"),
                ] {
                    let response = ui.add_sized(
                        [132., 38.],
                        egui::Button::new(title).selected(self.page == page),
                    );
                    if response.clicked() {
                        self.page = page;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new(concat!("v", env!("CARGO_PKG_VERSION"), " · macOS"))
                            .size(11.)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new("Remote Event\nMonitoring Interface")
                            .size(11.)
                            .color(MUTED),
                    );
                    ui.add_space(14.);
                    let (label, color) = if self.demo {
                        ("Demostración", AMBER)
                    } else if self.connected {
                        ("Vigilando", ACCENT)
                    } else {
                        ("Sin conexión", MUTED)
                    };
                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(8., 16.), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 3., color);
                        ui.colored_label(color, label);
                    });
                });
            });
    }
    fn activity(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new("Un vistazo, y tranquilo.").size(27.));
                ui.label(RichText::new("Los accesos SSH que necesitas conocer.").color(MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.task.is_some() && !self.demo {
                    if ui.button("Desconectar").clicked() {
                        self.disconnect();
                        self.error = None;
                        self.notice = None;
                    }
                } else if !self.state.settings.host.is_empty()
                    && !self.demo
                    && ui.button("Conectar").clicked()
                {
                    self.connect(ctx);
                }
            });
        });
        ui.add_space(18.);
        if self.demo {
            card(ui, |ui| {
                ui.colored_label(AMBER, "DEMOSTRACIÓN · Estos eventos son ficticios");
                ui.horizontal(|ui| {
                    if ui.button("Simular acceso inesperado").clicked() {
                        self.demo_event(false);
                    }
                    if ui.button("Simular acceso permitido").clicked() {
                        self.demo_event(true);
                    }
                    if ui.button("Terminar demo").clicked() {
                        self.demo = false;
                        self.pending.clear();
                        self.selected = None;
                    }
                });
            });
            ui.add_space(12.);
        }
        let entries = if self.demo {
            self.demo_events.clone()
        } else {
            self.state.history.clone()
        };
        let unexpected = entries.iter().filter(|e| e.needs_attention()).count();
        ui.columns(3, |columns| {
            for (column, title, value) in [
                (0, "ACCESOS GUARDADOS", entries.len().to_string()),
                (1, "FUERA DE TU LISTA", unexpected.to_string()),
                (
                    2,
                    "ESTADO",
                    if self.demo {
                        "Demo".into()
                    } else {
                        self.status.clone()
                    },
                ),
            ] {
                card(&mut columns[column], |ui| {
                    ui.label(RichText::new(title).size(10.).color(MUTED));
                    ui.label(
                        RichText::new(value)
                            .size(if column == 2 { 19. } else { 28. })
                            .strong(),
                    );
                });
            }
        });
        ui.add_space(18.);
        if entries.is_empty() {
            ui.add_space(35.);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Tu próxima señal aparecerá aquí.").size(22.));
                ui.add_space(8.);
                ui.label("Conecta tu servidor Debian para empezar a observar accesos.");
                ui.add_space(18.);
                if primary(ui, "Configurar servidor").clicked() {
                    self.page = Page::Server;
                }
                if ui.button("Explorar una demostración").clicked() {
                    self.disconnect();
                    self.demo = true;
                    self.error = None;
                    self.demo_event(true);
                }
            });
            return;
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Buscar usuario, IP o servidor")
                    .desired_width(280.),
            );
            ui.checkbox(&mut self.only_alerts, "Solo fuera de mi lista");
        });
        ui.add_space(8.);
        let filter = self.filter.to_lowercase();
        let mut visible = 0;
        egui::ScrollArea::vertical()
            .id_salt("history")
            .show(ui, |ui| {
                for entry in entries.iter().filter(|e| {
                    (!self.only_alerts || e.needs_attention())
                        && format!("{} {} {}", e.event.user, e.event.source_ip, e.server)
                            .to_lowercase()
                            .contains(&filter)
                }) {
                    visible += 1;
                    let selected = self.selected.as_deref() == Some(&entry.id);
                    let label = format!(
                        "{}   {}  ·  {}\n      {}  ·  {}",
                        if entry.observer {
                            "Remi"
                        } else if entry.expected {
                            "OK"
                        } else {
                            "!"
                        },
                        entry.event.user,
                        entry.event.source_ip,
                        entry.server,
                        entry
                            .event
                            .timestamp
                            .with_timezone(&chrono::Local)
                            .format("%d %b · %H:%M:%S")
                    );
                    let response = ui.add_sized(
                        [ui.available_width(), 63.],
                        egui::Button::new(RichText::new(label).color(if entry.needs_attention() {
                            AMBER
                        } else {
                            INK
                        }))
                        .selected(selected),
                    );
                    if selected && self.scroll_to_selected {
                        response.scroll_to_me(Some(egui::Align::Center));
                        self.scroll_to_selected = false;
                    }
                    if response.clicked() {
                        self.selected = Some(entry.id.clone());
                    }
                    if selected {
                        card(ui, |ui| {
                            ui.label(
                                RichText::new(if entry.observer {
                                    "Conexión de Remi · registrada sin aviso"
                                } else if entry.expected {
                                    "Origen dentro de tu lista permitida"
                                } else {
                                    "Origen fuera de tu lista permitida al recibir el evento"
                                })
                                .strong(),
                            );
                            ui.label(format!(
                                "Usuario: {} · Método: {} · Puerto de origen: {}",
                                entry.event.user, entry.event.method, entry.event.source_port
                            ));
                            ui.label(format!(
                                "Fecha: {}",
                                entry
                                    .event
                                    .timestamp
                                    .with_timezone(&chrono::Local)
                                    .format("%Y-%m-%d %H:%M:%S %:z")
                            ));
                            if entry.simulated {
                                ui.colored_label(AMBER, "Evento de demostración");
                            }
                            ui.label(
                                RichText::new(format!("Evento #{}", entry.event.sequence))
                                    .small()
                                    .color(MUTED),
                            );
                        });
                    }
                }
                if visible == 0 {
                    ui.label("No hay accesos que coincidan con estos filtros.");
                }
            });
    }
    fn server(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading(RichText::new("Conoce a tu servidor.").size(27.));
        ui.label(
            RichText::new("Un Debian. Una conexión SSH. Sus accesos, en tu Mac.").color(MUTED),
        );
        ui.add_space(18.);
        card(ui, |ui| {
            field(ui, "Nombre", &mut self.draft.name, "Producción");
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("IP o dominio");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.draft.host)
                            .hint_text("servidor.example.com")
                            .desired_width(310.),
                    );
                });
                ui.vertical(|ui| {
                    ui.label("Puerto");
                    ui.add(egui::TextEdit::singleline(&mut self.draft.port).desired_width(65.));
                });
            });
            field(ui, "Usuario SSH", &mut self.draft.user, "admin");
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.draft.use_agent, true, "Agente SSH");
                ui.radio_value(&mut self.draft.use_agent, false, "Archivo de llave");
            });
            if !self.draft.use_agent {
                field(
                    ui,
                    "Ruta de la llave",
                    &mut self.draft.key_path,
                    "~/.ssh/id_ed25519",
                );
                ui.label("Frase de acceso · solo en memoria");
                ui.add(
                    egui::TextEdit::singleline(&mut self.passphrase)
                        .password(true)
                        .desired_width(420.),
                );
            }
            ui.collapsing("Identidad del servidor", |ui| {
                field(
                    ui,
                    "Archivo known_hosts",
                    &mut self.draft.known_hosts,
                    "~/.ssh/known_hosts",
                );
            });
            ui.checkbox(&mut self.draft.auto_connect, "Reconectar al abrir Remi");
            ui.add_space(4.);
            if ui
                .add_enabled(
                    self.writable,
                    egui::Button::new(RichText::new("Guardar y conectar").color(Color32::WHITE))
                        .fill(ACCENT),
                )
                .clicked()
            {
                self.connect(ctx);
            }
        });
        if let Some(host) = &self.pending_host {
            ui.add_space(12.);
            let (hostname, port, fingerprint, key) = (
                host.host.clone(),
                host.port,
                host.fingerprint.clone(),
                host.key.clone(),
            );
            card(ui, |ui| {
                ui.colored_label(AMBER, "Primera conexión · confirma la identidad SSH");
                ui.label(format!("{hostname}:{port}"));
                ui.monospace(&fingerprint);
                ui.label("Compara esta huella con la consola de tu proveedor antes de confiar.");
                if ui.button("Confiar en esta identidad y conectar").clicked() {
                    match transport::trust_host(&self.draft, &hostname, port, &key) {
                        Ok(_) => self.connect(ctx),
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
            });
        }
        ui.add_space(16.);
        ui.collapsing("Preparar Debian", |ui| {
            ui.label("Instala el paquete .deb y autoriza a tu usuario SSH como lector.");
            ui.monospace(format!(
                "sudo apt install ./remi-agent_{}_arm64.deb",
                env!("CARGO_PKG_VERSION")
            ));
            ui.monospace("sudo remi-agent authorize TU_USUARIO");
            ui.label("Vuelve a iniciar sesión SSH después de autorizar al usuario.");
            ui.label("Usa el paquete amd64 si tu servidor tiene un procesador Intel o AMD.");
        });
    }
    fn preferences(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Avisos con intención.").size(27.));
        ui.label(RichText::new("Elige qué merece tu atención.").color(MUTED));
        ui.add_space(18.);
        card(ui, |ui| {
            ui.label(RichText::new("Cuándo avisar").strong());
            ui.radio_value(
                &mut self.draft.alert_mode,
                AlertMode::OutsideAllowlist,
                "Solo accesos fuera de mi lista",
            );
            ui.radio_value(
                &mut self.draft.alert_mode,
                AlertMode::All,
                "Todos los accesos SSH",
            );
            ui.label(
                RichText::new("Las conexiones identificadas como Remi se guardan sin avisos.")
                    .small()
                    .color(MUTED),
            );
            ui.add_space(8.);
            ui.label("IP y redes permitidas");
            ui.add(
                egui::TextEdit::multiline(&mut self.draft.allowed)
                    .hint_text("192.0.2.10\n10.0.0.0/8\n2001:db8::/32")
                    .desired_rows(4)
                    .desired_width(460.),
            );
            ui.label(RichText::new("Una por línea; acepta IPv4, IPv6 y redes CIDR. Una lista vacía avisa de todos los orígenes.").small().color(MUTED));
            if primary(ui, "Guardar preferencias").clicked() {
                match self.draft.policy() {
                    Ok(_) => {
                        let previous = self.state.settings.clone();
                        self.state.settings.allowed = self.draft.allowed.clone();
                        self.state.settings.alert_mode = self.draft.alert_mode.clone();
                        if self.save() {
                            self.error = None;
                            self.notice = Some(
                                "Preferencias guardadas; se aplican a los próximos eventos".into(),
                            );
                            info!(action = "policy_saved");
                        } else {
                            self.state.settings = previous;
                        }
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });
        ui.add_space(12.);
        card(ui, |ui| {
            ui.label(RichText::new("Notificaciones de macOS").strong());
            let status = self.notifications.status.load(Ordering::Relaxed);
            ui.label(match status {
                3 => "Autorizadas · los avisos usan el centro de notificaciones",
                2 => "Desactivadas · puedes habilitarlas en Ajustes del Sistema",
                4 => "macOS rechazó un aviso · revisa los permisos",
                _ => "Activa los avisos para verlos en pantalla",
            });
            ui.horizontal(|ui| {
                if status == 2 && ui.button("Abrir Ajustes de macOS").clicked() {
                    ui.ctx().open_url(egui::OpenUrl::same_tab(
                        "x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                    ));
                } else if status != 2 && ui.button("Activar notificaciones").clicked() {
                    self.notifications.request();
                }
                if ui
                    .add_enabled(status == 3, egui::Button::new("Enviar aviso de prueba"))
                    .clicked()
                {
                    self.notifications.send(
                        "remi-test",
                        "Remi · Aviso de prueba",
                        "Todo listo. Aquí aparecerán los accesos SSH de tu servidor.",
                    );
                }
            });
            ui.label(RichText::new("El modo Concentración de macOS puede silenciar los avisos. El historial permanece en Remi.").small().color(MUTED));
        });
        ui.add_space(12.);
        if ui.button("Explorar demostración").clicked() {
            self.disconnect();
            self.demo = true;
            self.error = None;
            self.page = Page::Activity;
            if self.demo_events.is_empty() {
                self.demo_event(true);
            }
        }
    }
}

impl eframe::App for Remi {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.init_tray(ctx);
        self.process();
        self.notifications();
        let clicked = self
            .notifications
            .clicked
            .lock()
            .ok()
            .and_then(|mut c| c.take());
        if let Some(id) = clicked {
            Self::raise(ctx);
            self.page = Page::Activity;
            self.filter.clear();
            self.only_alerts = false;
            match notification_target(&id, &self.state.history, &self.demo_events) {
                NotificationTarget::History => {
                    self.demo = false;
                    self.selected = Some(id);
                }
                NotificationTarget::Demo => {
                    self.disconnect();
                    self.demo = true;
                    self.selected = Some(id);
                }
                NotificationTarget::Test => {
                    self.notice = Some("Aviso de prueba abierto correctamente".into());
                    self.selected = None;
                }
                NotificationTarget::Missing => {
                    self.notice = Some("Este aviso ya no está en el historial conservado".into());
                    self.selected = None;
                }
            }
            self.scroll_to_selected = self.selected.is_some();
            info!(
                action = "notification_opened",
                demo = self.demo,
                found = self.selected.is_some()
            );
        }
        let events: Vec<_> = self.menu_events.lock().unwrap().drain(..).collect();
        for id in events {
            if let Some(tray) = &self.tray {
                if id == *tray.open.id() {
                    Self::raise(ctx);
                    info!(action = "tray_open");
                }
                if id == *tray.quit.id() {
                    info!(action = "tray_quit");
                    self.quit = true;
                    self.disconnect();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        if let Some(tray) = &self.tray {
            tray.status.set_text(format!(
                "Remi · {}",
                if self.demo {
                    "Demostración"
                } else {
                    &self.status
                }
            ));
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.quit && self.tray.is_some() {
            info!(action = "window_hidden");
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        self.sidebar(ctx);
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(PAPER).inner_margin(28))
            .show(ctx, |ui| {
                if let Some(error) = &self.error {
                    egui::Frame::new()
                        .fill(Color32::from_rgb(255, 236, 226))
                        .corner_radius(8)
                        .inner_margin(12)
                        .show(ui, |ui| {
                            ui.colored_label(AMBER, error);
                        });
                    ui.add_space(12.);
                }
                if let Some(notice) = &self.notice {
                    ui.label(RichText::new(notice).small().color(MUTED));
                    ui.add_space(8.);
                }
                if self.simulated_agent && !self.demo {
                    ui.colored_label(
                        AMBER,
                        "AGENTE DE PRUEBA · Los eventos recibidos son simulados",
                    );
                }
                if self.notifications.status.load(Ordering::Relaxed) != 3
                    && self.page != Page::Preferences
                {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(
                                "Activa las notificaciones para recibir avisos en pantalla.",
                            )
                            .small()
                            .color(MUTED),
                        );
                        if ui.small_button("Configurar avisos").clicked() {
                            self.page = Page::Preferences;
                        }
                    });
                    ui.add_space(12.);
                }
                egui::ScrollArea::vertical()
                    .id_salt("page")
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        Page::Activity => self.activity(ui, ctx),
                        Page::Connections => self.connections.show(
                            ui,
                            self.connected && !self.demo && !self.simulated_agent,
                            &self.state.settings.name,
                        ),
                        Page::Server => self.server(ui, ctx),
                        Page::Preferences => self.preferences(ui),
                    });
            });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.disconnect();
        self.save();
    }
}
fn card(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(225, 232, 224)))
        .corner_radius(12)
        .inner_margin(16)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui);
        });
}
fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(ACCENT))
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, placeholder: &str) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(placeholder)
            .desired_width(440.),
    );
}
fn icon_pixels(size: usize) -> Vec<u8> {
    let mut pixels = vec![0; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 / size as f32;
            let fy = y as f32 / size as f32;
            let inside = (fx - 0.5).powi(2) + (fy - 0.5).powi(2) < 0.20;
            let eye = ((fx - 0.35).powi(2) + (fy - 0.47).powi(2) < 0.005)
                || ((fx - 0.65).powi(2) + (fy - 0.47).powi(2) < 0.005);
            let color = if eye {
                [244, 247, 240, 255]
            } else if inside {
                [38, 102, 83, 255]
            } else {
                [0, 0, 0, 0]
            };
            pixels[(y * size + x) * 4..(y * size + x) * 4 + 4].copy_from_slice(&color);
        }
    }
    pixels
}
