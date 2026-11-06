use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use remi_core::{
    Frame, Login, PROTOCOL, StreamRequest, atomic_write, parse_journal, read_json, read_line,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{Mutex, Semaphore, watch},
};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(version, about = "Remi: SSH login observation for Debian")]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/remi/agent.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the collector and local read-only event socket.
    Run {
        /// Explicitly simulated input for reproducible integration tests.
        #[arg(long)]
        journal_fixture: Option<PathBuf>,
    },
    /// Stream events over an existing SSH channel; never opens a network port.
    Stream {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        instance: Option<String>,
    },
    /// Check configuration, journal permissions, persistence, and collector health.
    Doctor,
    /// Grant a local SSH account read access to Remi events (requires root).
    Authorize { user: String },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    state_dir: PathBuf,
    socket_path: PathBuf,
    retention_events: usize,
    hostname: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: "/var/lib/remi".into(),
            socket_path: "/run/remi/events.sock".into(),
            retention_events: 10_000,
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "debian".into())
                .trim()
                .to_string(),
        }
    }
}
impl Config {
    fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(
            &fs::read_to_string(path)
                .with_context(|| format!("No se pudo leer {}", path.display()))?,
        )?;
        if !(10..=100_000).contains(&config.retention_events) {
            bail!("retention_events debe estar entre 10 y 100000");
        }
        if !config.state_dir.is_absolute() || !config.socket_path.is_absolute() {
            bail!("Las rutas deben ser absolutas");
        }
        if config.hostname.is_empty()
            || config.hostname.len() > 128
            || config.hostname.chars().any(char::is_control)
        {
            bail!("hostname inválido");
        }
        Ok(config)
    }
    fn store_path(&self) -> PathBuf {
        self.state_dir.join("events.json")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredLogin {
    cursor: String,
    event: Login,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Store {
    schema: u32,
    instance: String,
    #[serde(default = "chrono::Utc::now")]
    observed_since: chrono::DateTime<chrono::Utc>,
    next_sequence: u64,
    entries: VecDeque<StoredLogin>,
}
impl Store {
    fn load(path: &Path) -> Result<Self> {
        let state: Self = read_json(path, 128 * 1024 * 1024)?.unwrap_or_else(|| Self {
            schema: 1,
            instance: format!(
                "{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ),
            observed_since: chrono::Utc::now(),
            next_sequence: 1,
            entries: VecDeque::new(),
        });
        if state.schema != 1
            || state.next_sequence == 0
            || state.instance.is_empty()
            || state.instance.len() > 128
            || !state
                .instance
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("Formato de historial no compatible");
        }
        let mut previous = 0;
        for entry in &state.entries {
            if entry.event.sequence <= previous || entry.event.sequence >= state.next_sequence {
                bail!("Historial inconsistente");
            }
            previous = entry.event.sequence;
        }
        if state
            .entries
            .back()
            .map(|entry| entry.event.sequence)
            .unwrap_or(0)
            != state.latest()
        {
            bail!("Historial inconsistente: falta el último evento");
        }
        Ok(state)
    }
    fn save(&self, path: &Path) -> Result<()> {
        atomic_write(path, &serde_json::to_vec(self)?)
    }
    fn append(
        &mut self,
        path: &Path,
        cursor: String,
        mut event: Login,
        retain: usize,
    ) -> Result<bool> {
        if self.entries.iter().any(|entry| entry.cursor == cursor) {
            return Ok(false);
        }
        let mut next = self.clone();
        event.sequence = next.next_sequence;
        next.next_sequence = next
            .next_sequence
            .checked_add(1)
            .context("Secuencia agotada")?;
        next.entries.push_back(StoredLogin { cursor, event });
        while next.entries.len() > retain {
            next.entries.pop_front();
        }
        next.save(path)?;
        *self = next;
        Ok(true)
    }
    fn latest(&self) -> u64 {
        self.next_sequence - 1
    }
    fn oldest(&self) -> u64 {
        self.entries.front().map(|e| e.event.sequence).unwrap_or(0)
    }
    fn journal_start(&self, fallback: bool) -> String {
        match self.entries.back() {
            Some(last) if !fallback => format!("--after-cursor={}", last.cursor),
            last => format!(
                "--since=@{}",
                last.map(|entry| entry.event.timestamp)
                    .unwrap_or(self.observed_since)
                    .timestamp()
            ),
        }
    }
}

struct State {
    store: Store,
    journal_ready: bool,
    journal_gap: bool,
    simulated: bool,
}
type Shared = Arc<Mutex<State>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    match cli.command {
        Action::Run { journal_fixture } => run(config, journal_fixture).await,
        Action::Stream { after, instance } => stream(config, after, instance).await,
        Action::Doctor => doctor(config).await,
        Action::Authorize { user } => {
            if user.is_empty()
                || user.starts_with('-')
                || user.len() > 64
                || !user
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.$".contains(c))
            {
                bail!("Usuario inválido");
            }
            let status = Command::new("/usr/sbin/usermod")
                .args(["-aG", "remi", "--", &user])
                .status()
                .await?;
            if !status.success() {
                bail!(
                    "No se pudo autorizar; ejecuta este comando con sudo para una cuenta existente"
                );
            }
            info!(
                action = "reader_authorized",
                "Acceso de lectura configurado"
            );
            println!(
                "Listo. Cierra y vuelve a abrir la conexión SSH de {user} para activar el grupo remi."
            );
            Ok(())
        }
    }
}

async fn preflight_journal() -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("journalctl")
            .env("LC_ALL", "C")
            .args(["--system", "--no-pager", "-n", "0"])
            .output(),
    )
    .await??;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        || stderr.contains("not seeing")
        || stderr.contains("Permission denied")
    {
        bail!("Sin acceso al journal del sistema; revisa el grupo systemd-journal y journald");
    }
    Ok(())
}

async fn run(config: Config, fixture: Option<PathBuf>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(&config.state_dir)?;
    fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o700))?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config.state_dir.join("agent.lock"))?;
    lock.try_lock_exclusive()
        .context("Otro agente está usando este directorio")?;
    let mut store = Store::load(&config.store_path())?;
    while store.entries.len() > config.retention_events {
        store.entries.pop_front();
    }
    store.save(&config.store_path())?;
    let socket_dir = config
        .socket_path
        .parent()
        .context("socket_path inválido")?;
    fs::create_dir_all(socket_dir)?;
    fs::set_permissions(socket_dir, fs::Permissions::from_mode(0o750))?;
    if config.socket_path.exists() {
        fs::remove_file(&config.socket_path)?;
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660))?;
    let shared = Arc::new(Mutex::new(State {
        store,
        journal_ready: false,
        journal_gap: false,
        simulated: fixture.is_some(),
    }));
    let (shutdown, receiver) = watch::channel(false);
    let mut collector = tokio::spawn(collect(
        config.clone(),
        shared.clone(),
        fixture,
        receiver.clone(),
    ));
    let limit = Arc::new(Semaphore::new(16));
    info!(
        action = "agent_started",
        version = env!("CARGO_PKG_VERSION"),
        retention = config.retention_events
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = loop {
        tokio::select! {
            result = &mut collector => { break result.context("Collector task failed")?; },
            _ = tokio::signal::ctrl_c() => { break Ok(()); },
            _ = terminate.recv() => { break Ok(()); },
            result = listener.accept() => {
                let (socket, _) = result?;
                match limit.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let state = shared.clone(); let config = config.clone(); let stop = receiver.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = serve(socket, config, state, stop).await { warn!(action = "reader_disconnected", error = %e); }
                        });
                    },
                    Err(_) => warn!(action = "reader_limit", "Se alcanzó el límite de lectores"),
                }
            }
        }
    };
    let _ = shutdown.send(true);
    if !collector.is_finished() {
        collector.abort();
        let _ = collector.await;
    }
    fs::remove_file(&config.socket_path).ok();
    info!(action = "agent_stopped");
    result
}

async fn collect(
    config: Config,
    state: Shared,
    fixture: Option<PathBuf>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    if let Some(path) = fixture {
        warn!(
            action = "simulated_collector",
            "Usando eventos de prueba, no el journal real"
        );
        let mut lines = BufReader::new(tokio::fs::File::open(path).await?);
        while let Some(line) = read_line(&mut lines).await? {
            ingest(&config, &state, &line).await?;
        }
        state.lock().await.journal_ready = true;
        let _ = stop.changed().await;
        return Ok(());
    }
    preflight_journal().await?;
    let mut fallback_since = false;
    let cursor = state
        .lock()
        .await
        .store
        .entries
        .back()
        .map(|entry| entry.cursor.clone());
    if let Some(cursor) = cursor
        && !journal_contains(&cursor).await?
    {
        state.lock().await.journal_gap = true;
        fallback_since = true;
        warn!(
            action = "journal_cursor_missing",
            "El journal ya no conserva el punto de reanudación; se recuperarán los registros disponibles por fecha"
        );
    }
    loop {
        let (journal_start, resumed) = {
            let guard = state.lock().await;
            (
                guard.store.journal_start(fallback_since),
                !guard.store.entries.is_empty(),
            )
        };
        let mut command = Command::new("journalctl");
        command.env("LC_ALL", "C");
        command.args([
            "--system",
            "--follow",
            "--no-tail",
            "--no-pager",
            "--quiet",
            "--output=json",
        ]);
        command.arg(journal_start);
        command
            .args([
                "_COMM=sshd",
                "_UID=0",
                "+",
                "_COMM=sshd-session",
                "_UID=0",
                "+",
                "_COMM=sshd-auth",
                "_UID=0",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().context("No se pudo iniciar journalctl")?;
        let stdout = child.stdout.take().context("journalctl sin stdout")?;
        let stderr = child.stderr.take().context("journalctl sin stderr")?;
        let error_task = tokio::spawn(async move {
            let mut input = BufReader::new(stderr);
            let mut cursor_error = false;
            while let Ok(Some(line)) = read_line(&mut input).await {
                if line.contains("cursor") {
                    cursor_error = true;
                }
                warn!(
                    action = "journal_diagnostic",
                    "journalctl emitió un diagnóstico; consulta remi-agent doctor"
                );
            }
            cursor_error
        });
        let mut input = BufReader::new(stdout);
        state.lock().await.journal_ready = true;
        info!(action = "journal_following", resumed);
        loop {
            tokio::select! {
                _ = stop.changed() => { child.kill().await.ok(); error_task.abort(); return Ok(()); },
                line = read_journal_line(&mut input) => match line? {
                    Some(line) => ingest(&config, &state, &line).await?,
                    None => break,
                }
            }
        }
        state.lock().await.journal_ready = false;
        let status = child.wait().await?;
        let cursor_error = error_task.await.unwrap_or(false);
        if !fallback_since && resumed && cursor_error {
            state.lock().await.journal_gap = true;
            fallback_since = true;
            warn!(
                action = "journal_cursor_unavailable",
                "El journal rotó: se recuperará desde la última marca de tiempo disponible"
            );
            continue;
        }
        error!(action = "journal_stopped", code = ?status.code());
        bail!("journalctl terminó; systemd reiniciará el agente");
    }
}

/// Journal records are independent: discard an oversized record without wedging the collector.
async fn read_journal_line<R: AsyncBufRead + Unpin>(input: &mut R) -> Result<Option<String>> {
    const LIMIT: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    let mut discarded = false;
    loop {
        let available = input.fill_buf().await?;
        if available.is_empty() {
            if bytes.is_empty() || discarded {
                return Ok(None);
            }
            bail!("Journal interrumpido a mitad de un registro");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if !discarded && bytes.len() + count <= LIMIT {
            bytes.extend_from_slice(&available[..count]);
        } else {
            discarded = true;
            bytes.clear();
        }
        input.consume(count);
        if newline.is_some() {
            if discarded {
                warn!(action = "journal_record_oversized", limit = LIMIT);
                discarded = false;
            } else {
                return Ok(Some(String::from_utf8(bytes)?));
            }
        }
    }
}

// journalctl may seek to a nearby record when an old cursor was vacuumed, without an error.
async fn journal_contains(cursor: &str) -> Result<bool> {
    let mut child = Command::new("journalctl")
        .env("LC_ALL", "C")
        .args(["--system", "--no-pager", "--no-tail", "--output=json"])
        .arg(format!("--cursor={cursor}"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let output = child.stdout.take().context("journalctl sin stdout")?;
    let line = tokio::time::timeout(
        Duration::from_secs(5),
        read_journal_line(&mut BufReader::new(output)),
    )
    .await;
    child.kill().await.ok();
    child.wait().await.ok();
    let line = line.context("No se pudo verificar el cursor del journal")??;
    Ok(line
        .and_then(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
        .and_then(|value| {
            value
                .get("__CURSOR")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .as_deref()
        == Some(cursor))
}

async fn ingest(config: &Config, state: &Shared, line: &str) -> Result<()> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            warn!(action = "journal_invalid_json");
            return Ok(());
        }
    };
    if let Some((cursor, event)) = parse_journal(&value) {
        let mut guard = state.lock().await;
        if guard
            .store
            .append(&config.store_path(), cursor, event, config.retention_events)?
        {
            info!(action = "login_recorded", sequence = guard.store.latest());
        }
    }
    Ok(())
}

async fn send(socket: &mut tokio::net::unix::OwnedWriteHalf, frame: Frame) -> Result<()> {
    let mut data = serde_json::to_vec(&frame)?;
    data.push(b'\n');
    tokio::time::timeout(Duration::from_secs(10), socket.write_all(&data)).await??;
    Ok(())
}

async fn serve(
    socket: UnixStream,
    config: Config,
    state: Shared,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let (read, mut write) = socket.into_split();
    let mut read = BufReader::new(read);
    let line = tokio::time::timeout(Duration::from_secs(5), read_line(&mut read))
        .await??
        .context("Solicitud vacía")?;
    let request: StreamRequest = serde_json::from_str(&line)?;
    if request.protocol != PROTOCOL {
        send(
            &mut write,
            Frame::Error {
                message: "Versión de protocolo no compatible".into(),
            },
        )
        .await?;
        return Ok(());
    }
    let snapshot = state.lock().await;
    let resync = request.instance.as_deref() != Some(&snapshot.store.instance)
        || request.after > snapshot.store.latest();
    let mut cursor = if resync { 0 } else { request.after };
    let gap =
        snapshot.journal_gap || (!resync && cursor.saturating_add(1) < snapshot.store.oldest());
    if cursor.saturating_add(1) < snapshot.store.oldest() {
        cursor = snapshot.store.oldest() - 1;
    }
    let hello = Frame::Hello {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION").into(),
        instance: snapshot.store.instance.clone(),
        hostname: config.hostname.clone(),
        oldest: snapshot.store.oldest(),
        latest: snapshot.store.latest(),
        journal_ready: snapshot.journal_ready,
        resync,
        gap,
        simulated: snapshot.simulated,
    };
    drop(snapshot);
    send(&mut write, hello).await?;
    info!(action = "reader_connected", resync, gap);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut ticks = 0;
    loop {
        tokio::select! {
            _ = stop.changed() => return Ok(()),
            _ = interval.tick() => {
                let snapshot = state.lock().await;
                if cursor > 0 && cursor.saturating_add(1) < snapshot.store.oldest() {
                    drop(snapshot);
                    send(&mut write, Frame::Error { message: "El historial avanzó fuera de la retención durante la conexión; vuelve a conectar".into() }).await?;
                    return Ok(());
                }
                let events: Vec<_> = snapshot.store.entries.iter().filter(|e| e.event.sequence > cursor).map(|e| e.event.clone()).collect();
                let heartbeat = Frame::Heartbeat { latest: snapshot.store.latest(), journal_ready: snapshot.journal_ready };
                drop(snapshot);
                for event in events { cursor = event.sequence; send(&mut write, Frame::Login { event }).await?; }
                if ticks % 5 == 0 { send(&mut write, heartbeat).await?; }
                ticks += 1;
            }
        }
    }
}

async fn stream(config: Config, after: u64, instance: Option<String>) -> Result<()> {
    if instance.as_ref().is_some_and(|s| s.len() > 128) {
        bail!("Identificador de agente inválido");
    }
    let mut socket = UnixStream::connect(&config.socket_path).await.context(
        "No se pudo abrir Remi; verifica el servicio y que tu cuenta SSH pertenezca al grupo remi",
    )?;
    let mut request = serde_json::to_vec(&StreamRequest {
        protocol: PROTOCOL,
        after,
        instance,
    })?;
    request.push(b'\n');
    socket.write_all(&request).await?;
    tokio::io::copy(&mut socket, &mut tokio::io::stdout()).await?;
    Ok(())
}

async fn doctor(config: Config) -> Result<()> {
    println!("Remi {} · protocol {}", env!("CARGO_PKG_VERSION"), PROTOCOL);
    preflight_journal().await?;
    println!("OK: acceso al journal del sistema");
    let mut socket = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match UnixStream::connect(&config.socket_path).await {
                Ok(socket) => return Ok::<_, std::io::Error>(socket),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .context("El servicio no abrió su socket; revisa systemctl status remi-agent")??;
    let mut request = serde_json::to_vec(&StreamRequest {
        protocol: PROTOCOL,
        after: 0,
        instance: None,
    })?;
    request.push(b'\n');
    socket.write_all(&request).await?;
    let mut input = BufReader::new(socket);
    let line = tokio::time::timeout(Duration::from_secs(5), read_line(&mut input))
        .await??
        .context("Agente sin respuesta")?;
    match serde_json::from_str::<Frame>(&line)? {
        Frame::Hello {
            latest,
            journal_ready,
            gap,
            simulated,
            ..
        } => {
            println!("OK: servicio accesible · último evento {latest}");
            if gap {
                bail!("Se detectó una interrupción en el journal; consulta los logs del agente");
            }
            if simulated {
                bail!("El agente está usando datos simulados");
            }
            if !journal_ready {
                info!(action = "doctor_waiting_for_collector");
                tokio::time::timeout(Duration::from_secs(6), async {
                    while let Some(line) = read_line(&mut input).await? {
                        if matches!(
                            serde_json::from_str::<Frame>(&line)?,
                            Frame::Heartbeat {
                                journal_ready: true,
                                ..
                            }
                        ) {
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                    bail!("El servicio cerró la conexión durante el arranque")
                })
                .await
                .context("El colector no está leyendo el journal")??;
            }
            println!("OK: colector activo · historial durable");
        }
        _ => bail!("Respuesta inesperada"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> Login {
        Login {
            sequence: 0,
            timestamp: chrono::Utc::now(),
            user: "deploy".into(),
            source_ip: "192.0.2.4".parse().unwrap(),
            source_port: 40000,
            method: "publickey".into(),
        }
    }
    #[test]
    fn store_survives_restart_deduplicates_and_enforces_retention() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events.json");
        let mut store = Store::load(&file).unwrap();
        for i in 0..15 {
            assert!(
                store
                    .append(&file, format!("cursor-{i}"), event(), 10)
                    .unwrap()
            );
        }
        let mut restored = Store::load(&file).unwrap();
        assert_eq!(restored.instance, store.instance);
        assert_eq!(restored.oldest(), 6);
        assert_eq!(restored.latest(), 15);
        assert!(
            !restored
                .append(&file, "cursor-14".into(), event(), 10)
                .unwrap()
        );
        assert_eq!(restored.latest(), 15);
    }
    #[test]
    fn failed_persistence_does_not_advance_event_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events.json");
        let mut store = Store::load(&file).unwrap();
        assert!(store.append(dir.path(), "c".into(), event(), 10).is_err());
        assert_eq!(store.latest(), 0);
    }
    #[test]
    fn restart_before_first_login_keeps_original_observation_start() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events.json");
        let mut store = Store::load(&file).unwrap();
        store.observed_since = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        store.save(&file).unwrap();
        let restored = Store::load(&file).unwrap();
        assert_eq!(restored.journal_start(false), "--since=@1700000000");
        assert_eq!(restored.journal_start(true), "--since=@1700000000");
    }
    #[tokio::test]
    async fn oversized_journal_record_does_not_hide_the_next_login() {
        let mut bytes = vec![b'x'; 1024 * 1024 + 1];
        bytes.extend_from_slice(b"\n{\"ok\":true}\n");
        let line = read_journal_line(&mut BufReader::with_capacity(2048, bytes.as_slice()))
            .await
            .unwrap();
        assert_eq!(line.as_deref(), Some("{\"ok\":true}\n"));
    }
    #[test]
    fn damaged_store_is_rejected_and_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.json");
        let mut store = Store::load(&path).unwrap();
        store.next_sequence = 9;
        store.save(&path).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(Store::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        store.next_sequence = 1;
        store.instance.clear();
        store.save(&path).unwrap();
        assert!(Store::load(&path).is_err());
    }
    #[test]
    fn configuration_rejects_unknown_fields_relative_paths_and_bad_retention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        for content in [
            "retention_events = 9",
            "retention_events = 100001",
            "state_dir = 'relative'",
            "socket_path = 'relative'",
            "unknown = 3",
            "hostname = ''",
        ] {
            fs::write(&path, content).unwrap();
            assert!(Config::load(&path).is_err(), "{content}");
        }
        fs::write(&path, "retention_events = 10\nhostname = 'test'").unwrap();
        assert_eq!(Config::load(&path).unwrap().retention_events, 10);
    }
    #[tokio::test]
    async fn stream_recovers_backlog_and_marks_retention_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events.json");
        let mut store = Store::load(&file).unwrap();
        for i in 0..20 {
            store.append(&file, format!("c{i}"), event(), 10).unwrap();
        }
        let instance = store.instance.clone();
        let shared = Arc::new(Mutex::new(State {
            store,
            journal_ready: true,
            journal_gap: false,
            simulated: false,
        }));
        let (server, mut client) = UnixStream::pair().unwrap();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve(server, Config::default(), shared, receiver));
        client
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&StreamRequest {
                        protocol: PROTOCOL,
                        after: 5,
                        instance: Some(instance)
                    })
                    .unwrap()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut input = BufReader::new(client);
        assert!(matches!(
            serde_json::from_str::<Frame>(&read_line(&mut input).await.unwrap().unwrap()).unwrap(),
            Frame::Hello {
                gap: true,
                resync: false,
                oldest: 11,
                ..
            }
        ));
        for seq in 11..=20 {
            let frame: Frame =
                serde_json::from_str(&read_line(&mut input).await.unwrap().unwrap()).unwrap();
            assert!(matches!(frame, Frame::Login { event } if event.sequence == seq));
        }
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
