use crate::{
    host_keys,
    model::{Settings, expand_path},
};
use anyhow::{Context, Result, bail};
use remi_core::{Frame, PROTOCOL, connections::*, read_line, read_line_bounded};
use russh::{
    ChannelMsg, client,
    keys::{
        PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        agent::{AgentIdentity, client::AgentClient},
    },
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio::io::BufReader;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct Cursor {
    pub instance: Option<String>,
    pub sequence: u64,
}
pub enum Update {
    Connecting,
    Frame(Frame),
    Disconnected(String),
    ControlReady(tokio::sync::mpsc::Sender<ControlRequest>),
    ControlReply(ControlReply),
    ControlUnavailable(String),
    HostKey {
        host: String,
        port: u16,
        fingerprint: String,
        key: String,
    },
}
pub struct Envelope {
    pub generation: u64,
    pub update: Update,
}
#[derive(Clone)]
pub struct Updates {
    pub tx: mpsc::Sender<Envelope>,
    pub context: eframe::egui::Context,
    pub generation: u64,
}
impl Updates {
    pub fn send(&self, update: Update) {
        let _ = self.tx.send(Envelope {
            generation: self.generation,
            update,
        });
        self.context.request_repaint();
    }
}
struct AbortTask(tokio::task::JoinHandle<Result<()>>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Handler {
    settings: Settings,
    updates: Updates,
    hard_failure: Arc<AtomicBool>,
}

fn permanent<T>(result: Result<T>, updates: &Updates, hard_failure: &AtomicBool) -> Result<T> {
    if let Err(error) = &result {
        hard_failure.store(true, Ordering::Relaxed);
        warn!(action = "ssh_configuration_rejected", error = %error);
        updates.send(Update::Disconnected(error.to_string()));
    }
    result
}
impl client::Handler for Handler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if server_key.certificate().is_some() {
            self.hard_failure.store(true, Ordering::Relaxed);
            self.updates.send(Update::Disconnected("Este MVP requiere una llave de host SSH; los certificados de host aún no están soportados".into()));
            return Ok(false);
        }
        let key = server_key.public_key();
        let host = &self.settings.host;
        let port = self.settings.port.parse().unwrap_or(22);
        let known_hosts = expand_path(&self.settings.known_hosts);
        match host_keys::read(&known_hosts)
            .and_then(|contents| host_keys::verify(&contents, host, port, &key))
        {
            Ok(host_keys::Trust::Verified) => {
                info!(action = "host_key_verified");
                Ok(true)
            }
            Ok(host_keys::Trust::Unknown) => {
                self.hard_failure.store(true, Ordering::Relaxed);
                self.updates.send(Update::HostKey {
                    host: host.clone(),
                    port,
                    fingerprint: key
                        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                        .to_string(),
                    key: key.to_openssh().unwrap_or_default(),
                });
                Ok(false)
            }
            Err(error) => {
                self.hard_failure.store(true, Ordering::Relaxed);
                warn!(action = "host_key_rejected");
                self.updates.send(Update::Disconnected(error.to_string()));
                Ok(false)
            }
        }
    }
}

pub fn start(
    settings: Settings,
    passphrase: String,
    cursor: Arc<Mutex<Cursor>>,
    updates: Updates,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let hard_failure = Arc::new(AtomicBool::new(false));
        let mut delay = 1;
        loop {
            updates.send(Update::Connecting);
            info!(action = "ssh_connecting");
            let outcome = session(
                &settings,
                &passphrase,
                &cursor,
                updates.clone(),
                hard_failure.clone(),
            )
            .await;
            if hard_failure.load(Ordering::Relaxed) {
                return;
            }
            let message = outcome
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "El agente cerró la conexión".into());
            warn!(action = "ssh_disconnected", retry_seconds = delay, error = %message);
            updates.send(Update::Disconnected(format!(
                "{message} · reintento en {delay} s"
            )));
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(30);
        }
    })
}

async fn session(
    settings: &Settings,
    passphrase: &str,
    cursor: &Arc<Mutex<Cursor>>,
    updates: Updates,
    hard_failure: Arc<AtomicBool>,
) -> Result<()> {
    let handler = Handler {
        settings: settings.clone(),
        updates: updates.clone(),
        hard_failure: hard_failure.clone(),
    };
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(25)),
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 2,
        ..Default::default()
    };
    let port = settings.port.parse::<u16>()?;
    let mut ssh = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(Arc::new(config), (settings.host.as_str(), port), handler),
    )
    .await
    .context("Tiempo de conexión agotado")??;
    let auth = async {
        let hash = ssh.best_supported_rsa_hash().await?.flatten();
        if settings.use_agent {
            let mut agent = permanent(AgentClient::connect_env().await.context(
                "No se encontró SSH_AUTH_SOCK; agrega una llave a tu agente SSH o usa un archivo",
            ), &updates, &hard_failure)?;
            let identities = permanent(
                agent
                    .request_identities()
                    .await
                    .context("No se pudieron leer las llaves del agente SSH"),
                &updates,
                &hard_failure,
            )?;
            info!(
                action = "ssh_agent_identities",
                available = identities.len()
            );
            if identities.is_empty() {
                return permanent(
                    Err(anyhow::anyhow!(
                        "El agente SSH no tiene llaves cargadas; usa ssh-add o selecciona un archivo de llave"
                    )),
                    &updates,
                    &hard_failure,
                );
            }
            for identity in identities.into_iter().take(5) {
                if let AgentIdentity::PublicKey { key, .. } = identity
                    && ssh
                        .authenticate_publickey_with(&settings.user, key, hash, &mut agent)
                        .await?
                        .success()
                {
                    return Ok::<_, anyhow::Error>(());
                }
            }
            return permanent(
                Err(anyhow::anyhow!(
                    "El servidor no aceptó las llaves del agente SSH; revisa el usuario y las llaves cargadas"
                )),
                &updates,
                &hard_failure,
            );
        } else {
            let key = permanent(
                russh::keys::load_secret_key(
                    expand_path(&settings.key_path),
                    if passphrase.is_empty() {
                        None
                    } else {
                        Some(passphrase)
                    },
                )
                .context(
                    "No se pudo abrir la llave; verifica la ruta, el formato y la frase de acceso",
                ),
                &updates,
                &hard_failure,
            )?;
            if !ssh
                .authenticate_publickey(
                    &settings.user,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await?
                .success()
            {
                return permanent(
                    Err(anyhow::anyhow!(
                        "El servidor no aceptó la llave SSH; revisa el usuario y la llave seleccionada"
                    )),
                    &updates,
                    &hard_failure,
                );
            }
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(25), auth)
        .await
        .context("Autenticación SSH agotó el tiempo")??;
    info!(action = "ssh_authenticated");
    // Separate channels, one SSH transport: no extra login and the same protected socket.
    let control_task = match ssh.channel_open_session().await {
        Ok(channel) => {
            let updates = updates.clone();
            Some(AbortTask(tokio::spawn(async move {
                let result = connection_control(channel, &updates).await;
                if let Err(error) = &result {
                    warn!(action = "connection_control_unavailable", error = %error);
                    updates.send(Update::ControlUnavailable(format!("{error:#}")));
                }
                result
            })))
        }
        Err(error) => {
            updates.send(Update::ControlUnavailable(format!(
                "No se pudo abrir el canal de conexiones: {error}"
            )));
            None
        }
    };
    let saved = cursor.lock().unwrap().clone();
    let mut command = format!("/usr/bin/remi-agent stream --after {}", saved.sequence);
    if let Some(instance) = &saved.instance {
        if instance.is_empty()
            || instance.len() > 128
            || !instance
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("Identificador de agente inválido");
        }
        command.push_str(" --instance ");
        command.push_str(instance);
    }
    let mut channel = ssh.channel_open_session().await?;
    channel.exec(true, command).await?;
    // Keep stdout and stderr separate: a diagnostic cannot become a protocol event.
    let (writer, reader) = tokio::io::duplex(128 * 1024);
    let pump = AbortTask(tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut writer = writer;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => writer.write_all(&data).await?,
                ChannelMsg::ExtendedData { .. } => debug!(
                    action = "remote_agent_diagnostic",
                    "El agente remoto emitió un diagnóstico"
                ),
                ChannelMsg::ExitStatus { exit_status } if exit_status != 0 => bail!(
                    "remi-agent terminó con código {exit_status}; verifica instalación y grupo remi"
                ),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => (),
            }
        }
        Ok::<_, anyhow::Error>(())
    }));
    let mut input = BufReader::new(reader);
    let result = async {
        let mut hello = false;
        loop {
            let line = tokio::time::timeout(Duration::from_secs(20), read_line(&mut input)).await.context("El agente dejó de enviar señales de vida")??
                .context("No hay flujo de Remi; revisa que el agente esté instalado, activo y que el usuario SSH pertenezca al grupo remi")?;
            let frame: Frame = serde_json::from_str(&line).context("Respuesta incompatible del agente")?;
            match &frame {
                Frame::Hello { protocol, instance, .. } => {
                    if hello || *protocol != PROTOCOL || instance.is_empty() || instance.len() > 128 || !instance.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') { bail!("Protocolo o identidad del agente no compatible"); }
                    hello = true;
                },
                Frame::Error { message } => bail!("Agente: {}", message.chars().take(300).collect::<String>()),
                _ if !hello => bail!("El agente no inició el protocolo correctamente"),
                _ => (),
            }
            updates.send(Update::Frame(frame));
        }
    }.await;
    pump.0.abort();
    drop(control_task);
    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "Remi disconnected", "en")
        .await;
    result
}

async fn connection_control(channel: russh::Channel<client::Msg>, updates: &Updates) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    channel
        .exec(true, "/usr/bin/remi-agent connections")
        .await?;
    let (reader, mut writer) = tokio::io::split(channel.into_stream());
    let mut input = BufReader::new(reader);
    let hello = tokio::time::timeout(
        Duration::from_secs(8),
        read_line_bounded(&mut input, CONTROL_FRAME_BYTES),
    )
    .await
    .context("El canal de conexiones no respondió")??
    .context("Actualiza remi-agent a 0.2.0 para gestionar conexiones")?;
    let hello: ControlReply =
        serde_json::from_str(&hello).context("Respuesta de control incompatible")?;
    if hello.id != 0
        || !matches!(
            hello.result,
            ControlResult::Ready {
                protocol: CONTROL_PROTOCOL
            }
        )
    {
        bail!("Protocolo de conexiones incompatible; actualiza el agente");
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ControlRequest>(2);
    updates.send(Update::ControlReady(tx));
    info!(action = "connection_control_ready");
    while let Some(request) = rx.recv().await {
        let close = matches!(request.action, ControlAction::Close { .. });
        info!(
            action = "connection_control_request",
            request_id = request.id,
            close
        );
        let mut bytes = serde_json::to_vec(&request)?;
        if bytes.len() >= CONTROL_REQUEST_BYTES {
            bail!("Solicitud de conexión demasiado grande");
        }
        bytes.push(b'\n');
        let response = tokio::time::timeout(Duration::from_secs(15), async {
            writer.write_all(&bytes).await?;
            writer.flush().await?;
            read_line_bounded(&mut input, CONTROL_FRAME_BYTES)
                .await?
                .context("Se cerró el canal de control")
        })
        .await
        .context(
            "Sin confirmación del servidor; comprueba la conexión antes de repetir un cierre",
        )??;
        let reply: ControlReply = serde_json::from_str(&response)?;
        if reply.id != request.id || matches!(reply.result, ControlResult::Ready { .. }) {
            bail!("Respuesta de control fuera de secuencia");
        }
        updates.send(Update::ControlReply(reply));
    }
    Ok(())
}

pub fn trust_host(settings: &Settings, host: &str, port: u16, openssh_key: &str) -> Result<()> {
    // The form stays editable while the fingerprint card is shown.
    settings.validate()?;
    if host != settings.host || port.to_string() != settings.port {
        bail!("La configuración cambió; vuelve a verificar el servidor");
    }
    let key = russh::keys::ssh_key::PublicKey::from_openssh(openssh_key)?;
    host_keys::remember(&expand_path(&settings.known_hosts), host, port, &key)?;
    info!(action = "host_key_approved");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBBFy4/1MtRbkgvfdaPX8Z5pYHaxGEhdtB7stG3UAvi";
    #[test]
    fn trust_validates_settings_before_writing_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = Settings {
            host: "127.0.0.1".into(),
            port: "2222".into(),
            user: "reader".into(),
            known_hosts: "remi-trust-test/known_hosts".into(),
            ..Default::default()
        };
        let error = trust_host(&settings, "127.0.0.1", 2222, KEY)
            .unwrap_err()
            .to_string();
        assert!(error.contains("debe empezar"), "{error}");
        assert!(!std::path::Path::new("remi-trust-test").exists());
        let path = dir.path().join("known_hosts");
        settings.known_hosts = path.to_string_lossy().into();
        trust_host(&settings, "127.0.0.1", 2222, KEY).unwrap();
        assert!(
            std::fs::read_to_string(path)
                .unwrap()
                .starts_with("[127.0.0.1]:2222 ")
        );
    }
    #[tokio::test]
    #[ignore = "Requires the disposable Remi SSH acceptance server and explicit REMI_QA_* variables"]
    async fn local_ssh_authentication_and_protocol() {
        let key = std::env::var("REMI_QA_KEY").ok();
        let settings = Settings {
            host: "127.0.0.1".into(),
            port: std::env::var("REMI_QA_PORT").unwrap(),
            user: "remitest".into(),
            known_hosts: std::env::var("REMI_QA_KNOWN_HOSTS").unwrap(),
            use_agent: key.is_none(),
            key_path: key.unwrap_or_default(),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        let context = eframe::egui::Context::default();
        let task = start(
            settings,
            std::env::var("REMI_QA_PASSPHRASE").unwrap_or_default(),
            Arc::new(Mutex::new(Cursor {
                instance: None,
                sequence: 0,
            })),
            Updates {
                tx,
                context,
                generation: 1,
            },
        );
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                while let Ok(envelope) = rx.try_recv() {
                    match envelope.update {
                        Update::Frame(Frame::Hello {
                            protocol: PROTOCOL,
                            simulated: false,
                            ..
                        }) => return Ok(()),
                        Update::Disconnected(error) => return Err(error),
                        Update::HostKey { .. } => return Err("Untrusted test host".into()),
                        _ => (),
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if let Ok(expected) = std::env::var("REMI_QA_EXPECT_ERROR") {
            assert!(
                matches!(&result, Ok(Err(error)) if error.contains(&expected)),
                "{result:?}"
            );
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("Permanent failures must stop retrying")
                .unwrap();
        } else {
            task.abort();
            assert!(matches!(result, Ok(Ok(()))), "{result:?}");
        }
    }
}
