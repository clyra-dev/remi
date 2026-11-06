//! On-demand control over SSH; the journal collector remains unprivileged.
use crate::sockets;
use anyhow::{Context, Result, bail};
use remi_core::{connections::*, read_line_bounded};
use serde::{Deserialize, Serialize};
use std::{ffi::CString, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    process::Command,
};
use tracing::{info, warn};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperRequest {
    request: ControlRequest,
    observer: Option<Observer>,
}

async fn write_reply(reply: &ControlReply) -> Result<()> {
    let mut bytes = serde_json::to_vec(reply)?;
    if bytes.len() >= CONTROL_FRAME_BYTES {
        bail!("La respuesta de conexiones excedió el límite");
    }
    bytes.push(b'\n');
    let mut output = tokio::io::stdout();
    output.write_all(&bytes).await?;
    output.flush().await?;
    Ok(())
}

pub async fn serve() -> Result<()> {
    let observer = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|value| Observer::from_ssh_connection(&value).ok());
    info!(
        action = "connection_control_started",
        observer_identified = observer.is_some()
    );
    write_reply(&ControlReply {
        id: 0,
        result: ControlResult::Ready {
            protocol: CONTROL_PROTOCOL,
        },
    })
    .await?;
    let mut input = BufReader::new(tokio::io::stdin());
    while let Some(line) = read_line_bounded(&mut input, CONTROL_REQUEST_BYTES).await? {
        let request: ControlRequest =
            serde_json::from_str(&line).context("Solicitud de conexiones inválida")?;
        if request.id == 0 {
            bail!("Identificador de solicitud inválido");
        }
        let id = request.id;
        let helper = HelperRequest {
            request,
            observer: observer.clone(),
        };
        let result = if unsafe { libc::geteuid() } == 0 {
            let reply = tokio::task::spawn_blocking(move || execute(helper)).await?;
            Ok(reply)
        } else {
            elevated(&helper).await
        };
        let reply = match result {
            Ok(reply) => reply,
            Err(error) => {
                warn!(action = "connection_control_privilege_unavailable", request_id = id, error = %error);
                // Listing is available without sudo, with explicitly limited process visibility.
                let result = if matches!(helper_action(&line)?, ControlAction::List) {
                    let observer = observer.clone();
                    match tokio::task::spawn_blocking(move || {
                        sockets::snapshot(observer.as_ref(), false)
                    })
                    .await?
                    {
                        Ok(snapshot) => ControlResult::Snapshot { snapshot },
                        Err(error) => ControlResult::Error {
                            message: format!("{error:#}"),
                        },
                    }
                } else {
                    ControlResult::Error { message: "No se pudo autorizar el cierre: se requiere sudo sin contraseña para /usr/bin/remi-agent socket-helper".into() }
                };
                ControlReply { id, result }
            }
        };
        write_reply(&reply).await?;
    }
    info!(action = "connection_control_stopped");
    Ok(())
}

fn helper_action(line: &str) -> Result<ControlAction> {
    Ok(serde_json::from_str::<ControlRequest>(line)?.action)
}

async fn elevated(request: &HelperRequest) -> Result<ControlReply> {
    let bytes = serde_json::to_vec(request)?;
    let mut child = Command::new("/usr/bin/sudo")
        .args(["-n", "--", "/usr/bin/remi-agent", "socket-helper"])
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let operation = async {
        let mut stdin = child.stdin.take().context("Sin entrada al ayudante")?;
        stdin.write_all(&bytes).await?;
        stdin.write_all(b"\n").await?;
        drop(stdin);
        let mut stdout = BufReader::new(child.stdout.take().context("Sin salida del ayudante")?);
        let line = read_line_bounded(&mut stdout, CONTROL_FRAME_BYTES)
            .await?
            .context("El ayudante no respondió; verifica sudo")?;
        let status = child.wait().await?;
        if !status.success() {
            bail!("El ayudante terminó sin autorización");
        }
        let reply: ControlReply = serde_json::from_str(&line)?;
        if reply.id != request.request.id {
            bail!("El ayudante respondió a otra solicitud");
        }
        Ok(reply)
    };
    tokio::time::timeout(Duration::from_secs(12), operation)
        .await
        .context("El ayudante agotó su tiempo")?
}

pub async fn helper() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("socket-helper requiere sudo");
    }
    let mut input = BufReader::new(tokio::io::stdin());
    let line = tokio::time::timeout(
        Duration::from_secs(3),
        read_line_bounded(&mut input, CONTROL_REQUEST_BYTES),
    )
    .await
    .context("Solicitud al ayudante agotada")??
    .context("Falta la solicitud")?;
    let request: HelperRequest = serde_json::from_str(&line)?;
    if request.request.id == 0 {
        bail!("Identificador de solicitud inválido");
    }
    let reply = tokio::task::spawn_blocking(move || execute(request)).await?;
    write_reply(&reply).await
}

fn execute(helper: HelperRequest) -> ControlReply {
    let id = helper.request.id;
    let result = match helper.request.action {
        ControlAction::List => sockets::snapshot(helper.observer.as_ref(), true).map(|snapshot| {
            info!(
                action = "connections_snapshot",
                request_id = id,
                count = snapshot.total,
                can_close = snapshot.can_close
            );
            ControlResult::Snapshot { snapshot }
        }),
        ControlAction::Close { key } => {
            audit(id, &key, "requested", None);
            let closed = helper
                .observer
                .as_ref()
                .context("No se identificó la sesión SSH de Remi; cierre deshabilitado")
                .and_then(|observer| sockets::close(&key, observer));
            match &closed {
                Ok(()) => audit(id, &key, "closed", None),
                Err(error) => audit(id, &key, "rejected", Some(&format!("{error:#}"))),
            }
            closed.map(|()| ControlResult::Closed { key })
        }
    };
    ControlReply {
        id,
        result: result.unwrap_or_else(|error| {
            warn!(action = "connection_control_failed", request_id = id, error = %error);
            ControlResult::Error {
                message: format!("{error:#}").chars().take(1000).collect(),
            }
        }),
    }
}

fn audit(id: u64, key: &SocketKey, outcome: &str, error: Option<&str>) {
    let actor = std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into());
    let event = serde_json::json!({
        "action": "tcp_connection_close", "request_id": id, "actor": actor,
        "local": key.local, "remote": key.remote, "cookie": key.cookie,
        "inode": key.inode, "outcome": outcome, "error": error,
    })
    .to_string();
    info!(action = "tcp_connection_close", request_id = id, outcome, local = %key.local, remote = %key.remote);
    if let Ok(message) = CString::new(event) {
        // Persist the privileged action in the system journal, independent of the desktop.
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | libc::LOG_NOTICE,
                c"%s".as_ptr(),
                message.as_ptr(),
            );
        }
    }
}
