#[cfg(target_os = "macos")]
mod app;
#[cfg(target_os = "macos")]
mod host_keys;
#[cfg(target_os = "macos")]
mod model;
#[cfg(target_os = "macos")]
mod notifications;
#[cfg(target_os = "macos")]
mod transport;

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use eframe::egui;
    let directory = model::data_dir();
    std::fs::create_dir_all(&directory)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let log_dir = directory.join("logs");
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("remi")
        .max_log_files(7)
        .build(log_dir)?;
    let (writer, _log_guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .with_env_filter("remi=info")
        .init();
    tracing::info!(
        action = "desktop_started",
        version = env!("CARGO_PKG_VERSION")
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let _entered = runtime.enter();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Remi")
            .with_inner_size([940., 680.])
            .with_min_inner_size([780., 560.]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Remi",
        options,
        Box::new(move |cc| Ok(Box::new(app::Remi::new(cc, directory)))),
    )
    .map_err(|e| anyhow::anyhow!("No se pudo abrir Remi: {e}"))?;
    tracing::info!(action = "desktop_stopped");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("La app de escritorio de Remi requiere macOS; usa remi-agent en Debian.");
}
