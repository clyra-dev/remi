//! Curated behavioral mutations, not a claim of exhaustive mutation coverage.
//! Source edits happen only in an ignored copy; tests and expectations are never mutated.
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Mutation {
    id: &'static str,
    description: &'static str,
    file: &'static str,
    before: &'static str,
    after: &'static str,
    package: &'static str,
    target: &'static [&'static str],
    linux: bool,
    control: bool,
}

macro_rules! case {
    ($id:literal, $description:literal, $file:literal, $before:literal, $after:literal, $package:literal, $target:expr, $linux:literal, $control:literal) => {
        Mutation {
            id: $id,
            description: $description,
            file: $file,
            before: $before,
            after: $after,
            package: $package,
            target: $target,
            linux: $linux,
            control: $control,
        }
    };
}

const CORE: &[&str] = &["--lib"];
const DESKTOP: &[&str] = &["--bin", "remi"];
const AGENT: &[&str] = &["--bin", "remi-agent"];
const SOCKETS: &[&str] = &["--test", "connections"];

const CASES: &[Mutation] = &[
    case!(
        "C01",
        "Invert allowlist alerts",
        "crates/remi-core/src/lib.rs",
        "self.mode == AlertMode::All || !self.expected(address)",
        "self.mode == AlertMode::All || self.expected(address)",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C02",
        "Accept non-root journal records",
        "crates/remi-core/src/lib.rs",
        "|| value.get(\"_UID\")?.as_str()? != \"0\"",
        "|| false",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C03",
        "Permit zero source ports",
        "crates/remi-core/src/lib.rs",
        "fields[7].parse::<u16>().ok().filter(|port| *port > 0)?",
        "fields[7].parse::<u16>().ok()?",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C04",
        "Accept missing socket inodes",
        "crates/remi-core/src/connections.rs",
        "|| self.inode == 0",
        "|| false",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C05",
        "Accept missing kernel cookies",
        "crates/remi-core/src/connections.rs",
        "|| self.cookie == [u32::MAX; 2]",
        "|| false",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C06",
        "Protect every session from the observer IP",
        "crates/remi-core/src/connections.rs",
        "&& a.port() == b.port()",
        "&& true",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C07",
        "Allow closing listeners",
        "crates/remi-core/src/connections.rs",
        "matches!(self.state, 1..=5 | 8 | 9 | 11)",
        "matches!(self.state, 1..=5 | 8 | 9 | 10 | 11)",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C08",
        "Count sessions as distinct client IPs",
        "crates/remi-core/src/services.rs",
        "service.clients = clients.get(port).map_or(0, BTreeSet::len);",
        "service.clients = service.connections;",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C09",
        "Stop normalizing mapped IPv4 clients",
        "crates/remi-core/src/services.rs",
        "IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),",
        "IpAddr::V6(v6) => IpAddr::V6(v6),",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C10",
        "Prioritize background sockets over listeners",
        "crates/remi-core/src/services.rs",
        "} else if row.state == 10 {\n            1",
        "} else if row.state == 10 {\n            4",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C11",
        "Remove the service summary bound",
        "crates/remi-core/src/services.rs",
        "services.into_values().take(SERVICE_LIMIT).collect()",
        "services.into_values().collect()",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C12",
        "Hide mixed network/loopback services as internal",
        "crates/remi-core/src/services.rs",
        ".all(|a| canonical(a.ip()).is_loopback())",
        ".any(|a| canonical(a.ip()).is_loopback())",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C13",
        "Limit individual chunks instead of complete frames",
        "crates/remi-core/src/lib.rs",
        "if line.len() + take > limit {",
        "if take > limit {",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "C14",
        "Reject a frame exactly at the allowed limit",
        "crates/remi-core/src/lib.rs",
        "if line.len() + take > limit {",
        "if line.len() + take >= limit {",
        "remi-core",
        CORE,
        false,
        false
    ),
    case!(
        "D01",
        "Show internal services by default",
        "crates/remi-desktop/src/connections.rs",
        "(self.internal || !s.local_only())",
        "(true || self.internal || !s.local_only())",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D02",
        "Automatically refresh the fixed detail view",
        "crates/remi-desktop/src/connections.rs",
        "self.view == View::Services\n                    && self.auto_refresh",
        "true\n                    && self.auto_refresh",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D03",
        "Accept a reply for the wrong port",
        "crates/remi-desktop/src/connections.rs",
        "if snapshot.port != expected_port {",
        "if false && snapshot.port != expected_port {",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D04",
        "Accept a reply for the wrong request ID",
        "crates/remi-desktop/src/connections.rs",
        "if reply.id != request.id {",
        "if false && reply.id != request.id {",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D05",
        "Enable close while disconnected",
        "crates/remi-desktop/src/connections.rs",
        "connected\n            && self.sender.is_some()",
        "(connected || true)\n            && self.sender.is_some()",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D06",
        "Alternative stable reverse ordering (negative control)",
        "crates/remi-desktop/src/connections.rs",
        "rows.sort_by_key(|r| (r.key.remote, r.key.local, r.key.cookie));",
        "rows.sort_by_key(|r| std::cmp::Reverse((r.key.remote, r.key.local, r.key.cookie)));",
        "remi-desktop",
        DESKTOP,
        false,
        true
    ),
    case!(
        "D07",
        "Keep destructive actions enabled after an error",
        "crates/remi-desktop/src/connections.rs",
        "self.error = Some(message);\n                self.last_received = None;",
        "self.error = Some(message);",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D08",
        "Accept a close acknowledgment for another socket",
        "crates/remi-desktop/src/connections.rs",
        "if key == expected =>",
        "if true =>",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D09",
        "Alert on Remi's own login",
        "crates/remi-desktop/src/model.rs",
        "if self.observer {\n            \"observer_session\"",
        "if false && self.observer {\n            \"observer_session\"",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "D10",
        "Accept a revoked host key",
        "crates/remi-desktop/src/host_keys.rs",
        "Some(Marker::Revoked) if same_key =>",
        "Some(Marker::Revoked) if false && same_key =>",
        "remi-desktop",
        DESKTOP,
        false,
        false
    ),
    case!(
        "A01",
        "Store the same journal cursor twice",
        "crates/remi-agent/src/main.rs",
        "if self.entries.iter().any(|entry| entry.cursor == cursor) {",
        "if false && self.entries.iter().any(|entry| entry.cursor == cursor) {",
        "remi-agent",
        AGENT,
        false,
        false
    ),
    case!(
        "A02",
        "Advance the event cursor before persistence succeeds",
        "crates/remi-agent/src/main.rs",
        "next.save(path)?;\n        *self = next;",
        "*self = next.clone();\n        next.save(path)?;",
        "remi-agent",
        AGENT,
        false,
        false
    ),
    case!(
        "A03",
        "Suppress other SSH sessions on the same source IP",
        "crates/remi-agent/src/observer.rs",
        "&& event.source_port == self.connection.remote.port()",
        "&& true",
        "remi-agent",
        AGENT,
        false,
        false
    ),
    case!(
        "A04",
        "Reject a login at the process start timestamp",
        "crates/remi-agent/src/observer.rs",
        "origin.monotonic_micros >= *started",
        "origin.monotonic_micros > *started",
        "remi-agent",
        AGENT,
        false,
        false
    ),
    case!(
        "A05",
        "Ignore the SSH process identity",
        "crates/remi-agent/src/observer.rs",
        "origin.pid == *pid && origin.monotonic_micros",
        "true && origin.monotonic_micros",
        "remi-agent",
        AGENT,
        false,
        false
    ),
    case!(
        "L01",
        "Leak unrelated listeners into a scoped query",
        "crates/remi-agent/src/sockets.rs",
        "rows.retain(|r| r.key.local.port() == port);",
        "let _ = port;",
        "remi-agent",
        SOCKETS,
        true,
        false
    ),
    case!(
        "L02",
        "Omit observer protection from Linux snapshots",
        "crates/remi-agent/src/sockets.rs",
        "row.protected = observer.is_some_and(|o| o.protects(&row.key));",
        "row.protected = false;",
        "remi-agent",
        AGENT,
        true,
        false
    ),
    case!(
        "L03",
        "Compute service counts after truncating sockets",
        "crates/remi-agent/src/sockets.rs",
        "rows.truncate(SNAPSHOT_LIMIT);",
        "rows.truncate(SNAPSHOT_LIMIT);\n        overview = remi_core::services::ServiceOverview::from_rows(&rows);",
        "remi-agent",
        SOCKETS,
        true,
        false
    ),
    case!(
        "L04",
        "Apply the per-port filter after the sample limit",
        "crates/remi-agent/src/sockets.rs",
        "rows.retain(|r| r.state == 10 || r.key.local.port() == port);",
        "let _ = port;",
        "remi-agent",
        SOCKETS,
        true,
        false
    ),
    case!(
        "E01",
        "Equivalent addition order (negative control)",
        "crates/remi-core/src/services.rs",
        "service.connections += 1;",
        "service.connections = 1 + service.connections;",
        "remi-core",
        CORE,
        false,
        true
    ),
];

pub fn run(linux: bool, only: Option<&str>, label: &str) -> Result<()> {
    if linux && !cfg!(target_os = "linux") {
        bail!("The Linux audit must run inside a disposable Linux environment");
    }
    if !linux && !cfg!(target_os = "macos") {
        bail!("The native audit includes the macOS desktop; use --linux on Linux");
    }
    if label.is_empty()
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("Use an alphanumeric audit label");
    }
    let selection = only.map(|s| s.split(',').collect::<BTreeSet<_>>());
    if let Some(ids) = &selection {
        for id in ids {
            if !CASES.iter().any(|m| m.id == *id && m.linux == linux) {
                bail!("Unknown mutation for this platform: {id}");
            }
        }
    }
    let cases: Vec<_> = CASES
        .iter()
        .filter(|m| m.linux == linux && selection.as_ref().is_none_or(|ids| ids.contains(m.id)))
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let output = root.join(format!(
        ".test/mutations/{label}-{stamp}-{}",
        std::process::id()
    ));
    let source = output.join("source");
    fs::create_dir_all(&source)?;
    let files = Command::new("git")
        .arg("-c")
        .arg(format!("safe.directory={}", root.display()))
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()?;
    if !files.status.success() {
        bail!("Cannot enumerate repository sources");
    }
    for name in files.stdout.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let name = std::str::from_utf8(name)?;
        let from = root.join(name);
        if !from.is_file() {
            continue;
        }
        if fs::symlink_metadata(&from)?.file_type().is_symlink() {
            bail!("Symlink source is unsupported: {name}");
        }
        let to = source.join(name);
        fs::create_dir_all(to.parent().unwrap())?;
        fs::copy(&from, &to)?;
    }
    println!(
        "audit_sources={} mutations={}",
        source.display(),
        cases.len()
    );
    let mut targets = BTreeSet::new();
    for m in &cases {
        targets.insert((m.package, m.target));
    }
    for (package, target) in &targets {
        let (ok, timed_out, log) = test(
            &source,
            &output,
            root,
            package,
            target,
            &format!("baseline-{package}-{}", target[0].trim_start_matches('-')),
            false,
        )?;
        if !ok || timed_out || !has_passing_tests(&log) {
            bail!("Baseline failed; see {}", output.display());
        }
    }
    let mut results = Vec::new();
    let mut unexpected = 0;
    for m in cases {
        let file = source.join(m.file);
        let original = fs::read_to_string(&file)?;
        let production_end = original.find("#[cfg(test)]").unwrap_or(original.len());
        let production = &original[..production_end];
        if production.matches(m.before).count() != 1 {
            bail!(
                "{} needs exactly one production-code anchor; tests are never patched",
                m.id
            );
        }
        let changed = format!(
            "{}{}",
            production.replacen(m.before, m.after, 1),
            &original[production_end..]
        );
        fs::write(&file, changed)?;
        let execution = (|| -> Result<_> {
            let (built, timeout, _) = test(
                &source,
                &output,
                root,
                m.package,
                m.target,
                &format!("{}-compile", m.id),
                true,
            )?;
            if !built || timeout {
                return Ok((if timeout { "timeout" } else { "invalid" }, String::new()));
            }
            let (passed, timeout, log) =
                test(&source, &output, root, m.package, m.target, m.id, false)?;
            let outcome = if timeout {
                "timeout"
            } else if passed && has_passing_tests(&log) {
                if m.control {
                    "control_passed"
                } else {
                    "survived"
                }
            } else if log.contains("test result: FAILED.")
                && log
                    .lines()
                    .any(|l| l.starts_with("test ") && l.ends_with(" ... FAILED"))
            {
                if m.control {
                    "control_failed"
                } else {
                    "detected"
                }
            } else {
                "invalid"
            };
            Ok((outcome, log))
        })();
        fs::write(&file, &original)?;
        if fs::read_to_string(&file)? != original {
            bail!("Failed to restore isolated source");
        }
        let (outcome, log) = execution?;
        let failed: Vec<_> = log
            .lines()
            .filter(|l| l.starts_with("test ") && l.ends_with(" ... FAILED"))
            .collect();
        println!(
            "mutation={} outcome={} description={}",
            m.id, outcome, m.description
        );
        if !matches!(outcome, "detected" | "control_passed") {
            unexpected += 1;
        }
        results.push(json!({"id":m.id,"description":m.description,"file":m.file,"before":m.before,"after":m.after,"package":m.package,"target":m.target,"outcome":outcome,"failed_tests":failed}));
        fs::write(
            output.join("results.json"),
            serde_json::to_vec_pretty(&results)?,
        )?;
    }
    // Demonstrate that restoring the code returns the same suites to green.
    for (package, target) in targets {
        let (ok, timeout, log) = test(
            &source,
            &output,
            root,
            package,
            target,
            &format!("restored-{package}-{}", target[0].trim_start_matches('-')),
            false,
        )?;
        if !ok || timeout || !has_passing_tests(&log) {
            bail!("Restored baseline failed; see {}", output.display());
        }
    }
    println!(
        "audit_complete={} unexpected={unexpected}",
        output.display()
    );
    if unexpected > 0 {
        bail!(
            "{unexpected} mutations need investigation; invalid and timeout cases are not detections"
        );
    }
    Ok(())
}

fn has_passing_tests(log: &str) -> bool {
    log.contains("test result: ok.")
        && log
            .lines()
            .any(|l| l.starts_with("test ") && l.ends_with(" ... ok"))
}

fn test(
    source: &Path,
    output: &Path,
    root: &Path,
    package: &str,
    target: &[&str],
    name: &str,
    compile_only: bool,
) -> Result<(bool, bool, String)> {
    let log_path = output.join(format!("{name}.log"));
    let log = fs::File::create(&log_path)?;
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .args(["test", "--locked", "--offline", "-p", package])
        .args(target)
        .current_dir(source)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if compile_only {
        command.arg("--no-run");
    } else {
        command.args(["--", "--test-threads=1"]);
    }
    // A timed-out mutation must not leave test binaries running after cargo exits.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().context("Cannot start mutation test")?;
    let started = Instant::now();
    let (passed, timeout) = loop {
        if let Some(status) = child.try_wait()? {
            break (status.success(), false);
        }
        if started.elapsed() > Duration::from_secs(180) {
            #[cfg(unix)]
            {
                // SAFETY: this is the new process group created for our own child above.
                if unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            #[cfg(not(unix))]
            child.kill()?;
            child.wait()?;
            break (false, true);
        }
        thread::sleep(Duration::from_millis(100));
    };
    Ok((passed, timeout, fs::read_to_string(log_path)?))
}
