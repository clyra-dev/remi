//! Real daemon process tests. Fixtures are explicitly flagged as simulated on the wire.
use remi_core::{Frame, PROTOCOL, StreamRequest, read_line};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::UnixStream,
};

struct Agent {
    child: Child,
    dir: tempfile::TempDir,
    config: PathBuf,
    fixture: PathBuf,
    socket: PathBuf,
}
impl Agent {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("agent.toml");
        let fixture = dir.path().join("journal.jsonl");
        let socket = dir.path().join("run/events.sock");
        fs::write(&config, format!("state_dir = {:?}\nsocket_path = {:?}\nretention_events = 10\nhostname = 'cli-test'\n", dir.path().join("state").to_str().unwrap(), socket.to_str().unwrap())).unwrap();
        let mut records = String::new();
        for index in 1..=15 {
            records.push_str(&format!("{}\n", serde_json::json!({"_COMM":"sshd","_UID":"0","__CURSOR":format!("cursor-{index}"),"__REALTIME_TIMESTAMP":format!("1700000000{index:06}"),"MESSAGE":"Accepted publickey for reader from 192.0.2.10 port 40000 ssh2: ED25519 SECRET-FINGERPRINT"})));
        }
        fs::write(&fixture, records).unwrap();
        let child = spawn(&config, &fixture);
        Self {
            child,
            dir,
            config,
            fixture,
            socket,
        }
    }
    async fn ready(&self) -> Frame {
        for _ in 0..150 {
            if let Ok(mut socket) = UnixStream::connect(&self.socket).await {
                let mut request = serde_json::to_vec(&StreamRequest {
                    protocol: PROTOCOL,
                    after: 0,
                    instance: None,
                })
                .unwrap();
                request.push(b'\n');
                socket.write_all(&request).await.unwrap();
                let line = tokio::time::timeout(
                    Duration::from_secs(2),
                    read_line(&mut BufReader::new(socket)),
                )
                .await
                .unwrap()
                .unwrap()
                .unwrap();
                let hello: Frame = serde_json::from_str(&line).unwrap();
                if matches!(
                    hello,
                    Frame::Hello {
                        latest: 15,
                        journal_ready: true,
                        ..
                    }
                ) {
                    return hello;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("daemon did not become ready");
    }
}
fn spawn(config: &std::path::Path, fixture: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_remi-agent"))
        .arg("--config")
        .arg(config)
        .args(["run", "--journal-fixture"])
        .arg(fixture)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[tokio::test]
async fn daemon_lock_permissions_protocol_and_fixture_label_are_enforced() {
    let agent = Agent::start();
    assert!(matches!(
        agent.ready().await,
        Frame::Hello {
            simulated: true,
            oldest: 6,
            latest: 15,
            ..
        }
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_remi-agent"))
        .arg("--config")
        .arg(&agent.config)
        .args(["run", "--journal-fixture"])
        .arg(&agent.fixture)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Otro agente"));
    use std::os::unix::fs::PermissionsExt;
    for (path, mode) in [
        (agent.socket.clone(), 0o660),
        (agent.dir.path().join("state/events.json"), 0o600),
        (agent.dir.path().join("state"), 0o700),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            mode
        );
    }
    let saved = fs::read_to_string(agent.dir.path().join("state/events.json")).unwrap();
    assert!(!saved.contains("SECRET-FINGERPRINT"));
    let mut client = UnixStream::connect(&agent.socket).await.unwrap();
    client
        .write_all(b"{\"protocol\":999,\"after\":0,\"instance\":null}\n")
        .await
        .unwrap();
    let mut input = BufReader::new(client);
    let frame: Frame =
        serde_json::from_str(&read_line(&mut input).await.unwrap().unwrap()).unwrap();
    assert!(matches!(frame, Frame::Error { .. }));
    assert!(read_line(&mut input).await.unwrap().is_none());
}

#[tokio::test]
async fn daemon_restart_preserves_identity_and_replays_only_retained_events() {
    let mut agent = Agent::start();
    let Frame::Hello { instance, .. } = agent.ready().await else {
        panic!()
    };
    agent.child.kill().unwrap();
    agent.child.wait().unwrap();
    // A real journal resumes after its cursor. The test fixture reproduces that by only replaying retained cursors.
    let records = fs::read_to_string(&agent.fixture)
        .unwrap()
        .lines()
        .skip(5)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&agent.fixture, records).unwrap();
    agent.child = spawn(&agent.config, &agent.fixture);
    assert!(
        matches!(agent.ready().await, Frame::Hello { instance: ref next, latest: 15, .. } if next == &instance)
    );
    let mut client = UnixStream::connect(&agent.socket).await.unwrap();
    let request = format!(
        "{}\n",
        serde_json::to_string(&StreamRequest {
            protocol: PROTOCOL,
            after: 13,
            instance: Some(instance)
        })
        .unwrap()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut input = BufReader::new(client);
    let hello: Frame =
        serde_json::from_str(&read_line(&mut input).await.unwrap().unwrap()).unwrap();
    assert!(matches!(
        hello,
        Frame::Hello {
            resync: false,
            gap: false,
            ..
        }
    ));
    for expected in [14, 15] {
        let frame: Frame =
            serde_json::from_str(&read_line(&mut input).await.unwrap().unwrap()).unwrap();
        assert!(matches!(frame, Frame::Login { event } if event.sequence == expected));
    }
    agent.child.kill().unwrap();
    agent.child.wait().unwrap();
    let state = agent.dir.path().join("state/events.json");
    fs::write(&state, "broken").unwrap();
    agent.child = spawn(&agent.config, &agent.fixture);
    assert!(!agent.child.wait().unwrap().success());
    assert_eq!(fs::read_to_string(state).unwrap(), "broken");
}
