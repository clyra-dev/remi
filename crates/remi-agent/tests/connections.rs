#![cfg(target_os = "linux")]
use remi_core::{connections::*, read_line_bounded};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn control_protocol_lists_real_sockets_and_refuses_close_without_observer() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let _unrelated_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_remi-agent"))
        .arg("connections")
        .env_remove("SSH_CONNECTION")
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let hello: ControlReply = serde_json::from_str(
        &read_line_bounded(&mut output, CONTROL_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        hello.result,
        ControlResult::Ready {
            protocol: CONTROL_PROTOCOL
        }
    ));
    let request = ControlRequest {
        id: 1,
        action: ControlAction::List,
    };
    stdin
        .write_all(format!("{}\n", serde_json::to_string(&request).unwrap()).as_bytes())
        .await
        .unwrap();
    let reply: ControlReply = serde_json::from_str(
        &tokio::time::timeout(
            Duration::from_secs(15),
            read_line_bounded(&mut output, CONTROL_FRAME_BYTES),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    assert_eq!(reply.id, 1);
    let ControlResult::Snapshot { snapshot } = reply.result else {
        panic!("not a snapshot")
    };
    assert!(!snapshot.can_close);
    let row = snapshot
        .connections
        .iter()
        .find(|r| {
            r.key.local == server.local_addr().unwrap()
                && r.key.remote == client.local_addr().unwrap()
        })
        .unwrap();
    assert!(snapshot.overview.is_some());
    let port = server.local_addr().unwrap().port();
    let scoped = ControlRequest {
        id: 2,
        action: ControlAction::ListService { port },
    };
    stdin
        .write_all(format!("{}\n", serde_json::to_string(&scoped).unwrap()).as_bytes())
        .await
        .unwrap();
    let reply: ControlReply = serde_json::from_str(
        &tokio::time::timeout(
            Duration::from_secs(15),
            read_line_bounded(&mut output, CONTROL_FRAME_BYTES),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    assert_eq!(reply.id, 2);
    let ControlResult::Snapshot { snapshot: scoped } = reply.result else {
        panic!("not a scoped snapshot")
    };
    assert_eq!(scoped.port, Some(port));
    assert!(!scoped.connections.is_empty());
    assert!(
        scoped
            .connections
            .iter()
            .all(|r| r.key.local.port() == port)
    );
    assert_eq!(
        scoped
            .overview
            .as_ref()
            .unwrap()
            .service(port)
            .unwrap()
            .connections,
        1
    );
    let request = ControlRequest {
        id: 3,
        action: ControlAction::Close {
            key: row.key.clone(),
        },
    };
    stdin
        .write_all(format!("{}\n", serde_json::to_string(&request).unwrap()).as_bytes())
        .await
        .unwrap();
    let reply: ControlReply = serde_json::from_str(
        &tokio::time::timeout(
            Duration::from_secs(15),
            read_line_bounded(&mut output, CONTROL_FRAME_BYTES),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    assert_eq!(reply.id, 3);
    assert!(matches!(reply.result, ControlResult::Error { .. }));
    drop(stdin);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

async fn snapshot_for(action: ControlAction) -> ConnectionsSnapshot {
    let mut child = Command::new(env!("CARGO_BIN_EXE_remi-agent"))
        .arg("connections")
        .env_remove("SSH_CONNECTION")
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(
            format!(
                "{}\n",
                serde_json::to_string(&ControlRequest { id: 1, action }).unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    drop(input);
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    let reply: ControlReply = serde_json::from_str(output.lines().nth(1).unwrap()).unwrap();
    assert_eq!(reply.id, 1);
    let ControlResult::Snapshot { snapshot } = reply.result else {
        panic!("Expected snapshot")
    };
    snapshot
}

#[tokio::test]
async fn busy_unrelated_service_cannot_hide_full_counts_or_a_scoped_connection() {
    // Every socket belongs to this test on loopback; no external service or privilege is needed.
    let count = SNAPSHOT_LIMIT + 32;
    // Development shells may start with a soft limit of 1,024 descriptors.
    // Only this test process is adjusted, and never beyond its existing hard limit.
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes a valid, uniquely borrowed rlimit structure.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
        0
    );
    let needed = (count * 2 + 128) as libc::rlim_t;
    if limits.rlim_cur < needed {
        assert!(
            limits.rlim_max >= needed,
            "This isolated socket test needs a hard descriptor limit of at least {needed}"
        );
        limits.rlim_cur = needed;
        // SAFETY: the initialized structure preserves the hard limit and supplies a valid soft limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
    }
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (busy, target) = if first.local_addr().unwrap().port() < second.local_addr().unwrap().port()
    {
        (first, second)
    } else {
        (second, first)
    };
    let mut background = Vec::new();
    for _ in 0..count {
        let client = std::net::TcpStream::connect(busy.local_addr().unwrap()).unwrap();
        let (server, _) = busy.accept().unwrap();
        background.push((client, server));
    }
    let client = std::net::TcpStream::connect(target.local_addr().unwrap()).unwrap();
    let (server, _) = target.accept().unwrap();
    let general = snapshot_for(ControlAction::List).await;
    assert!(general.total > SNAPSHOT_LIMIT);
    assert_eq!(general.connections.len(), SNAPSHOT_LIMIT);
    let overview = general.overview.unwrap();
    assert_eq!(
        overview
            .service(busy.local_addr().unwrap().port())
            .unwrap()
            .connections,
        count
    );
    assert!(
        overview.other_connections > count,
        "All client-side sockets must be counted before sampling"
    );
    let port = target.local_addr().unwrap().port();
    let scoped = snapshot_for(ControlAction::ListService { port }).await;
    assert_eq!(scoped.port, Some(port));
    assert_eq!(scoped.total, 2);
    assert_eq!(
        scoped.connections.len(),
        2,
        "An unrelated busy lower port must not consume this sample"
    );
    assert!(
        scoped
            .connections
            .iter()
            .all(|r| r.key.local.port() == port)
    );
    assert!(scoped.connections.iter().any(|r| r.state == 1
        && r.key.local == server.local_addr().unwrap()
        && r.key.remote == client.local_addr().unwrap()));
    assert_eq!(background.len(), count);
}

#[tokio::test]
async fn malformed_control_does_not_run_an_operation() {
    for request in [
        "{\"id\":1,\"action\":{\"action\":\"shell\",\"command\":\"whoami\"}}\n".to_string(),
        "x".repeat(CONTROL_REQUEST_BYTES + 1),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_remi-agent"))
            .arg("connections")
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(request.as_bytes()).await.unwrap();
        drop(stdin);
        let result = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(!result.status.success());
        let replies = String::from_utf8(result.stdout).unwrap();
        assert_eq!(replies.lines().count(), 1); // Ready only, never a successful operation.
    }
}
