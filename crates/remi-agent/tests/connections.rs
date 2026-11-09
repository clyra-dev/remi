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
