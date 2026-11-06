# Connection control 0.2.0 — acceptance, 2026-11-06

The desktop and agent implementation are Rust. This report separates kernel/protocol checks from visible application acceptance; existing notification-click limitations remain documented in [MVP acceptance](ACCEPTANCE.md).

## Automated and kernel checks

- [x] `cargo fmt --all --check` and `git diff --check`.
- [x] Clippy with warnings denied: all workspace targets on macOS; agent/core targets on Linux.
- [x] macOS workspace: **32 passing tests**; the existing optional SSH fixture test is excluded from this run.
- [x] Linux agent/core: **23 passing tests**, including real IPv4/IPv6 socket enumeration, process identity, bounded stdin protocol, malformed requests and refusal without an identified observer.
- [x] All **11 agent unit tests**, including destructive kernel checks, pass on Debian 12 AMD64 inside a newly created, isolated network namespace with loopback only.
- [x] Exact TCP close works for IPv4 and IPv6; a second established connection remains usable and the original listener accepts a new client afterward.
- [x] The observer and its reversed loopback tuple are protected; IPv4-mapped IPv6 normalization is covered.
- [x] Wrong cookies, stale sockets, missing socket identity and listening sockets cannot be closed through the operation.
- [x] The kernel capability probe preserves existing connections; unsupported kernels return read-only snapshots.
- [x] Desktop request IDs are matched, disconnects clear pending actions, failed/unconfirmed operations are not replayed, and a successful close updates the count before refreshing.

The LinuxKit 7.0.14 kernel in this Docker Desktop installation has `CONFIG_INET_DIAG_DESTROY` disabled. An initial destructive test correctly failed with `EOPNOTSUPP`; it was then run successfully on Debian's 6.1.0-54-cloud-amd64 kernel with that option enabled. The application now detects this limitation and disables closure. This is not an assertion that LinuxKit supports closing sockets.

## Visible macOS acceptance against the actual testing server

Performed through native computer control, screenshots and accessibility observations in the user's Remi window, using the existing SSH account and known-host identity:

- [x] 0.2.0 reconnects to the real Debian testing server and retains the existing login history.
- [x] **Conexiones** displays a live table of approximately 600–650 TCP sockets, endpoints, states, owners and process/PID metadata.
- [x] Periodic refresh updates the timestamp and table; manual refresh works and disables closure while data is pending or stale.
- [x] Searching the observer's exact peer endpoint shows **Remi · protegida**, with no close button.
- [x] Searching the SSH listener shows **En escucha**, with no close button; toggling listener inclusion hides and restores it.
- [x] An independently created disposable SSH session is found using its exact peer endpoint.
- [x] **Cerrar conexión** shows the exact endpoints and an interruption warning.
- [x] **Cancelar** leaves that session running; its output continues afterward.
- [x] **Confirmar cierre** returns **Conexión cerrada** and removes the selected connection from the refreshed table.
- [x] The disposable client exits with `Connection reset by peer`; the main Remi transport remains **Vigilando**.
- [x] The server's system journal contains correlated `tcp_connection_close` records for `requested` and `closed`, including the actor, tuple, cookie and request ID.

A transient count discrepancy discovered in the UI was fixed: removing the locally confirmed row now also decrements the snapshot count while the refreshed table arrives; a regression test covers it.

## Deployment and limits

- [x] The Debian 12 AMD64 testing server was upgraded from 0.1.0 to 0.2.0 using the checksum-verified `.deb`; `doctor` succeeds and the collector is active and enabled with its existing unprivileged service account.
- [x] ARM64 and AMD64 Debian packages and the local Apple Silicon app bundle build successfully.
- This update does not install sudoers rules, change SSH/firewall configuration or open a network listener.
- Closure requires the existing account's passwordless sudo access to the helper, `CAP_NET_ADMIN` and kernel support; the monitoring service itself remains unprivileged.
- Scope is TCP in the agent's network namespace, capped at 1,024 displayed sockets with explicit truncation; processes can reconnect after a close.
- UDP, service termination, IP blocking, other container namespaces, Intel macOS and a new Debian 13 destructive-closure acceptance run are outside this version's tested scope.

To reproduce the destructive unit test, build the agent test executable for the target Linux architecture and run it in a disposable network namespace with loopback enabled and `CAP_NET_ADMIN`, selecting `sockets::linux::tests::exact_close_preserves_other_sockets_listener_and_observer --ignored --exact`.
