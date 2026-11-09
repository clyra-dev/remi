# Service administration 0.3.0 — acceptance, 2026-11-09 UTC

This update addresses the unstable, oversized connection table. The default view now groups listening ports into services; the per-service detail remains fixed while the operator reviews it. All application, interface, protocol and packaging changes are Rust.

## Automated checks

- [x] macOS workspace: **43 tests passed**, with the existing opt-in SSH fixture excluded.
- [x] Linux agent/core and integration checks: **30 tests passed**; the existing destructive kernel unit test was excluded in Docker because its kernel does not support `INET_DIAG_DESTROY`.
- [x] All five desktop connection-model tests passed again after the final test adjustment.
- [x] Clippy with warnings denied passed on all macOS workspace targets and Linux agent/core targets.
- [x] `cargo fmt --all -- --check` and `git diff --check` passed.
- [x] IPv4/IPv6 listeners are grouped by local port; mapped addresses and unique client counts are normalized without labeling network bindings as publicly exposed.
- [x] A sample with 1,500 background connections preserves complete service counts and prioritizes listeners before the detail limit.
- [x] The Linux control integration test reads real sockets, requests one local port and verifies that unrelated rows are absent; closure without an identified observer remains refused.
- [x] Desktop tests cover fixed detail refresh, scoped reconnect, retained cache, pagination bounds, mismatched replies, failed-channel action invalidation and no replay of a close after disconnect.

## Visible macOS acceptance on the actual testing server

Performed with native mouse and keyboard actions, accessibility observations and screenshots in the user's Remi window. Direct protocol and journal checks below supplement these visible tests.

- [x] The updated app connects to testing and displays **v0.3.0** and **Vigilando**.
- [x] **Conexiones** opens **Servicios** by default: 19 network service groups were visible, with 32 loopback-only groups hidden behind **Incluir internos**.
- [x] Cards display process/service names, local ports, connection counts and unique client IP counts. No individual background connections appear in the default view.
- [x] **Siguiente** and **Anterior** change pages with at most six cards per page. An automatic refresh updates counts/timestamp while retaining page two and its service order.
- [x] Turning off **Actualizar cada 10 s** keeps the summary timestamp fixed for more than 30 seconds; **Actualizar** still works while automatic refresh is paused. Automatic refresh was restored afterward.
- [x] Searching for an internal port initially shows no results; enabling **Incluir internos** reveals the matching loopback service, and disabling it hides the service again.
- [x] Searching for SSH opens its dedicated connection view. Process owner/PID information appears only after expanding **Detalles**.
- [x] The detail view stays unchanged for 25 seconds, including after a disposable SSH session is opened. **Actualizar** then adds that session without losing the selected service.
- [x] The Remi transport is labeled **Remi · protegida** and has no close button.
- [x] **Cerrar conexión** on the disposable session shows its exact endpoints. **Cancelar** keeps the socket established, confirmed by a server read.
- [x] A second confirmation stays usable for more than 15 seconds. **Confirmar cierre** closes only the disposable session; the UI reports success and removes the row, and that SSH client exits with `Connection reset by peer`.
- [x] The server journal records correlated `tcp_connection_close` outcomes `requested` and `closed`; Remi and the separate administration session remain connected.
- [x] **Vista técnica** is optional, fixed and paginated; its 1,024-row sample explicitly reports truncation. Listeners have no close button.
- [x] **Consultar puerto** rejects zero in the UI and retrieves only the requested port's detail when a valid port is entered. The server independently rejects port zero.
- [x] Searching within SSH narrows the results. Disconnecting preserves the selected port, query and cached row while disabling **Actualizar** and **Cerrar conexión**.
- [x] Reconnecting retains the selected port/query, fetches fresh data for that port and restores actions only after the reply arrives.
- [x] The final app bundle displays **Sin conexión** with retained service cards after a manual disconnect, then returns to **Vigilando** with fresh data after reconnecting. It is left on **Servicios**, with internal services hidden, an empty search and automatic refresh enabled.

## Deployment and direct verification

- [x] Apple Silicon app and Debian AMD64/ARM64 release binaries and packages build successfully; the local app's ad-hoc signature verifies.
- [x] The Debian AMD64 testing server was upgraded from 0.2.1 to 0.3.0 using the checksum-verified package. The installed executable hash matches the built binary.
- [x] `remi-agent doctor` succeeds after the UI tests; the collector remains active/enabled as `remi` with `NoNewPrivileges=yes`.
- [x] Configuration bytes, collector instance and the complete pre-upgrade event prefix are preserved. Desktop settings, endpoint, instance and existing history are preserved.
- [x] A direct general query observed **1,147 sockets**, a bounded **1,024-row** sample and **51 service groups**. A scoped SSH query returned all four matching rows (two listeners and two sessions) despite unrelated traffic exceeding the general sample limit.
- [x] Private pre-upgrade desktop and server backups are retained outside version control.

## Limits

The summary groups by local port, rather than application deployment or container. Network bindings do not establish public reachability through a firewall. Counts cover the agent's network namespace; separate container namespaces are outside this view. Up to 256 service groups and 1,024 detail rows are returned, with explicit partial-data messages. Other listener metadata can reserve part of the scoped detail bound.

A fixed detail is a timestamped snapshot, not proof that every displayed socket is still open. Closure still verifies the exact kernel cookie, tuple and inode; failed operations require fresh data before further actions. This update stabilizes the administration view and preserves data across reconnects; it does not prevent network loss or Mac sleep from interrupting SSH.

The disposable-session close was tested on the actual Debian testing kernel. This report does not claim the excluded Docker destructive test passed, or repeat all notification acceptance from previous releases. Existing notification and platform limits remain in [MVP acceptance](ACCEPTANCE.md), [connection control acceptance](CONNECTIONS.md) and [observer identity acceptance](OBSERVER.md).
