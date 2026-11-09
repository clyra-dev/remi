# Service recognition 0.4.0 — evidence, 2026-11-09 UTC

The service summary now explains recognized process roles, TCP payload recency and Nginx sites/destinations configured on a selected port. Shared HTTPS sockets are not assigned to applications without evidence. Application, protocol, UI and packaging implementation remains Rust.

## Automated verification

- [x] macOS workspace: **57 passed**, one existing opt-in SSH test ignored.
- [x] Linux agent/core: **42 passed**, one existing destructive kernel test ignored.
- [x] Clippy with warnings denied on all workspace targets on macOS and agent/core targets on Linux.
- [x] Desktop tests passed again after the final presentation adjustment; formatting and diff whitespace checks passed.
- [x] Nginx fixtures independently specify port separation, IPv4/IPv6 listeners, literal names, TLS, includes, upstream resolution and expected backend authorities.
- [x] Paths, query tokens and header credentials are absent from serialized catalog fixtures; variable and credential-bearing destinations remain unavailable.
- [x] Missing files, malformed includes, recursive includes, outside-tree paths, symlink escapes, size/depth/site limits and recovery to a valid configuration are covered.
- [x] TCP attribute tests cover native-endian offsets, both payload directions, unused directions, alignment, missing attributes, old layouts and truncated/malformed lengths.
- [x] Summary tests distinguish 9,999 ms from 10,000 ms, unknown metrics, unused sockets and transitioning TCP states.
- [x] A real Linux loopback socket starts with zero data segments; after payload it has a recent age; the age increases during silence and resets after another payload. This reads actual INET_DIAG responses, without mocking the kernel.
- [x] A pre-0.4 snapshot fixture deserializes with absent recognition fields; missing metadata does not become invented activity.

Commands:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
docker exec remi-build /usr/local/cargo/bin/cargo test -p remi-core -p remi-agent --locked
docker exec remi-build /usr/local/cargo/bin/cargo clippy -p remi-core -p remi-agent --all-targets --locked -- -D warnings
cargo test -p remi-desktop --locked
cargo fmt --all -- --check
git diff --check
```

## Manual challenges of unchanged tests

Production code was edited manually in `.test/recognition-0.4.0/manual/source`, a disposable copy of the current sources. No mutation runner was used. Each test passed before the edit; the faulty code compiled; the exact same test failed for the behavioral reason below; the source edit was reverted; the same test passed again. Assertions and fixtures were unchanged throughout. Final file comparisons verified the four restored files matched the working sources byte for byte.

| Behavior | Temporary fault | Observed failure | Restored |
| --- | --- | --- | --- |
| Recent traffic is strictly less than 10 seconds old | `< RECENT_TRAFFIC_MS` became `<= RECENT_TRAFFIC_MS` | Actual recent/quiet **3/2**, expected **2/3**; the exactly-10-second connection was misclassified | 1 passed |
| A catalog contains only the requested port | Replaced the listener port equality with `is_some()` | Actual **2 sites**, expected **1**; the port-80 site leaked into port 443 | 1 passed |
| Recency uses the latest payload in either direction | Replaced `min()` with `max()` | Actual **12,000 ms**, expected **230 ms** | 1 passed |
| The netlink request asks for TCP_INFO | Set the extension byte to zero | Real-socket test failed with **The request must enable TCP_INFO** | 1 passed |

Direct test commands, run from the disposable workspace with the existing Cargo target cache:

```sh
cargo test -p remi-core services::tests::traffic_counts_follow_payload_age_boundary_and_keep_unknown_separate --lib --locked -- --exact
cargo test -p remi-agent nginx::tests::catalog_matches_port_resolves_includes_and_redacts_request_material --bin remi-agent --locked -- --exact
cargo test -p remi-agent tcp_info::tests::decodes_payload_recency_and_excludes_directions_without_payload --bin remi-agent --locked -- --exact
docker exec -e CARGO_TARGET_DIR=/src/target remi-build /usr/local/cargo/bin/cargo test --manifest-path /src/.test/recognition-0.4.0/manual/source/Cargo.toml -p remi-agent sockets::linux::tests::kernel_payload_recency_moves_from_unused_to_quiet_and_back_to_recent --bin remi-agent --locked -- --exact
```

These four challenges provide evidence for the sampled behaviors, not an exhaustive mutation score or a guarantee of universal correctness. A patch-context mismatch while setting up one edit was corrected before running its test; it was not counted as defect detection.

## Visible macOS acceptance against actual Debian testing

Performed using native mouse clicks, keyboard input, accessibility observations and screenshots in Remi. Direct protocol checks complement this acceptance.

- [x] Installed app displays **v0.4.0** and **Vigilando** against the existing testing endpoint.
- [x] Service cards identify SSH administration, Nginx web/proxy and PostgreSQL database roles; unknown programs retain an explicit unknown purpose.
- [x] Cards and port summaries show recent/quiet activity; the final card presentation also includes transitioning and unavailable counts.
- [x] Opening port 443 displays **14 configured sites from 17 files**, TLS and backend destinations, with an explicit partial-catalog notice.
- [x] Searching by an application name narrows to its site and destinations; searching by backend port finds the corresponding site; an unmatched search displays zero results; clearing restores the catalog.
- [x] Port 80 has a separate **11-site** catalog without an explicit TLS listener, rather than inheriting the HTTPS catalog.
- [x] The individual-connections tab remains fixed at its capture timestamp, displays six rows per page, advances to page two and shows payload age in expanded details.
- [x] The SSH transport is marked **Remi · protegida** with no close button. The separate diagnostic session can open the exact-endpoint confirmation; **Cancelar** dismisses it and leaves the session alive.
- [x] Disconnecting preserves the selected port and catalog, displays **Sin conexión**, and disables refresh.
- [x] Reconnecting returns to **Vigilando**, refreshes the same port and keeps the catalog available; the timestamp advances only after fresh data arrives.
- [x] The final build's application search, explanation disclosure, catalog scrolling and manual refresh were exercised visibly; Remi is left connected on the port-443 summary with an empty search.

## Deployment and data preservation

- [x] macOS release build and local ad-hoc signature verification succeeded.
- [x] Debian AMD64 and ARM64 release binaries and `.deb` packages built successfully.
- [x] Testing upgraded from 0.3.0 to 0.4.0 using a checksum-verified AMD64 package; the installed executable hash matches the build.
- [x] `remi-agent doctor` succeeds; the collector remains active as `remi` with `NoNewPrivileges=yes`.
- [x] Configuration bytes, collector identity and all **203 pre-upgrade collector entries** are preserved as the unchanged history prefix.
- [x] Desktop settings, endpoint, collector identity and all **236 pre-upgrade desktop history entries** are preserved.
- [x] A direct scoped read returned **109 connections = 56 recent + 53 quiet**, with no transitioning/unknown entries in that sample; counts naturally change over time.
- [x] Desktop logs record received recognition metadata (port, site/file counts and completeness) and tab transitions, without configuration contents.
- [x] Private desktop/server backups remain outside version control. No Nginx configuration, access-log policy, firewall, SSH configuration or sudoers changes were made.

## Limits and excluded checks

Activity measures TCP payload recency, not current HTTP requests, application identity, user counts or malicious intent. The catalog is a bounded interpretation of standard Debian configuration files on disk; it is not proof those exact files are loaded. Outside-tree includes are intentionally skipped. In this testing environment that includes configuration outside `/etc/nginx`, so the partial notice is expected. Unsupported syntax, runtime variables, permissions and resource bounds can also make the catalog partial. Multiple names and applications may share one port; individual connections are not attributed to a specific site.

This release did not close any existing user/service connection or repeat notification permission flows. The pre-existing opt-in SSH and destructive Docker checks were not counted as passed. Kernel recency, protocol compatibility, UI acceptance and manual mutation evidence above are distinct forms of verification. AMD64 was installed on testing; ARM64 was built and packaged, not installed on a separate server.
