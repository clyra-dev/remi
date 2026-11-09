# Remi

**Remote Event Monitoring Interface.** A small macOS companion for SSH access and TCP connections on your Debian server.

Source: [clyra-dev/remi](https://github.com/clyra-dev/remi). The default integration branch is `staging`.

All application, interface, transport, agent, packaging-helper and build-tool code is Rust. The macOS app uses egui/eframe, AppKit's menu bar, UserNotifications and russh. The Debian agent uses the system journal. No web frontend, cloud account or additional TCP listener is required.

## MVP

- One Debian server; successful SSH authentication (IPv4 / IPv6).
- Native macOS notifications, history, server status and an explicit demo mode.
- All-login alerts or IP/CIDR allowlists; first-sync history is quiet, missed subsequent events are recovered.
- Remi's own SSH sessions stay in history without desktop alerts; other sessions from the same IP still follow your alert policy.
- Dedicated `remi` service account, durable bounded history, systemd service, `.deb` lifecycle, signed APT repository generation.
- SSH host identity verification and authentication using an SSH agent or private-key file. Passphrases are held in memory, never persisted.
- A service-first administration view: listening ports, connection/client counts, focused per-port inspection and an optional technical view.
- Explicitly confirmed closure of one TCP connection, kernel-cookie verification, protection of Remi's own SSH session and system-journal auditing.

TCP connection alerts, UDP control, stopping listening services and multiple servers are future work. This version reports SSH policy deviations; it cannot identify whether a valid SSH credential was stolen. A compromised root account can tamper with local telemetry.

## Install on Debian

Supported packaging targets: Debian 12 / 13, `arm64` and `amd64`, with systemd and OpenSSH. Use the package matching your machine (`dpkg --print-architecture`).

```sh
sudo apt install ./remi-agent_0.4.0_arm64.deb
sudo remi-agent authorize YOUR_SSH_USER
```

Start a **new** SSH session after authorization so the group membership takes effect. The `remi` daemon has no interactive shell; the SSH account connects only to the agent's read-only Unix socket. `authorize` grants access to login metadata, not the full system journal.

```sh
sudo remi-agent doctor
systemctl status remi-agent
sudo journalctl -u remi-agent -n 50 --no-pager
```

Configuration: `/etc/remi/agent.toml`. State: `/var/lib/remi/events.json` (10,000 events by default, oldest evicted first). Socket: `/run/remi/events.sock`. The agent starts from the current journal position on a fresh installation and resumes from its last recorded login thereafter. If journal retention has removed its cursor, Remi reports the gap and recovers available entries by time. It never claims to reconstruct deleted journal data.

To update manually, install the new `.deb` with `apt install ./...deb`. Configuration and event state are preserved; the active service restarts and catches up with the journal. An administrator-disabled service remains disabled. `apt remove remi-agent` stops/removes the program and retains configuration. `apt purge remi-agent` removes package configuration but intentionally retains audit history and the system account; delete retained history separately when appropriate.

## Use on macOS

Open `dist/Remi.app`, enable notifications and add the server's address, SSH username and authentication method. The included local bundle is for Apple Silicon; build on an Intel Mac for an Intel executable. Compare an unknown host fingerprint against your provider's console before trusting it. A changed recorded host identity is rejected. Configure permitted networks in Preferences.

Closing the window keeps Remi in the menu bar. Choose **Salir de Remi** there to quit. When the Mac sleeps or the app is closed, the agent continues storing events; they are recovered on reconnect. Native notifications respect macOS notification permissions and Focus settings. Bursts are grouped rather than producing one popup per event.

The demo uses reserved documentation addresses and is visibly marked. It does not contact a server or alter the real server cursor/history. Allowlists apply to real events; demo buttons intentionally generate an allowed or unexpected example.

Desktop state: `~/Library/Application Support/Remi/state.json` (2,000 events). Diagnostic logs: its `logs/` folder, rotated daily, retaining seven files. Files contain event metadata, not passwords, key contents, SSH command history or full journal messages. `REMI_DATA_DIR` selects a separate directory for acceptance tests. A corrupted state file is preserved and saving is disabled rather than silently overwriting it.

With desktop and agent 0.2.1 or newer, the SSH connection opened by Remi is recorded as **Conexión de Remi · registrada sin aviso**, including reconnects after sleep or network loss. It is excluded from the outside-allowlist count/filter without changing your allowlist or alert mode. Other SSH sessions from the same IP/user/key still follow your policy. Identification uses the server-reported source endpoint, trusted journal boot/PID/monotonic timestamp, and the reader's actual SSH process ancestry; a reused PID or port from an earlier session does not match. Classification is specific to each reader and never changes the collector's shared history.

If identity metadata is missing or cannot be verified, normal alerts remain enabled. Older agents show an identification notice, and old history is not retroactively labeled as Remi. Journal origin metadata contains process identity, not key fingerprints or command contents. Policies classify events when they arrive; changing a policy does not rewrite the classification of old history. Closing the app pauses desktop alerts while the server continues collecting.

## Live connections

Open **Conexiones** with desktop and agent 0.4.0. The default **Servicios** view groups listening sockets by local port, merges IPv4/IPv6 bindings and shows process names, recognized purposes and connection/client counts. Recognition uses observed process names rather than assuming a protocol from a port number. Loopback-only services are hidden until **Incluir internos** is selected. The summary updates every ten seconds in port order; connection churn does not reorder cards. A network binding means the process listens on that interface, not that a firewall or cloud policy exposes it publicly.

Choose **Ver servicio** to open its summary, then **Conexiones individuales** to inspect sockets. This detail view stays fixed until **Actualizar**, reconnect or a confirmed close; search, selection and pagination remain under your control. Only six socket rows are rendered per page. **Vista técnica** exposes the general TCP sample and can query a specific local port. The most recent data remains visible but non-actionable during disconnects, and changing servers clears the cache.

**Recognition in 0.4.0:** Linux `INET_DIAG_INFO` / `TCP_INFO` supplies payload recency. Established connections with data sent or received less than 10,000 ms before capture count as recent; older payload or no payload yet counts as quiet. Connecting/closing states and missing metrics remain separate. These are TCP data observations, not active HTTP request counts, people, WebSocket classification or threat scores. Acknowledgments alone do not count as payload. Counts are calculated before detail truncation. Old agents remain readable with explicitly unavailable activity metadata.

For a port owned by Nginx, the summary reads a catalog of HTTP `server` blocks from `/etc/nginx/nginx.conf` and includes contained within `/etc/nginx`. It shows literal server names, explicit TLS configuration and `proxy_pass` authorities, resolving literal upstream groups. Search accepts site names, configuration basenames and destinations. Shared ports do **not** associate a live socket with an individual site. This is configuration **on disk**, which may differ from the loaded configuration after an un-reloaded edit. Custom configuration roots, other network namespaces, runtime variables, unsupported syntax and unreadable/outside-tree includes can leave the catalog partial; Remi marks that condition. It does not reload Nginx or enable access logs.

Configuration inspection runs only on an explicit port read, within the existing helper's permissions. It does not execute Nginx, inspect traffic contents, or return request paths, query strings, credentials, header values, certificates or full configurations. Reads are bounded to 1 MiB, 96 file reads and depth 32; cycles, nonregular files and symlink escapes are rejected. The response includes at most 64 sites, 16 names/destinations per site and 64 KiB of catalog metadata. Recognition logs include port, file/site counts and completeness, without configuration contents. The UAPI layout is documented in Linux's [TCP header](https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/tcp.h); Nginx explains its [configuration and reload behavior](https://nginx.org/en/docs/beginners_guide.html).

The agent computes service counts before limiting detail rows and prioritizes listeners. It reports up to 256 port groups; detail queries contain at most 1,024 rows with explicit truncation. A per-port query filters on the server before the detail sample is bounded, so busy unrelated services cannot consume its whole sample. Other listener metadata may reserve part of that bound. Older agents remain usable with an explicitly partial summary and no scoped query support. Socket ownership is the kernel UID; for SSH it may be `root`/`sshd`, rather than the authenticated login user shown in Activity. The list covers the agent's network namespace; sockets inside separate Docker/container namespaces are not enumerated. TIME_WAIT and CLOSED entries are omitted.

Select **Cerrar conexión**, review both endpoints and the interruption warning, then **Confirmar cierre**. A fixed detail view does not expire an open confirmation after fifteen seconds; the server rechecks the exact tuple, inode and kernel cookie before requesting `SOCK_DESTROY`, so a stale selection cannot target a replacement socket. A disconnected or failed query disables actions until fresh data arrives. The current SSH transport is protected on both sides, including IPv4-mapped IPv6 addresses. Listening ports remain informational; closing an established connection leaves the owning process and listener running. A client can reconnect afterward: this is not an IP block or firewall rule. A lost acknowledgment is reported as unconfirmed and the close request is never replayed on reconnect.

The collector continues running as `remi` with its existing systemd restrictions. A separate channel on the same SSH session invokes the Rust `remi-agent connections` command. Inspection falls back to read-only operation when administrative access is unavailable. Full process visibility and closure use `sudo -n -- /usr/bin/remi-agent socket-helper` on demand, with bounded typed requests through stdin. Closing requires `CAP_NET_ADMIN`, a recognized observer connection and a kernel built with `CONFIG_INET_DIAG_DESTROY`; unsupported environments show a read-only explanation. No shell command, PID kill, wildcard-port filter, extra listener or automatic sudoers change is used. An existing administrative SSH account with passwordless sudo can operate the feature; other accounts retain read-only access unless an administrator deliberately configures a suitable policy.

Each close attempt and result records request ID, actor, endpoints, kernel cookie and outcome in the server's authpriv system journal, without passwords, key material, process arguments or packet contents:

```sh
sudo journalctl _COMM=remi-agent --since '15 minutes ago' --no-pager
```

Implementation references: Linux [socket diagnostics](https://www.man7.org/linux/man-pages/man7/sock_diag.7.html), [INET_DIAG UAPI](https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/inet_diag.h), and [TCP diagnostic destruction](https://github.com/torvalds/linux/blob/v6.1/net/ipv4/tcp_diag.c).

## Build

Use Rust 1.99 or newer with the committed lockfile; Linux binaries are built on Debian 12 for glibc compatibility. The host needs the usual OS build tools, not a JavaScript toolchain.

```sh
cargo test --workspace --locked
cargo build --release -p remi-desktop --locked
cargo xtask bundle
```

On Debian:

```sh
cargo build --release -p remi-agent -p remi-package --locked
cargo xtask deb --arch arm64
```

`xtask deb` checks the binaries' ELF architecture. Use `amd64` with x86-64 Linux builds. The Debian lifecycle executables (`postinst`, `prerm`, `postrm`) are also compiled Rust, not shell scripts. The installer delegates account and service management to Debian's own tools.

The local app bundle is ad-hoc signed. Public distribution requires an Apple Developer ID signature and notarization. The source build does not ship a production signing identity.

## APT distribution

A downloaded `.deb` alone does **not** subscribe the server to updates. The repository publisher generates signed metadata with a separately managed GPG release key:

```sh
cargo xtask apt --signing-key YOUR_GPG_FINGERPRINT --packages dist --output dist/apt
```

Run this on Debian with `dpkg-deb` and GnuPG installed. Serve `dist/apt/` over HTTPS. Distribute the public key over a trusted channel and configure a Deb822 `.sources` entry with `Types: deb`, the repository URL, `Suites: stable`, `Components: main` and a scoped `Signed-By: /etc/apt/keyrings/remi.asc`. Then:

```sh
sudo apt update
sudo apt install --only-upgrade remi-agent
```

This repository includes the generator; no public APT URL, production signing key or remote deployment is assumed. Retain previous packages for explicit version selection, and test state compatibility before downgrading.

## Layout

- `remi-core`: versioned protocol, trusted-journal parser, IP policy, atomic persistence.
- `remi-agent`: journal collector, bounded store, local stream, diagnostics and reader authorization.
- `remi-desktop`: Rust UI, verified SSH transport, macOS notifications and local history.
- `remi-package`: Debian lifecycle executables.
- `xtask`: app bundle, Debian archives and signed APT metadata.

Contributions target `staging`. Run formatting, Clippy, tests and applicable visible macOS acceptance flows before proposing changes. MIT licensed.

## Validation of this MVP

After merging [PR #1](https://github.com/clyra-dev/remi/pull/1), six additional desktop unit tests and two strengthened tests cover SSH path validation and trust-file preservation. The macOS workspace has **66 passing tests**, with one opt-in SSH test ignored; four manually introduced production faults were detected and reverted. See [SSH path and trust evidence](tests/SSH_PATHS.md) for exact commands, failures, recovery and limits.

The 2026-11-09 [mutation audit](tests/MUTATIONS.md) deliberately introduced 32 compiling behavioral faults: the original tests detected 18; strengthened tests detect all 32 in this curated sample. Two behavior-preserving controls still pass. Reproduce the native audit with `cargo xtask mutate`, or the Linux socket cases with `cargo xtask mutate --linux` inside a disposable Linux environment.

Service recognition 0.4.0 was checked on 2026-11-09 UTC with 57 passing macOS tests, 42 passing Linux tests, four manually introduced behavioral faults detected by unchanged tests, and visible acceptance against actual Debian testing; see [recognition evidence](tests/RECOGNITION.md) for commands, observed failures, restoration, UI checks and limits.

Service administration 0.3.0 was checked on 2026-11-09 UTC with 43 passing macOS tests, 30 passing Linux tests and visible interaction against the actual Debian testing server; see [service-view acceptance](tests/SERVICES.md) for stable detail, scoped queries, reconnect and disposable-session closure checks.

Connection control 0.2.0 was checked on 2026-11-06 with real Debian kernel sockets and visible macOS interaction; see [connection acceptance](tests/CONNECTIONS.md) for the checklist, permissions and environment limits.

Checked locally on 2026-11-05; see the feature-by-feature [acceptance report](tests/ACCEPTANCE.md) for methods, evidence and remaining checks:

- Formatting, Clippy with warnings denied, and 27 Rust tests pass on macOS; the 16 shared/agent tests also pass on Linux. Six opt-in live SSH configurations pass separately.
- ARM64 packages install on Debian 12 and 13.7; AMD64 installs on Debian 12 using Docker Desktop emulation. All start an unprivileged systemd service.
- Real OpenSSH logins over IPv4 and IPv6 are collected, including a login during downtime before the first stored event. Unauthorized socket readers are rejected.
- A signed, disposable local APT repository upgrades the agent while retaining edited configuration and history. A tampered signature is rejected. Reinstalling an administratively disabled service leaves it disabled and stopped.
- Visible native macOS interaction covers configuration, live SSH history, invalid CIDR rejection, allowed-IP classification, filtering, event details, demo, and reconnect/backlog recovery. macOS accepted the notification requests, and the user confirmed seeing a notification on screen.

The Debian test image is defined in `tests/debian/Dockerfile`; privileged containers are disposable test environments for systemd, not the recommended deployment. No production server was changed. Native notification-click reopening, tray-specific Quit, a physical sleep/wake cycle, Intel macOS and Debian 13 AMD64 still need their own acceptance runs. Menu-bar reopening was observed, and native app-menu Quit was tested. No public APT repository or notarized macOS release is published.
