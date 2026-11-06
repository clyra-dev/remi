# Remi

**Remote Event Monitoring Interface.** A small macOS companion for SSH access on your Debian server.

Source: [clyra-dev/remi](https://github.com/clyra-dev/remi). The default integration branch is `staging`.

All application, interface, transport, agent, packaging-helper and build-tool code is Rust. The macOS app uses egui/eframe, AppKit's menu bar, UserNotifications and russh. The Debian agent uses the system journal. No web frontend, cloud account or additional TCP listener is required.

## MVP

- One Debian server; successful SSH authentication (IPv4 / IPv6).
- Native macOS notifications, history, server status and an explicit demo mode.
- All-login alerts or IP/CIDR allowlists; first-sync history is quiet, missed subsequent events are recovered.
- Dedicated `remi` service account, durable bounded history, systemd service, `.deb` lifecycle, signed APT repository generation.
- SSH host identity verification and authentication using an SSH agent or private-key file. Passphrases are held in memory, never persisted.

Generic TCP connection detection and multiple servers are the next iteration. This version reports policy deviations; it cannot identify whether a valid SSH credential was stolen. A compromised root account can tamper with local telemetry.

## Install on Debian

Supported packaging targets: Debian 12 / 13, `arm64` and `amd64`, with systemd and OpenSSH. Use the package matching your machine (`dpkg --print-architecture`).

```sh
sudo apt install ./remi-agent_0.1.0_arm64.deb
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

The SSH connection opened by Remi is itself a successful login and is recorded. Permit your Mac's public IP/network if these accesses should be quiet. Policies classify events when they arrive; changing a policy does not rewrite the classification of old history. Closing the app pauses desktop alerts while the server continues collecting.

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

Checked locally on 2026-11-05; see the feature-by-feature [acceptance report](tests/ACCEPTANCE.md) for methods, evidence and remaining checks:

- Formatting, Clippy with warnings denied, and 27 Rust tests pass on macOS; the 16 shared/agent tests also pass on Linux. Six opt-in live SSH configurations pass separately.
- ARM64 packages install on Debian 12 and 13.7; AMD64 installs on Debian 12 using Docker Desktop emulation. All start an unprivileged systemd service.
- Real OpenSSH logins over IPv4 and IPv6 are collected, including a login during downtime before the first stored event. Unauthorized socket readers are rejected.
- A signed, disposable local APT repository upgrades the agent while retaining edited configuration and history. A tampered signature is rejected. Reinstalling an administratively disabled service leaves it disabled and stopped.
- Visible native macOS interaction covers configuration, live SSH history, invalid CIDR rejection, allowed-IP classification, filtering, event details, demo, and reconnect/backlog recovery. macOS accepted the notification requests, and the user confirmed seeing a notification on screen.

The Debian test image is defined in `tests/debian/Dockerfile`; privileged containers are disposable test environments for systemd, not the recommended deployment. No production server was changed. Native notification-click reopening, tray-specific Quit, a physical sleep/wake cycle, Intel macOS and Debian 13 AMD64 still need their own acceptance runs. Menu-bar reopening was observed, and native app-menu Quit was tested. No public APT repository or notarized macOS release is published.
