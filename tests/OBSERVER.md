# Own-session alerts 0.2.1 — acceptance, 2026-11-08

Remi previously notified every successful SSH authentication, including its own reconnections after sleep or network loss. Version 0.2.1 keeps identified observer logins in history without notifying or adding them to the outside-allowlist count. Independent SSH sessions from the same IP, account and key still follow the configured policy.

## Automated checks

- [x] macOS workspace: **39 passing tests**, with the existing opt-in SSH fixture test excluded.
- [x] Debian build environment: **28 passing agent/core/integration tests**; the unrelated destructive socket test remains explicitly excluded.
- [x] Formatting, diff whitespace checks and Clippy with warnings denied on macOS and Linux.
- [x] Own-session matching requires the source endpoint, trusted journal boot ID/PID/monotonic timestamp and actual SSH process ancestry.
- [x] Different source IPs/ports, another process, a different boot and a reused PID/port predating the current process do not match.
- [x] IPv4-mapped IPv6 sources match the equivalent IPv4 observer endpoint.
- [x] Missing/invalid identity metadata preserves ordinary alerts; untrusted `SYSLOG_PID` cannot replace the trusted `_PID` field.
- [x] An SSH environment variable alone cannot establish observer identity; simulated streams remain simulated and are not silenced as observer sessions.
- [x] Old frames/history load without new metadata and retain their existing classification.
- [x] Both alert modes, first-sync suppression, allowlist behavior and persistence retain their intended behavior.
- [x] Apple Silicon app and Debian AMD64/ARM64 packages build successfully with the locked dependencies.

## Visible macOS acceptance against real Debian testing

Performed through native clicks, accessibility observations and screenshots in the user's actual app; SSH/log checks below complement those UI checks.

- [x] Desktop 0.2.1 opens the existing history and connects using the existing server settings.
- [x] Before the agent upgrade, the older agent remains usable and the desktop explains that it cannot identify its own session; ordinary alerts remain enabled.
- [x] Following the agent upgrade, automatic reconnection returns to **Vigilando**, clears the identification notice and displays **Conexión de Remi · registrada sin aviso**.
- [x] Native **Desconectar / Conectar** creates another identifiable, quiet observer login.
- [x] **Solo fuera de mi lista** hides observer rows and retains independent logins; restoring the filter reveals the observer rows again.
- [x] An independent real SSH login using the same source IP, account and key appears outside the allowlist; the outside-list count increases by one.
- [x] A real independent login while the desktop is disconnected is recovered on reconnect; it generates one notification request and the new observer login remains quiet.
- [x] Quitting and reopening the app preserves the observer labels and creates another quiet observer login.
- [x] Preferences still show the original all-logins policy, an unchanged empty allowlist and authorized macOS notifications; the UI explains the observer-session exception.
- [x] Installation help shows the current 0.2.1 package version.
- [x] **Conexiones** still loads live sockets and marks the current transport **Remi · protegida**.
- [x] The app is left open on Activity, connected to real testing, with the newest observer event selected.

Local logs and persisted state corroborate four observer logins with `observer=true`, `reason="observer_session"`, `alert=false` and `notified=false`; two independent test logins have `observer=false`, `alert=true` and `notified=true`. Neither history nor sequence IDs were duplicated. Both independent notification requests were accepted by macOS. A fresh OS banner and notification-click navigation were not visually verified in this run; the real app history, details, counts, filters and connection states were verified on screen.

## Deployment and traceability

- [x] Testing upgraded from 0.2.0 to 0.2.1 using the checksum-verified AMD64 `.deb` through APT.
- [x] `remi-agent doctor` passes and the collector is active.
- [x] Agent identity, every pre-upgrade event and the configuration file are preserved; private local/server backups were retained.
- [x] Desktop settings and all pre-upgrade history are preserved.

The shared collector stores optional trusted journal origin metadata, never a global observer flag. Each SSH stream annotates its own login using its actual process ancestry. Identification failures retain normal alert behavior. Logs include `observer_identity_checked`, `observer_identity_unavailable`, `observer_login_identified`, `observer_identity_received` and a classification `reason` on `login_evaluated`; they do not include key contents, fingerprints, command arguments or journal message bodies.

Old history is not retroactively silenced or relabeled. No IP allowlist, SSH setting, firewall rule or sudoers policy was changed. A physical sleep/wake cycle was not induced during this run; reconnection was tested through the agent upgrade, native disconnect/connect and app restart. Debian 13-specific SSH process layouts and Intel macOS were not newly exercised for this change. Socket destruction was not repeated because its implementation was unchanged; see [connection acceptance](CONNECTIONS.md).
