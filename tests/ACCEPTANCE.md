# Remi MVP acceptance — 2026-11-05

This report distinguishes automated checks, actual Debian/OpenSSH integration, and visible macOS interaction. A successful notification submission is not proof that macOS displayed a banner or that clicking it reopened the app.

## Environment and scope

- macOS 26.6.2, Apple Silicon, Rust 1.99.1.
- Disposable Debian 12 ARM64, Debian 12 AMD64 (Docker Desktop emulation), and Debian 13.7 ARM64 systems, all with systemd and real OpenSSH.
- Local SSH ports 22293 and 22294; disposable keys and an isolated SSH agent. No production server was modified.
- The QA application used its own bundle identifier and `REMI_DATA_DIR`; the final `dist/Remi.app` was also opened and tested visibly.
- At the time of this acceptance run, `staging` was an unborn local branch with no remote; the run did not commit or push changes.

## Automated results

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked` passed.

The macOS suite has **27 passing tests**: 7 agent, 2 daemon process integration, 7 core, and 11 desktop/host-identity tests. The 16 shared/agent tests also passed on Linux. One opt-in live SSH test is excluded from ordinary runs and was explicitly executed successfully under **six configurations**: SSH agent, encrypted private key, wrong passphrase, rejected client key, changed host key, and revoked host key. Negative authentication configurations assert that the transport task terminates rather than retrying indefinitely.

Local evidence is in the ignored `.test/` directory: `rust-tests.log`, `clippy.log`, `linux-final.log`, and `live-*.log`. Disposable private keys are not part of the source tree or this report.

## Feature checklist

| Check | Result | Method and evidence |
| --- | --- | --- |
| Successful SSH detection, IPv4 | PASS | Real OpenSSH logins on Debian 12 and 13; daemon history and macOS UI agree. |
| Successful SSH detection, IPv6 | PASS | Real loopback `::1` logins on Debian 12 and 13; IPv6 event details visible in Remi. |
| Reject failed logins and spoofed syslog tags | PASS | A rejected client key and `logger -t sshd` fake success did not advance Debian 13's sequence; parser also checks trusted UID/command fields. |
| Other supported authentication message formats | PASS, parser level | Password and supported OpenSSH formats are parsed without retaining fingerprints; only public-key logins were exercised against real sshd in this run. |
| Agent and private-key authentication | PASS | Both selected and used through the visible UI; an encrypted key and the ordinary key file connected successfully. |
| Wrong passphrase / rejected client key | PASS | Visible actionable error; direct live tests verify permanent failures stop retrying. |
| First host trust | PASS | Native UI fingerprint prompt compared with the disposable server key; explicit trust created a private, durable known_hosts entry. |
| Changed and revoked host identity | PASS | Both errors displayed in the final app, with no trust-bypass button or authentication attempt; restoring the original test file restored connection. |
| known_hosts variants and file integrity | PASS, automated | Tabs/comments, case, hashed names, nonstandard ports, globs, negation, multiple valid keys, revocation precedence, CA markers and malformed files. |
| Invalid server settings | PASS | Port 0 rejected in the UI; automated validation also covers host, user, key path and networks. |
| First synchronization remains quiet | PASS | First QA connection restored 12 prior events with no historical notification batch. |
| Reconnection and missed events | PASS | Three logins while the UI was disconnected were recovered once, followed by the observer's own new login; the UI moved from 28 to 32 entries. |
| Recovery after service restart | PASS | The installed agent restarted and the desktop reconnected without resetting its cursor or duplicating history. |
| Manual disconnect | PASS | Visible stop; retry notices are cleared and the transport is cancelled. |
| Optional automatic connection | PASS | QA relaunched connected with the option on; final app launched disconnected with the option off. |
| Empty allowlist | PASS | New real events classified outside the list and submitted for notification. |
| IPv4/CIDR and IPv6 allowlists | PASS | `172.17.0.0/16` and `::1` saved visibly; two real matching events were allowed and did not notify. Mapped IPv6 addresses also covered by unit tests. |
| Invalid CIDR | PASS | `172.17.0.0/99` rejected visibly without replacing the saved policy. |
| All-login alert mode | PASS | Saved through the UI; six allowed connections still generated alerts. |
| Burst grouping | PASS, submission level | Six concurrent real logins became one `notification_batch count=6`; all six were retained. macOS accepted the request. |
| Notification authorization and test button | PASS, permission/submission level | User granted the initial macOS permission; UI showed authorized and the test button produced a successful native API completion. Earlier session included user confirmation of a visible notice. |
| Native notification click opens selected event | **NOT VERIFIED visually** | Navigation routing tests pass, but this run did not observe a native notification click or `notification_opened` callback. Native tools exposed the system's widget window and could not complete the panel/banner click flow. No simulated callback is counted as acceptance. |
| Search and unexpected-only filter | PASS | Visible empty result, clearing search, and toggling unexpected-only correctly hid allowed entries. |
| Event details | PASS | Native click displayed user, public-key method, source port, timestamp/timezone, classification and event number. |
| Desktop history and deduplication | PASS | Live recovery plus automated 2,000-entry cap, duplicate suppression and restart persistence. |
| Corrupted desktop history | PASS | Isolated QA history intentionally damaged; UI preserved the file and disabled saving/connecting; original bytes verified and backup restored. |
| Demo examples and isolation | PASS | Both demo buttons and ending demo exercised visibly; real history/cursor file remained byte-for-byte identical, with zero simulated entries. |
| Closing the window keeps monitoring | PASS | Native close produced `window_hidden`; subsequent real events were persisted and submitted for notification while hidden. |
| Menu-bar reopening | PASS, observed interaction | `tray_open` was logged at 20:22:09 UTC and the real UI reappeared with its prior filter. This was observed during user interaction, not performed by the automated controller. |
| Quit and relaunch | PASS | Native app-menu Quit and keyboard Quit terminated the QA process; relaunch retained settings/history. Tray-specific Quit was not separately clicked. |
| Full-screen layout | PASS | Native full-screen control exercised; navigation, status, search and event list remained visible. |
| Agent durable bounded history | PASS | Restart/duplicate tests plus real retention reduction from 14 entries to 10 immediately kept sequences 5–14 without changing identity/latest sequence. |
| Retention gap reporting | PASS | A stream requesting an expired sequence returned `gap=true`, `resync=false`. |
| Missing journal cursor | PASS | Actual journal rotation/vacuum on Debian 13 removed the cursor; agent logged `journal_cursor_missing`, doctor reported the gap, and subsequent real logins were collected. |
| Startup before first login | PASS, automated | Persisted observation start survives restart before the first event. |
| Malformed or oversized input | PASS, automated | Invalid journal data skipped; oversized journal record no longer hides the following record; protocol fragmentation, EOF, UTF-8 and size limits checked. |
| Corrupted agent store / failed writes | PASS, automated/process | Invalid state rejected without overwriting it; failed persistence does not advance sequence; second daemon cannot acquire the same state lock. |
| Unix socket access | PASS | State directory 0700, history 0600, socket 0660; unauthorized user rejected; `authorize` grants the intended reader group. |
| Reader privilege separation | PASS | Reader can stream Remi events but cannot read the system journal or authorize other users; invalid username rejected. |
| Unprivileged service | PASS | systemd reports `User=remi`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`; no additional TCP listener. |
| Crash recovery | PASS | Forced kill on disposable Debian 13 produced a new daemon PID through systemd; state count and sequence unchanged. |
| Diagnostics immediately after restart | PASS | Corrected a startup race; three immediate restart/doctor runs and reinstall/doctor passed. |
| Debian installation and architecture | PASS | Final ARM64 package installed on Debian 12/13 and AMD64 on Debian 12 emulation; doctor and authorized streams succeeded. |
| Disabled service remains disabled | PASS | Reinstallation on Debian 12 AMD64 preserved disabled/inactive state; explicit enable/start restored service. |
| Signed APT upgrade | PASS | Generated a disposable scoped-key repository; 0.1.0 → 0.1.1~qa upgrade preserved config/history checksums. |
| Altered repository signature | PASS | Changing signed Origin metadata caused APT signature verification failure; restoring signed metadata restored update success. |
| Remove, purge, reinstall | PASS | Remove stopped the service and preserved config/history; purge removed config and retained audit history/account; reinstall restored defaults and read retained history. |
| Package architecture guard | PASS | ARM64 ELF input rejected when asked to create an AMD64 package. |
| Logs and credential persistence | PASS | Key transitions, failures, batch sizes and trust decisions traced; disposable passphrases/private-key markers absent from desktop state/logs. |
| Final macOS bundle | PASS | Release build and `codesign --verify --deep --strict` passed; final bundle launched and connected through the real UI. |

## Corrections made during this review

1. Strict host-identity verification now respects revoked keys, multiple valid rotation keys, hashes, whitespace, host patterns and nonstandard ports; damaged files are not overwritten.
2. Configuration/authentication failures stop retrying and show actionable messages; network disconnections still retry. Manual disconnect clears obsolete retry notices.
3. Notification navigation clears conflicting filters, selects the correct real/demo event and requests scrolling; test/expired identifiers receive appropriate handling. This logic is tested, while its native click acceptance remains open.
4. The shared transport cursor is updated at Hello as well as at login receipt, and a failed preference save restores the prior policy.
5. Agent startup enforces reduced retention immediately, validates store identity/latest sequence, checks whether a saved journal cursor still exists, and discards oversized journal records without stalling collection.
6. `doctor` waits briefly for service/socket/collector readiness instead of incorrectly reporting failure immediately after a package restart.
7. Search now shows an explicit no-matches message; additional structured logs identify window/tray transitions and notification batch sizes.

## Remaining acceptance and boundaries

- Native notification-click navigation remains unverified; automated routing and API submission do not close this item.
- Tray-specific Quit, a physical Mac sleep/wake cycle, Intel macOS and Debian 13 AMD64 have not received their own acceptance runs.
- Native banner display also depends on macOS Focus and screen-sharing notification settings; those protections were not disabled. Temporary test changes to the notification shortcut checkbox and one hot corner were restored.
- The MVP detects successful SSH authentication, not generic TCP sessions, failed-authentication alerts, stolen-key intent or multiple servers.
- The package repository generator is tested; there is no published production APT endpoint. The macOS bundle is locally ad-hoc signed, not Developer ID notarized.
- These checks establish the observed behavior, not a guarantee of perfect operation in every environment.

## Reproduction and evidence

Run the regular suite with the commands above. The live transport test is explicitly opt-in:

```sh
REMI_QA_PORT=22293 \
REMI_QA_KNOWN_HOSTS=/absolute/path/to/test/known_hosts \
SSH_AUTH_SOCK=/absolute/path/to/isolated/agent.sock \
cargo test -p remi-desktop local_ssh_authentication_and_protocol -- --ignored --nocapture
```

Use `REMI_QA_KEY` and `REMI_QA_PASSPHRASE` for a disposable key-file scenario. `REMI_QA_EXPECT_ERROR` asserts a specific failure and termination of retries. Never point these fixtures at production.

Debian fixtures use `tests/debian/Dockerfile`, with `DEBIAN_VERSION=bookworm` or `trixie`. Tests require disposable systemd environments; privileged Docker containers are used only for acceptance, not recommended for deploying the agent.

Other local evidence: `.test/debian13-service-permissions.log`, `doctor-readiness.log`, `apt-lifecycle.log`, `remove-purge-reinstall.log`, `amd64-lifecycle.log`, `false-login-rejection.log`, and `desktop-qa/logs/`. Some logs retain an initial failed attempt followed by its corrected successful rerun; this report describes final results and identifies the startup-race fix above.

The final release app and both `.deb` archives were rebuilt/repackaged; final checksums are in `.test/final-artifacts.sha256` and were verified. Test containers and the isolated SSH agent were stopped. The QA app was quit, test state/known_hosts restored, and the final app left open in explicitly labeled demonstration mode.
