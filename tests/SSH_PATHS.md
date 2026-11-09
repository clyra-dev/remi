# SSH paths and trust records — unit-test evidence, 2026-11-09 UTC

[PR #1](https://github.com/clyra-dev/remi/pull/1) was merged into `staging` first, at `de18aa642ca41698eab85b73dd30088001a0cb24`. This follow-up adds six unit tests and strengthens two existing tests; it changes no production code or dependencies.

## Behavioral coverage

- [x] An existing private-key file with a relative path is rejected. The same file with an absolute path is the valid control, so a missing-file error cannot mask a missing absolute-path check.
- [x] Agent authentication ignores unused private-key paths, including empty and invalid paths, while still requiring an absolute `known_hosts` path.
- [x] Pasted paths lose surrounding whitespace but preserve internal spaces. A new `known_hosts` file is permitted, and validation alone does not create it.
- [x] Approving a fingerprint rejects a changed host and a changed port independently; the other field remains valid in each case. Rejections create no trust file, and the matching endpoint succeeds.
- [x] Trust uses the trimmed destination, preserves unrelated records and comments, and remains idempotent when approved twice.
- [x] Revoked, changed and malformed identities keep their specific rejection messages and preserve the trust file byte for byte. An invalid presented public key also leaves the file unchanged; a valid key then succeeds.
- [x] Settings are validated again before persisting a fingerprint. The negative test owns a unique temporary relative destination, even if broken code writes to it; fixing only that path permits approval.
- [x] A denied write identifies the destination and permission problem, leaves no partial record, and succeeds after permissions are restored.

Temporary files are isolated and cleaned by their owners. Tests do not change the process working directory or environment, contact a server, read a personal SSH key, or write the user's trust store. Expected records are derived from explicit public-key and endpoint fixtures, not by calling the formatting code under test.

## Automated verification

- macOS desktop: **31 passed**, one existing opt-in live SSH test ignored.
- macOS workspace: **66 passed**, the same opt-in test ignored.
- Clippy with warnings denied, formatting and whitespace checks passed.

```sh
cargo test -p remi-desktop --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

## Manual challenges

Tests and their fixtures were copied into a disposable worktree at `.test/pr-1-unit-audit`. Each direct test passed before its fault was introduced. Production code was edited manually, one fault at a time; all four faulty versions compiled successfully. Each unchanged test then failed for the behavior below, with exit status 101 and exactly one executed, failing test. The production fault was reverted and the same test passed again. No assertions or fixtures were edited during these sequences, and no automated mutation runner was used.

| Behavior | Temporary production fault | Observed failure | After restoration |
| --- | --- | --- | --- |
| Existing relative keys must be rejected | Removed the absolute private-key path guard | Validation returned `Ok(())`; `unwrap_err()` failed | 1 passed |
| Pasted paths must trim surrounding whitespace | Removed `let path = path.trim();` | Expanded path retained the leading space/tab and trailing space/newline; exact comparison with the fixture path failed | 1 passed |
| Either endpoint change invalidates a fingerprint | Changed the host/port mismatch condition from `\|\|` to `&&` | A changed host with an unchanged port was accepted; `unwrap_err()` failed | 1 passed |
| Settings must be revalidated before trust is saved | Removed `settings.validate()?` from `trust_host` | A relative trust destination was accepted and written; `unwrap_err()` failed | 1 passed |

These exact test commands were each used before the edit, with faulty production code, and after restoration, from the disposable worktree. `CARGO_TARGET_DIR` pointed to the main checkout's `target` directory to reuse compiled dependencies.

```sh
cargo test -p remi-desktop model::tests::existing_relative_private_key_is_rejected_independently_of_file_presence --bin remi --locked -- --exact
cargo test -p remi-desktop model::tests::padded_paths_preserve_internal_spaces_and_allow_a_new_known_hosts_file --bin remi --locked -- --exact
cargo test -p remi-desktop transport::tests::trust_rejects_changed_host_and_port_independently_without_writing --bin remi --locked -- --exact
cargo test -p remi-desktop transport::tests::trust_validates_settings_before_writing_known_hosts --bin remi --locked -- --exact
```

After the challenges, all three Rust files in the disposable worktree matched the working sources byte for byte. The production portion of each working file also matched the merged PR. A subsequent test-comment clarification did not alter assertions or fixtures.

## Limits

This is unit-level evidence, including real temporary filesystem writes; it is not an SSH authentication, network integration or visible UI acceptance run. This follow-up did not deploy a server or reinstall the desktop app. The opt-in live SSH test is excluded from the passing count. The Unix permission-denial test assumes an unprivileged user; root can bypass directory permissions. The four manual challenges demonstrate detection of those sampled faults, not universal correctness or an exhaustive mutation score.
