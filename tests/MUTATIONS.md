# Mutation audit — 2026-11-09

The original tests detected **18 of 32 deliberately introduced behavioral faults**. Fourteen faults survived. After strengthening the tests, the same **32 of 32 faults are detected**, while two behavior-preserving controls still pass. Every counted fault compiled successfully before a test failed.

This is a curated sample, not a repository-wide mutation coverage percentage or proof that every bug is caught. The initial application/test source was commit `e8332a7ee6ff516f04f92262af36a932927847b6` (0.3.0). The mutations are exact, reviewable replacements in [the Rust audit runner](../xtask/src/mutation.rs).

| Test scope | Real faults | Detected originally | Detected after improvements |
| --- | ---: | ---: | ---: |
| Unit suites: shared core, desktop model, agent and Linux socket unit checks | 29 | 18 | 29 |
| Linux TCP control integration | 3 | 0 | 3 |
| Total sampled faults | 32 | 18 | 32 |
| Behavior-preserving controls, excluded above | 2 | Both acceptable | Both pass |

## What the audit found

- **Request identity was inadequately tested.** The old wrong-ID case also supplied the wrong port. Removing the ID check still passed because the port check rejected the reply. The test now varies each independently, tests both invalid together, and verifies the valid case succeeds.
- **Destructive-action state had gaps.** Tests now reject closure when the transport is disconnected, after a failed read, and when an acknowledgment identifies a different socket; successful refresh restores actions. A socket without an inode is rejected independently of its other valid identity fields.
- **The service view lacked behavioral assertions.** Tests now exercise hidden internal services, explicit inclusion, case-insensitive search and mixed loopback/network bindings. Inventory limits preserve full counts even when some services are omitted from the detail.
- **Protocol limits were tested with the wrong stimulus.** The old oversized input had no newline, so even a broken size guard rejected it as incomplete. Tests now supply complete frames below, at and above the limit, with several buffer sizes, including one byte per read.
- **Low-traffic Linux fixtures hid the original truncation failure.** A scoped-query test now has an unrelated listener. A second test holds 1,056 real loopback connections to a busy lower port plus an independent target connection: the full summary must count all of them and a scoped query must still return the target listener and session. Reintroducing late counting yields 1,022 instead of 1,056; reintroducing late filtering yields only one of the target's two rows.
- **An observer timestamp boundary was missing.** A login at the SSH process's start tick is accepted; an earlier login is rejected, across several PID/timestamp combinations.

Seven new unit tests and one new integration test were added, and three existing tests were strengthened. The order-stability test compares socket identities across changes in input enumeration and TCP state; it does not require one arbitrary ascending ordering.

## Controls and classification

`E01` changes `counter += 1` to `counter = 1 + counter`; it passes before and after. `D06` reverses the stable endpoint ordering. Manual review classified `D06` as an acceptable alternative, because the contract requires stable ordering, not one particular direction. Its initial raw result remains **survived** in the evidence; it is excluded from the real-fault denominator and subsequently labeled a negative control. No assertion was added merely to reject this harmless alternative.

There were **zero compile-invalid mutations and zero timeouts** in the completed before/after campaigns. A compile error, timeout, empty suite or unrelated execution failure cannot count as a detected mutation. A nonzero exit is accepted as detection only after compilation succeeds and the test output contains a named failed test.

## Reproduce

From the repository root on macOS, first populate the normal dependency/build cache:

```sh
cargo test --workspace --locked
cargo xtask mutate
cargo xtask mutate --only D04,D06 --label focused
```

For the Linux cases, use a disposable Linux environment with the repository, Git and the Rust toolchain available:

```sh
cargo test -p remi-agent -p remi-core --locked
cargo xtask mutate --linux
```

The runner copies Git-tracked and non-ignored source files into `.test/mutations/`, establishes a passing baseline, applies one production-code replacement at a time, compiles and runs the selected suite, restores the source, and finishes by rerunning the restored baseline. The normal checkout is never mutated. Compilation and test output, the isolated sources and a JSON result ledger are retained under that ignored directory. Each command runs offline with the lockfile; missing dependencies fail the baseline rather than appearing as a detection. A 180-second limit terminates the command's process group and records a timeout separately.

The Linux load fixture uses only sockets owned by the test on loopback. It raises only its own process's soft descriptor limit when necessary, preserving the existing hard limit. The low-soft-limit path was also exercised successfully starting at 1,024 descriptors. A hard limit of at least 2,240 is required for this fixture.

## Evidence and final validation

The JSON files retain each exact production patch, package/target, observed outcome and names of the tests that failed:

- [Original macOS results](mutations/before-macos.json)
- [Original Linux results](mutations/before-linux.json)
- [Final macOS results](mutations/after-macos.json)
- [Final Linux results](mutations/after-linux.json)
- [Comparison summary and source hashes](mutations/summary.json)

The comparison verifies that all 34 production patches are identical in both rounds; only test coverage and the explicit classification of `D06` changed.

Normal, unmutated verification passes: **50 tests on macOS** and **34 on Linux**, plus formatting and Clippy with warnings denied. The opt-in live SSH test and destructive kernel unit test remain excluded; this audit does not claim those passed. No real SSH server is contacted by the mutation campaign, and no mutant app or agent is deployed. The modified application files' production sections are byte-identical to the starting commit; application changes are entirely inside test modules. Runtime version remains 0.3.0.

This audit tests unit behavior and three Linux TCP protocol mutations. It does not repeat native UI acceptance, notification delivery, sleep/wake handling or privileged socket destruction; those retain their separately documented scope in [service acceptance](SERVICES.md), [connection acceptance](CONNECTIONS.md) and [MVP acceptance](ACCEPTANCE.md).
