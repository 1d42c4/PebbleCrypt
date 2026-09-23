# PebbleCrypt 0.1.2 review and regression report

Reviewed 2026-09-23. This is an AI-assisted source review and functional/security regression exercise, not an independent professional security audit or cryptographic certification.

## Result

- **104 tests pass** on Windows x64 in release mode: 96 added to the original 8.
- Formatting and Clippy pass, with warnings treated as errors.
- The native Windows executable was opened and visually checked; password generation and switching modes were exercised in the compact window. Build toolchain: Rust 1.98.0, `x86_64-pc-windows-msvc`.
- Production encryption remains binary password-based age with scrypt work factor 18. The compact 480 × 540 window is retained.
- `cargo-audit 0.22.2` reports **0 known vulnerabilities and 0 warnings** across 454 locked dependencies. RustSec database: 1,267 advisories, revision `1e640cd56d7604993e3a9ec392060666e3b95ccc`, updated 2026-09-23. No advisories were ignored. This is a point-in-time advisory check, not proof that dependencies have no defects. See the [RustSec advisory database](https://rustsec.org/).

## Findings addressed

| Finding | Impact | Resolution and evidence |
| --- | --- | --- |
| Temporary-file deletion errors could be silently ignored | A failed decryption/cancellation could leave partial plaintext without explaining where it was left | Explicit cleanup checks report the complete temporary path and plaintext warning. A Windows test prevents deletion with an open handle and verifies the warning. |
| Cancellation could hide another error | A cleanup or disk failure could appear to be an ordinary cancellation | Only a clean cancellation result is suppressed; disk errors, cleanup errors, and panics remain visible. Batch tests cover these races and preserving earlier completed files. |
| Password state outlived some UI actions | Clearing files, switching mode, or generating another password could retain stale fields or undo history | These actions now clear password state and discard the corresponding text-edit undo state. UI state tests and simulated button clicks cover the behavior. |
| Relative paths and repeated inputs were not robust at the processing boundary | Direct calls could fail to create a temporary file beside a relative input, or schedule duplicate work | Job planning canonicalizes input/output folders and deduplicates canonical source paths. Both cases have regression tests. |
| Interrupted reads were treated as fatal; empty header reads violated the `Read` contract | Recoverable I/O interruption could fail a job; an empty read at the header limit could return an error | Interrupted reads retry and empty reads return zero. Regression tests first reproduced both old behaviors. |
| A failed worker-thread launch was not handled gracefully | Resource exhaustion could panic instead of leaving the window usable | Fallible thread creation now reports an error and releases the busy state. The actual thread/channel path is tested end to end; OS thread-creation exhaustion itself was not forced. |
| Filesystem metadata was read during every repaint | Slow or unavailable storage could make the window unnecessarily sluggish | Display sizes are cached when files are added. Processing still reads current file metadata. A test removes a selected source and verifies rendering uses the cache. |
| Output-path edge cases needed earlier checks | Overlong names failed late; dangling links should reserve their names | Output components are length-checked before password derivation and `symlink_metadata` checks occupancy. Windows filename lengths, collisions, and hard-link preservation are tested; creating dangling Windows symlinks was not required/tested. |

No cipher or file-format replacement was introduced. Encryption/authentication remains delegated to the [age Rust library](https://docs.rs/age/0.12.1/age/) implementing the [age v1 specification](https://age-encryption.org/v1).

## Test coverage

- **Encryption and authentication:** empty, binary, Unicode, multiple chunk boundaries, a 32 MiB file, randomized round trips, production scrypt headers, distinct ciphertext for repeated encryption, wrong passwords, password whitespace, recipient-key rejection, header-size and scrypt-work limits.
- **Damaged/untrusted inputs:** one mutation at every byte position of a small ciphertext; every truncation of that ciphertext; appended bytes; swapped/duplicated chunks; cross-file payload splicing; a 256-entry deterministic malformed-header corpus. Failure checks verify that final outputs are absent and temporary files are cleaned up.
- **Filesystem behavior:** originals remain unchanged, no overwrite even when a destination appears during processing, filename collisions, case-insensitive suffixes, Unicode names, missing inputs/folders, output equal to source, hard links, Windows source write/delete locks, failed temporary cleanup, pre-start/mid-stream/post-commit cancellation.
- **I/O faults:** interrupted/short reads, short writes, zero-byte writes, simulated disk-full and read errors. These are controlled fault injections; they do not fill the user's disk.
- **Batch behavior:** first-error stop, panic containment, completed-file preservation, cancellation boundaries, progress order, cancellation/error races.
- **GUI:** validation, generated-password confirmation, password and undo clearing, file selection, duplicate size counting, mode selection, busy-state handling, worker disconnection, result display, and simulated Generate/Decrypt/Clear/Cancel clicks. Rendering tests check key controls at the compact size and long filenames at minimum width.
- **Actual background worker:** encrypts two files using production settings, decrypts them byte-for-byte through a new app instance, then verifies a partially successful batch containing a damaged second file. This exercises the real thread, channels, filesystem, crypto, and UI state together.

There are 104 named tests, some containing many input cases. No statement-count/branch-coverage percentage was measured. Library interoperability tests use direct calls to the same Rust age implementation; they are not a comparison with an independently implemented Go age executable.

## Run the checks

From the source directory with Rust/MSVC build prerequisites installed:

```powershell
./test.ps1
# Once dependencies are cached:
./test.ps1 -Offline
cargo build --release --locked
```

`test.ps1` runs `cargo fmt --all -- --check`, `cargo clippy --all-targets --release --locked -- -D warnings`, and `cargo test --release --locked`. The tests create disposable temporary files; they do not encrypt existing personal files. The production-parameter checks need several hundred MiB of memory.

For a fresh dependency scan, install the official cargo-audit tool and run:

```powershell
cargo install cargo-audit --locked
cargo audit --file Cargo.lock
```

Captured test output and the machine-readable dependency scans are included under `audit/`. `dependency-audit.json` is the initial fresh scan with database revision metadata; `dependency-audit-final.json` rechecks the final lockfile against that same database using `--no-fetch --no-yanked`. Dependencies did not change during the review (only the app's own version changed). Local workstation paths in the published test logs have been replaced with placeholders. These tools are for development; using the compiled graphical app does not require Rust or a terminal.

## Remaining limits and untested conditions

- Decryption temporarily stores authenticated plaintext chunks in the output folder before complete-file authentication finishes. Cleanup can fail, and crashes, forced termination, power loss, or some panics may leave a `.pebblecrypt-*.partial` file. Ordinary cleanup failures are reported; removal is not secure erasure. The final requested filename is committed only after full authentication and successful flush/sync.
- Use an output folder whose access controls you trust. This review does not claim protection against a hostile process sharing that folder, malware, an administrator, filesystem replacement races, or a compromised OS.
- Clearing secrets and undo state is best effort. Other I/O buffers, GUI allocations, clipboard, swap, and crash dumps can retain data; comprehensive memory-forensics testing was not performed.
- Password derivation cannot be interrupted internally. Encryption uses about 256 MiB; accepted decryption can request about 1 GiB. Extreme memory exhaustion, OS-wide resource starvation, network-share faults, actual full disks, power-loss recovery, and every display/GPU combination were not tested.
- Deterministic mutation cases are useful regression checks, not an exhaustive fuzz campaign or proof of cryptographic correctness. No third-party penetration test or independent cryptanalysis was performed.
- The executable remains unsigned. Password recovery, secure shredding, and PicoCrypt `.pcv` compatibility are outside the app's supported features.

Keep backups and validate a decrypt cycle with representative noncritical data before relying on any new release.
