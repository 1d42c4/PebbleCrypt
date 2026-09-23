# PebbleCrypt

A small, offline Windows desktop file encryption app written in Rust, inspired by PicoCrypt's straightforward workflow.

This repository distributes source code only. Compile the Windows app locally using the instructions below; executables and build outputs are excluded from Git.

## Build and test

On 64-bit Windows 10/11, install Rust 1.95 or newer with the MSVC toolchain, Visual Studio C++ build tools, and the Windows SDK. Open PowerShell in the directory containing `Cargo.toml`:

```powershell
cargo build --release --locked
./test.ps1
```

Double-click `target\release\pebblecrypt.exe` to open the graphical app. Alternatively, `./build.ps1` builds, tests, and places a local copy at `dist\PebbleCrypt.exe`. Neither location is tracked by Git. No installer or administrator access is needed to run the app.

## Run

After compiling, double-click **pebblecrypt.exe**. The application opens a normal Windows window and needs no terminal or account. Locally built executables are unsigned.

The compact window opens at 480 × 540 logical pixels (scaled by Windows display settings), and can be resized down to 440 × 460. Longer file lists scroll within the window.

1. Drag files into the window, or select **Browse files** (Ctrl+O).
2. Choose **Encrypt files** or **Decrypt files**. Adding only `.age` files to an empty queue automatically selects decryption.
3. Enter the password. Encryption requires at least 12 characters and matching confirmation. Use a long, unique passphrase, or **Generate password** for a random 24-character password. Save generated passwords before starting.
4. Optionally choose an output folder. By default, results are saved beside each original.
5. Click **Encrypt files** or **Decrypt files**. **Show output folder** opens the result location; expand **Completed files** to see all result paths.

Multiple files are processed individually. Zip a folder first if you want a single encrypted archive. File arguments are also accepted when files are dropped onto the executable; the program still opens a normal graphical window.

## File behavior

- Originals are always kept. The app never deletes or overwrites your original data.
- `notes.txt` becomes `notes.txt.age`. Decrypting restores `notes.txt` when that name is free.
- If a filename is taken, a suffix is chosen, for example `notes (decrypted).txt`. A second no-overwrite check protects against files appearing during processing.
- A batch stops at its first error. Successfully completed files remain available and are listed in the app.
- Cancel stops the current file and remaining files. Password derivation cannot be interrupted internally; cancellation waits for that short step to finish.
- Closing the window while busy is blocked. Cancel the job and wait for cleanup before closing.

## Encryption and compatibility

The app uses the [Rust age library](https://docs.rs/age/0.12.1/age/) and the [age v1 format](https://age-encryption.org/v1), not a custom cipher or container. Password-based encryption uses scrypt with N=2^18, r=8, p=1 (about 256 MiB) and authenticated ChaCha20-Poly1305 streaming encryption. Each encryption uses fresh library-generated randomness.

PebbleCrypt writes binary, password-encrypted `.age` files and opens that same format, including compatible password files from age/rage. It does not open PicoCrypt `.pcv` files, ASCII-armored age files, or recipient-key-encrypted age files. The scrypt decryption work factor is capped at 20 (about 1 GiB), and input headers are limited to 64 KiB.

## Practical security limits

Version 0.1.2 includes a code review, regression fixes, and 104 automated tests; see [AUDIT.md](AUDIT.md) for findings and limitations. This application has not been independently security-audited. Keep backups and verify a decrypt cycle with noncritical data before relying on it.

- There is no password recovery. Passwords are not saved in app settings, files, or logs.
- Password fields and the main copy buffer are zeroized when cleared/released; UI undo state is discarded on job start, password generation, mode changes, and clearing the queue. This is best-effort memory handling: other I/O buffers, GUI allocations, the OS, swap, clipboard, and crash dumps can retain copies.
- All work happens locally; the app has no network feature, telemetry, account, or updater.
- Names and approximate sizes remain visible. Rename an encrypted file if its name reveals sensitive information. Original timestamps and filesystem metadata are not restored on decryption.
- Decryption writes authenticated chunks to a randomly named `.pebblecrypt-*.partial` temporary file **in the output folder**. It publishes the final filename only after complete authentication and a successful flush. Errors/cancellation attempt to remove the temporary file; if deletion fails, the error includes its full path. A crash, forced termination, or power loss can also leave it behind. That temporary file can contain plaintext. Use an output folder with appropriate permissions, preferably on an encrypted disk; avoid shared/synchronized folders if partial plaintext must never be exposed there.
- Temporary-file deletion is not secure erasure. The app does not shred files or protect against malware, administrator access, screen capture, or a compromised operating system.
- On Windows the source file is opened without write/delete sharing during processing to prevent concurrent modification.

## Development

Run `./test.ps1` for formatting, Clippy, and the full test suite, or `./test.ps1 -Offline` once dependencies are cached. Tests use temporary directories and never use your personal files. One end-to-end test exercises the actual worker thread and production password derivation; most mutation tests use a lower test-only factor for speed.

Windows resources and the icon are included. The app uses egui/eframe with a native Windows window and OpenGL renderer; it is not a browser or CLI wrapper. Run `cargo clean` to remove Cargo build files. If you used `build.ps1`, the separate local `dist` copy remains ignored by Git.

The code is split into `src/main.rs` (window and worker), `src/batch.rs` (batch results and cancellation), and `src/crypto.rs` (file processing and naming). Dedicated test modules cover the UI, batch behavior, and file-processing edge cases. Do not weaken the production scrypt factor to speed up tests; test-only calls already use a lower factor while production-parameter tests verify the shipped value.

## License and reference

MIT. Dependency license notices are included in [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt). [PicoCrypt](https://github.com/Picocrypt/Picocrypt) is the workflow inspiration; this is a separate implementation and is not affiliated with that project.
