//! File operations around the age library. No home-grown cryptographic primitives.
use age::secrecy::{ExposeSecret, SecretString};
use std::{
    cell::Cell,
    collections::HashSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

pub const WORK_FACTOR: u8 = 18; // scrypt N=2^18, r=8, p=1 (~256 MiB).
const MAX_WORK_FACTOR: u8 = 20; // Bound memory/CPU for untrusted files (~1 GiB).
const BUFFER_SIZE: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mode {
    #[default]
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct Job {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn generated_password() -> Result<String, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut random = Zeroizing::new([0u8; 24]);
    getrandom::fill(random.as_mut())
        .map_err(|e| format!("Windows random generator failed: {e}"))?;
    // The alphabet size divides 256, so masking introduces no bias (144 bits).
    Ok(random
        .iter()
        .map(|b| ALPHABET[(b & 63) as usize] as char)
        .collect())
}

pub fn plan_jobs(
    files: &[PathBuf],
    destination: Option<&Path>,
    mode: Mode,
) -> Result<Vec<Job>, String> {
    if files.is_empty() {
        return Err("Choose at least one file.".into());
    }
    if destination.is_some_and(|p| !p.is_dir()) {
        return Err("The output folder is unavailable. Choose another folder.".into());
    }
    let destination = destination
        .map(fs::canonicalize)
        .transpose()
        .map_err(|e| format!("Could not resolve the output folder: {e}"))?;
    let mut reserved = HashSet::new();
    let mut seen_inputs = HashSet::new();
    let mut jobs = Vec::new();
    for input in files {
        if !input.is_file() {
            return Err(format!(
                "Not an available file: {}. Zip folders before adding them.",
                input.display()
            ));
        }
        let input = fs::canonicalize(input)
            .map_err(|e| format!("Could not resolve the source file: {e}"))?;
        if !seen_inputs.insert(input.clone()) {
            continue;
        }
        let folder = destination
            .as_deref()
            .unwrap_or_else(|| input.parent().expect("canonical file has a parent"));
        let name = input.file_name().ok_or("This file has no name.")?;
        let wanted = match mode {
            Mode::Encrypt => {
                let mut n = name.to_os_string();
                n.push(".age");
                n
            }
            Mode::Decrypt => {
                if input
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("age"))
                {
                    input.file_stem().unwrap_or(name).to_os_string()
                } else {
                    let mut n = name.to_os_string();
                    n.push(".decrypted");
                    n
                }
            }
        };
        let mut candidate = folder.join(&wanted);
        for index in 1..=10_000 {
            if filename_length(candidate.file_name().expect("output filename")) > 255 {
                return Err(format!(
                    "The output name for {} would be too long. Shorten the source filename or choose another output folder.",
                    input.display()
                ));
            }
            let key = candidate.to_string_lossy().to_lowercase();
            if !path_occupied(&candidate)? && reserved.insert(key) {
                break;
            }
            if index == 10_000 {
                return Err("Too many files have the same output name.".into());
            }
            let base = Path::new(&wanted);
            let mut next = OsString::from(base.file_stem().unwrap_or(&wanted));
            let action = if mode == Mode::Encrypt {
                "encrypted"
            } else {
                "decrypted"
            };
            next.push(if index == 1 {
                format!(" ({action})")
            } else {
                format!(" ({action} {index})")
            });
            if let Some(ext) = base.extension() {
                next.push(".");
                next.push(ext);
            }
            candidate = folder.join(next);
        }
        jobs.push(Job {
            input,
            output: candidate,
        });
    }
    Ok(jobs)
}

fn filename_length(name: &std::ffi::OsStr) -> usize {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        name.encode_wide().count()
    }
    #[cfg(not(windows))]
    {
        name.as_encoded_bytes().len()
    }
}

// Unlike Path::exists, this also reserves dangling symlinks/reparse points.
fn path_occupied(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Could not inspect the output path: {e}")),
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Cancelled.".into())
    } else {
        Ok(())
    }
}

// age accepts general recipient headers; this app caps the parser's input before
// it can allocate unbounded memory from a deliberately oversized header.
struct HeaderLimited<R> {
    inner: R,
    active: Rc<Cell<bool>>,
    remaining: usize,
}

impl<R: Read> Read for HeaderLimited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.active.get() {
            return self.inner.read(buf);
        }
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "age header exceeds 64 KiB",
            ));
        }
        let limit = buf.len().min(self.remaining);
        let count = self.inner.read(&mut buf[..limit])?;
        self.remaining -= count;
        Ok(count)
    }
}

fn copy_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    total: u64,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
) -> Result<(), String> {
    let mut buffer = Zeroizing::new(vec![0u8; BUFFER_SIZE]);
    let mut done = 0;
    loop {
        check_cancel(cancel)?;
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("Could not read or authenticate the file: {e}")),
        };
        if count == 0 {
            break;
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write the output: {e}"))?;
        done += count as u64;
        progress(done, total);
    }
    check_cancel(cancel)
}

pub fn transform(
    job: &Job,
    mode: Mode,
    password: SecretString,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
) -> Result<(), String> {
    transform_with_factor(job, mode, password, cancel, progress, WORK_FACTOR)
}

fn transform_with_factor(
    job: &Job,
    mode: Mode,
    password: SecretString,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    work_factor: u8,
) -> Result<(), String> {
    check_cancel(cancel)?;
    if mode == Mode::Encrypt && password.expose_secret().is_empty() {
        return Err("An encryption password is required.".into());
    }
    if path_occupied(&job.output)? {
        return Err("The output file already exists. Nothing was overwritten; try again.".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny writes/deletion while reading, including through other hard links.
        options.share_mode(1); // FILE_SHARE_READ
    }
    let file = options
        .open(&job.input)
        .map_err(|e| format!("Could not open the source file: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("The input must be a regular file.".into());
    }
    let total = metadata.len();
    let parent = job.output.parent().ok_or("The output needs a folder.")?;
    // Same-directory temporary + no-clobber commit: incomplete or unauthenticated
    // plaintext is never published under the requested destination filename.
    let mut temporary = tempfile::Builder::new()
        .prefix(".pebblecrypt-")
        .suffix(".partial")
        .tempfile_in(parent)
        .map_err(|e| format!("Could not create a file in the output folder: {e}"))?;
    let processed = (|| -> Result<(), String> {
        let mut output = BufWriter::with_capacity(BUFFER_SIZE, temporary.as_file_mut());
        let mut input = BufReader::with_capacity(BUFFER_SIZE, file);
        match mode {
            Mode::Encrypt => {
                let mut recipient = age::scrypt::Recipient::new(password);
                recipient.set_work_factor(work_factor);
                let encryptor = age::Encryptor::with_recipients(std::iter::once(
                    &recipient as &dyn age::Recipient,
                ))
                .map_err(|e| format!("Could not prepare encryption: {e}"))?;
                check_cancel(cancel)?;
                let mut writer = encryptor
                    .wrap_output(&mut output)
                    .map_err(|e| e.to_string())?;
                copy_stream(&mut input, &mut writer, total, cancel, progress)?;
                writer
                    .finish()
                    .map_err(|e| format!("Could not finish encryption: {e}"))?;
            }
            Mode::Decrypt => {
                let header_active = Rc::new(Cell::new(true));
                let limited = HeaderLimited {
                    inner: input,
                    active: header_active.clone(),
                    remaining: 64 * 1024,
                };
                let decryptor = age::Decryptor::new(limited)
                    .map_err(|_| "This is not a supported age file, or its header is damaged. PicoCrypt .pcv files are not supported.".to_owned())?;
                header_active.set(false);
                if !decryptor.is_scrypt() {
                    return Err("This age file uses a recipient key. PebbleCrypt opens password-encrypted age files.".into());
                }
                let mut identity = age::scrypt::Identity::new(password);
                identity.set_max_work_factor(MAX_WORK_FACTOR);
                let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
                    .map_err(|e| match e {
                        age::DecryptError::ExcessiveWork { .. } => "This file requests more password-derivation memory than PebbleCrypt allows (1 GiB).".to_owned(),
                        _ => "The password is incorrect, or the encrypted file is damaged.".to_owned(),
                    })?;
                check_cancel(cancel)?;
                copy_stream(&mut reader, &mut output, total, cancel, progress)?;
            }
        }
        output
            .flush()
            .map_err(|e| format!("Could not flush the output: {e}"))?;
        drop(output);
        check_cancel(cancel)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|e| format!("Could not save the output: {e}"))?;
        check_cancel(cancel)?;
        Ok(())
    })();
    if let Err(error) = processed {
        return Err(discard_partial(temporary, error));
    }
    if let Err(e) = temporary.persist_noclobber(&job.output) {
        return Err(discard_partial(
            e.file,
            format!(
                "Could not finalize the output; existing files were preserved: {}",
                e.error
            ),
        ));
    }
    progress(total, total);
    Ok(())
}

fn discard_partial(temporary: tempfile::NamedTempFile, error: String) -> String {
    let path = temporary.path().to_path_buf();
    match temporary.close() {
        Ok(()) => error,
        Err(cleanup_error) => format!(
            "{error}\nCould not remove the temporary file {}: {cleanup_error}. It may contain plaintext; remove it when it is no longer in use.",
            path.display()
        ),
    }
}

pub fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
#[path = "crypto_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn secret() -> SecretString {
        SecretString::from("a long test-only passphrase".to_owned())
    }
    fn run(input: &Path, output: &Path, mode: Mode) -> Result<(), String> {
        transform_with_factor(
            &Job {
                input: input.into(),
                output: output.into(),
            },
            mode,
            secret(),
            &AtomicBool::new(false),
            &mut |_, _| {},
            10,
        )
    }
    fn partials(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pebblecrypt-")
            })
            .count()
    }

    #[test]
    fn round_trip_empty_unicode_and_multiple_chunk_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        for size in [0, 1, 65535, 65536, 65537, 262144, 524301] {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let input = dir.path().join(format!("日本語-{size}.bin"));
            let enc = input.with_extension("age");
            let output = input.with_extension("out");
            fs::write(&input, &bytes).unwrap();
            run(&input, &enc, Mode::Encrypt).unwrap();
            run(&enc, &output, Mode::Decrypt).unwrap();
            assert_eq!(fs::read(output).unwrap(), bytes);
            assert_eq!(fs::read(input).unwrap(), bytes);
        }
        assert_eq!(partials(dir.path()), 0);
    }

    #[test]
    fn wrong_password_corruption_truncation_and_appended_data_leave_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let enc = dir.path().join("file.age");
        let output = dir.path().join("out");
        fs::write(&input, vec![42; 150000]).unwrap();
        run(&input, &enc, Mode::Encrypt).unwrap();
        let job = Job {
            input: enc.clone(),
            output: output.clone(),
        };
        assert!(
            transform(
                &job,
                Mode::Decrypt,
                SecretString::from("wrong".to_owned()),
                &AtomicBool::new(false),
                &mut |_, _| {}
            )
            .is_err()
        );
        assert!(!output.exists());
        let original = fs::read(&enc).unwrap();
        let mut damaged = original.clone();
        let end = damaged.len() - 1;
        damaged[end] ^= 1;
        let mut appended = original.clone();
        appended.push(0);
        for bad in [
            damaged,
            original[..original.len() - 1].to_vec(),
            original[..original.len() / 2].to_vec(),
            appended,
            b"not an age file".to_vec(),
        ] {
            fs::write(&enc, bad).unwrap();
            assert!(run(&enc, &output, Mode::Decrypt).is_err());
            assert!(!output.exists());
            assert_eq!(partials(dir.path()), 0);
        }
    }

    #[test]
    fn cancel_midstream_cleans_up_for_both_modes() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let enc = dir.path().join("file.age");
        let output = dir.path().join("out");
        fs::write(&input, vec![9; 1024 * 1024]).unwrap();
        run(&input, &enc, Mode::Encrypt).unwrap();
        for (source, mode) in [(&input, Mode::Encrypt), (&enc, Mode::Decrypt)] {
            let cancelled = AtomicBool::new(false);
            let result = transform_with_factor(
                &Job {
                    input: source.clone(),
                    output: output.clone(),
                },
                mode,
                secret(),
                &cancelled,
                &mut |_, _| {
                    cancelled.store(true, Ordering::Relaxed);
                },
                10,
            );
            assert!(result.is_err());
            assert!(!output.exists());
            assert_eq!(partials(dir.path()), 0);
        }
    }

    #[test]
    fn never_overwrite_even_if_destination_appears_during_processing() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("out");
        fs::write(&input, vec![7; 1024]).unwrap();
        let result = transform_with_factor(
            &Job {
                input,
                output: output.clone(),
            },
            Mode::Encrypt,
            secret(),
            &AtomicBool::new(false),
            &mut |_, _| {
                fs::write(&output, b"existing important data").unwrap();
            },
            10,
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"existing important data");
        assert_eq!(partials(dir.path()), 0);
    }

    #[test]
    fn batch_names_handle_existing_files_and_duplicate_basenames() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        let a = dir.path().join("report.txt");
        let b = other.join("report.txt");
        fs::write(&a, b"first").unwrap();
        fs::write(&b, b"second").unwrap();
        fs::write(dir.path().join("report.txt.age"), b"existing").unwrap();
        let jobs = plan_jobs(&[a, b], Some(dir.path()), Mode::Encrypt).unwrap();
        assert_ne!(jobs[0].output, jobs[1].output);
        assert!(jobs.iter().all(|j| !j.output.exists()));
        let decrypt = plan_jobs(&[dir.path().join("report.txt.age")], None, Mode::Decrypt).unwrap();
        assert_eq!(
            decrypt[0].output.file_name().unwrap(),
            "report (decrypted).txt"
        );
    }

    #[test]
    fn production_work_factor_and_standard_age_compatibility() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let enc = dir.path().join("file.age");
        fs::write(&input, b"production parameters").unwrap();
        transform(
            &Job {
                input,
                output: enc.clone(),
            },
            Mode::Encrypt,
            secret(),
            &AtomicBool::new(false),
            &mut |_, _| {},
        )
        .unwrap();
        let bytes = fs::read(enc).unwrap();
        assert!(bytes.windows(4).any(|w| w == b" 18\n"));
        let identity = age::scrypt::Identity::new(secret());
        let mut reader = age::Decryptor::new(bytes.as_slice())
            .unwrap()
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plain = Vec::new();
        reader.read_to_end(&mut plain).unwrap();
        assert_eq!(plain, b"production parameters");
    }

    #[test]
    fn randomization_and_password_generator() {
        let a = generated_password().unwrap();
        let b = generated_password().unwrap();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::write(&input, b"same input").unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        run(&input, &a, Mode::Encrypt).unwrap();
        run(&input, &b, Mode::Encrypt).unwrap();
        assert_ne!(fs::read(a).unwrap(), fs::read(b).unwrap());
    }

    #[test]
    fn rejects_oversized_headers_and_excessive_scrypt_cost() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("file.age");
        let output = dir.path().join("out");
        let mut bytes = b"age-encryption.org/v1\n-> scrypt ".to_vec();
        bytes.extend(vec![b'A'; 100000]);
        fs::write(&input, bytes).unwrap();
        assert!(run(&input, &output, Mode::Decrypt).is_err());
        let source = dir.path().join("source");
        fs::write(&source, b"test").unwrap();
        run(&source, &dir.path().join("valid.age"), Mode::Encrypt).unwrap();
        let mut bytes = fs::read(dir.path().join("valid.age")).unwrap();
        let position = bytes.windows(4).position(|w| w == b" 10\n").unwrap();
        bytes[position + 1] = b'3';
        bytes[position + 2] = b'0';
        fs::write(&input, bytes).unwrap();
        assert!(
            run(&input, &output, Mode::Decrypt)
                .unwrap_err()
                .contains("1 GiB")
        );
        assert!(!output.exists());
        assert_eq!(partials(dir.path()), 0);
    }
}
