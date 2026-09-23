use super::*;
use std::io::Cursor;

#[test]
fn interrupted_reads_are_retried() {
    struct InterruptedOnce(bool);
    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            Cursor::new(b"complete data").read(buf)
        }
    }
    // The wrapper only returns data once, then EOF.
    let mut reader = InterruptedOnce(false).take(13);
    let mut output = Vec::new();
    copy_stream(
        &mut reader,
        &mut output,
        13,
        &AtomicBool::new(false),
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(output, b"complete data");
}

#[test]
fn empty_read_after_header_budget_is_valid() {
    let mut reader = HeaderLimited {
        inner: Cursor::new(b"x"),
        active: Rc::new(Cell::new(true)),
        remaining: 0,
    };
    assert_eq!(reader.read(&mut []).unwrap(), 0);
}

#[test]
fn relative_inputs_produce_absolute_job_paths() {
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let relative = input.strip_prefix(&cwd).unwrap().to_path_buf();
    let jobs = plan_jobs(&[relative], None, Mode::Encrypt).unwrap();
    assert!(jobs[0].input.is_absolute());
    assert!(jobs[0].output.is_absolute());
}

#[test]
fn duplicate_inputs_are_only_planned_once() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("file");
    fs::write(&input, b"hello").unwrap();
    let jobs = plan_jobs(&[input.clone(), input], None, Mode::Encrypt).unwrap();
    assert_eq!(jobs.len(), 1);
}

fn password() -> SecretString {
    SecretString::from("audit test passphrase only".to_owned())
}
fn process(input: &Path, output: &Path, mode: Mode) -> Result<(), String> {
    transform_with_factor(
        &Job {
            input: input.into(),
            output: output.into(),
        },
        mode,
        password(),
        &AtomicBool::new(false),
        &mut |_, _| {},
        10,
    )
}
struct Fixture {
    dir: tempfile::TempDir,
    source: PathBuf,
    encrypted: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.dat");
        let encrypted = dir.path().join("cipher.age");
        let output = dir.path().join("restored.dat");
        fs::write(&source, bytes).unwrap();
        Self {
            dir,
            source,
            encrypted,
            output,
        }
    }
    fn encrypt(&self) {
        process(&self.source, &self.encrypted, Mode::Encrypt).unwrap();
    }
    fn no_partials(&self) {
        assert!(!fs::read_dir(self.dir.path()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pebblecrypt-")
        }));
    }
    fn reject(&self, bytes: &[u8]) {
        fs::write(&self.encrypted, bytes).unwrap();
        assert!(process(&self.encrypted, &self.output, Mode::Decrypt).is_err());
        assert!(!self.output.exists());
        self.no_partials();
    }
}

#[test]
fn empty_batch_is_rejected() {
    assert!(plan_jobs(&[], None, Mode::Encrypt).is_err());
}
#[test]
fn missing_input_is_rejected() {
    let f = Fixture::new(b"x");
    assert!(plan_jobs(&[f.output], None, Mode::Encrypt).is_err());
}
#[test]
fn folder_input_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    assert!(plan_jobs(&[dir.path().into()], None, Mode::Encrypt).is_err());
}
#[test]
fn missing_output_directory_is_rejected() {
    let f = Fixture::new(b"x");
    assert!(plan_jobs(&[f.source], Some(&f.output), Mode::Encrypt).is_err());
}
#[test]
fn regular_file_cannot_be_output_directory() {
    let f = Fixture::new(b"x");
    assert!(
        plan_jobs(
            std::slice::from_ref(&f.source),
            Some(&f.source),
            Mode::Encrypt
        )
        .is_err()
    );
}
#[test]
fn explicit_destination_is_used() {
    let f = Fixture::new(b"x");
    let out = tempfile::tempdir().unwrap();
    let jobs = plan_jobs(&[f.source], Some(out.path()), Mode::Encrypt).unwrap();
    assert_eq!(
        jobs[0].output.parent().unwrap(),
        fs::canonicalize(out.path()).unwrap()
    );
}
#[test]
fn uppercase_age_extension_is_removed() {
    let f = Fixture::new(b"x");
    let input = f.dir.path().join("secret.AGE");
    fs::write(&input, b"x").unwrap();
    assert_eq!(
        plan_jobs(&[input], None, Mode::Decrypt).unwrap()[0]
            .output
            .file_name()
            .unwrap(),
        "secret"
    );
}
#[test]
fn arbitrary_extension_gets_decrypted_suffix() {
    let f = Fixture::new(b"x");
    assert_eq!(
        plan_jobs(&[f.source], None, Mode::Decrypt).unwrap()[0]
            .output
            .file_name()
            .unwrap(),
        "source.dat.decrypted"
    );
}
#[test]
fn hidden_age_filename_remains_safe() {
    let f = Fixture::new(b"x");
    let input = f.dir.path().join(".age");
    fs::write(&input, b"x").unwrap();
    let jobs = plan_jobs(&[input], None, Mode::Decrypt).unwrap();
    assert_ne!(jobs[0].input, jobs[0].output);
}
#[test]
fn repeated_collisions_get_distinct_suffixes() {
    let f = Fixture::new(b"x");
    for name in [
        "source.dat.age",
        "source.dat (encrypted).age",
        "source.dat (encrypted 2).age",
    ] {
        fs::write(f.dir.path().join(name), b"keep").unwrap();
    }
    let jobs = plan_jobs(&[f.source], None, Mode::Encrypt).unwrap();
    assert_eq!(
        jobs[0].output.file_name().unwrap(),
        "source.dat (encrypted 3).age"
    );
}
#[test]
fn directory_at_output_name_is_preserved() {
    let f = Fixture::new(b"x");
    let occupied = f.dir.path().join("source.dat.age");
    fs::create_dir(&occupied).unwrap();
    let jobs = plan_jobs(&[f.source], None, Mode::Encrypt).unwrap();
    assert_ne!(jobs[0].output, occupied);
    assert!(occupied.is_dir());
}
#[test]
fn excessive_output_name_is_rejected_before_encryption() {
    let f = Fixture::new(b"x");
    let input = f.dir.path().join("a".repeat(253));
    fs::write(&input, b"x").unwrap();
    assert!(
        plan_jobs(&[input], None, Mode::Encrypt)
            .unwrap_err()
            .contains("too long")
    );
}
#[test]
fn unicode_and_spaces_survive_planning_and_processing() {
    let f = Fixture::new(b"Unicode plaintext: \xf0\x9f\x94\x90");
    let input = f.dir.path().join("résumé 日本語 🔐.txt");
    fs::rename(&f.source, &input).unwrap();
    let jobs = plan_jobs(std::slice::from_ref(&input), None, Mode::Encrypt).unwrap();
    process(&input, &jobs[0].output, Mode::Encrypt).unwrap();
    process(&jobs[0].output, &f.output, Mode::Decrypt).unwrap();
    assert_eq!(fs::read(input).unwrap(), fs::read(f.output).unwrap());
}
#[test]
fn empty_encryption_password_is_rejected() {
    let f = Fixture::new(b"x");
    assert!(
        transform(
            &Job {
                input: f.source.clone(),
                output: f.output.clone()
            },
            Mode::Encrypt,
            SecretString::from(String::new()),
            &AtomicBool::new(false),
            &mut |_, _| {}
        )
        .is_err()
    );
    assert!(!f.output.exists());
}
#[test]
fn output_equal_to_source_cannot_destroy_it() {
    let f = Fixture::new(b"keep me");
    assert!(process(&f.source, &f.source, Mode::Encrypt).is_err());
    assert_eq!(fs::read(f.source).unwrap(), b"keep me");
}
#[test]
fn output_hard_link_to_source_cannot_destroy_it() {
    let f = Fixture::new(b"keep me");
    fs::hard_link(&f.source, &f.output).unwrap();
    assert!(process(&f.source, &f.output, Mode::Encrypt).is_err());
    assert_eq!(fs::read(f.source).unwrap(), b"keep me");
}
#[test]
fn preexisting_output_preserved_in_both_modes() {
    let f = Fixture::new(b"original");
    f.encrypt();
    fs::write(&f.output, b"existing").unwrap();
    for (input, mode) in [(&f.source, Mode::Encrypt), (&f.encrypted, Mode::Decrypt)] {
        assert!(process(input, &f.output, mode).is_err());
        assert_eq!(fs::read(&f.output).unwrap(), b"existing");
    }
    f.no_partials();
}
#[test]
fn missing_source_leaves_no_temporary() {
    let f = Fixture::new(b"x");
    fs::remove_file(&f.source).unwrap();
    assert!(process(&f.source, &f.output, Mode::Encrypt).is_err());
    assert!(!f.output.exists());
    f.no_partials();
}
#[test]
fn unavailable_output_parent_leaves_original() {
    let f = Fixture::new(b"keep");
    assert!(process(&f.source, &f.dir.path().join("missing/out"), Mode::Encrypt).is_err());
    assert_eq!(fs::read(&f.source).unwrap(), b"keep");
    f.no_partials();
}
#[test]
fn cancellation_before_start_creates_nothing() {
    let f = Fixture::new(b"x");
    assert_eq!(
        transform(
            &Job {
                input: f.source.clone(),
                output: f.output.clone()
            },
            Mode::Encrypt,
            password(),
            &AtomicBool::new(true),
            &mut |_, _| {}
        )
        .unwrap_err(),
        "Cancelled."
    );
    assert!(!f.output.exists());
    f.no_partials();
}
#[test]
fn final_filename_is_absent_until_commit() {
    let f = Fixture::new(&vec![3; BUFFER_SIZE + 1]);
    let mut callbacks = 0;
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.output.clone(),
        },
        Mode::Encrypt,
        password(),
        &AtomicBool::new(false),
        &mut |done, total| {
            callbacks += 1;
            if f.output.exists() {
                assert_eq!(done, total);
            } else {
                assert!(done <= total);
            }
        },
        10,
    )
    .unwrap();
    assert!(callbacks >= 3);
    assert!(f.output.exists());
    f.no_partials();
}
#[test]
fn progress_is_monotonic_and_finishes_after_commit() {
    let f = Fixture::new(&vec![7; BUFFER_SIZE * 3 + 11]);
    let mut last = 0;
    let mut committed = false;
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.output.clone(),
        },
        Mode::Encrypt,
        password(),
        &AtomicBool::new(false),
        &mut |done, total| {
            assert!(done >= last && done <= total);
            last = done;
            if f.output.exists() {
                assert_eq!(done, total);
                committed = true;
            }
        },
        10,
    )
    .unwrap();
    assert!(committed);
}
#[test]
fn cancellation_after_committed_file_does_not_remove_it() {
    let f = Fixture::new(b"keep");
    let cancel = AtomicBool::new(false);
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.encrypted.clone(),
        },
        Mode::Encrypt,
        password(),
        &cancel,
        &mut |_, _| {
            if f.encrypted.exists() {
                cancel.store(true, Ordering::Relaxed);
            }
        },
        10,
    )
    .unwrap();
    assert!(f.encrypted.exists());
    process(&f.encrypted, &f.output, Mode::Decrypt).unwrap();
    assert_eq!(fs::read(f.output).unwrap(), b"keep");
}
#[test]
fn every_single_byte_mutation_is_rejected() {
    let f = Fixture::new(b"small authenticated payload");
    f.encrypt();
    let original = fs::read(&f.encrypted).unwrap();
    for offset in 0..original.len() {
        let mut bad = original.clone();
        bad[offset] ^= 1;
        f.reject(&bad);
    }
}
#[test]
fn every_truncation_of_a_small_file_is_rejected() {
    let f = Fixture::new(b"small authenticated payload");
    f.encrypt();
    let bytes = fs::read(&f.encrypted).unwrap();
    for length in 0..bytes.len() {
        f.reject(&bytes[..length]);
    }
}
#[test]
fn swapped_ciphertext_chunks_are_rejected() {
    let f = Fixture::new(&vec![11; 200000]);
    f.encrypt();
    let mut bytes = fs::read(&f.encrypted).unwrap();
    let start = bytes.windows(4).position(|w| w == b"--- ").unwrap() + 4 + 43 + 1 + 16;
    let chunk = 65536 + 16;
    for i in 0..chunk {
        bytes.swap(start + i, start + chunk + i);
    }
    f.reject(&bytes);
}
#[test]
fn duplicated_ciphertext_chunk_is_rejected() {
    let f = Fixture::new(&vec![12; 160000]);
    f.encrypt();
    let bytes = fs::read(&f.encrypted).unwrap();
    let start = bytes.windows(4).position(|w| w == b"--- ").unwrap() + 4 + 43 + 1 + 16;
    let chunk = 65536 + 16;
    let mut bad = bytes[..start + chunk].to_vec();
    bad.extend_from_slice(&bytes[start..]);
    f.reject(&bad);
}
#[test]
fn payload_spliced_from_different_encryption_is_rejected() {
    let f = Fixture::new(b"identical plaintext");
    f.encrypt();
    let mut a = fs::read(&f.encrypted).unwrap();
    process(&f.source, &f.output, Mode::Encrypt).unwrap();
    let b = fs::read(&f.output).unwrap();
    fs::remove_file(&f.output).unwrap();
    let len = a.len();
    a[len - 16..].copy_from_slice(&b[b.len() - 16..]);
    f.reject(&a);
}
#[test]
fn malformed_header_corpus_never_panics_or_publishes() {
    let f = Fixture::new(b"x");
    let mut state = 0x912a_bf61_0791_f133u64;
    for case in 0..256 {
        let mut data = if case % 2 == 0 {
            b"age-encryption.org/v1\n".to_vec()
        } else {
            vec![]
        };
        for _ in 0..case * 13 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push(state as u8);
        }
        f.reject(&data);
    }
}
#[test]
fn deterministic_random_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = 0x541b_2751_b923_a674u64;
    for case in 0..64 {
        let len = case * 1031;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        let input = dir.path().join(format!("{case}.in"));
        let enc = dir.path().join(format!("{case}.age"));
        let out = dir.path().join(format!("{case}.out"));
        fs::write(&input, &bytes).unwrap();
        process(&input, &enc, Mode::Encrypt).unwrap();
        process(&enc, &out, Mode::Decrypt).unwrap();
        assert_eq!(fs::read(out).unwrap(), bytes);
    }
}
#[test]
fn large_file_is_processed_in_bounded_chunks() {
    let f = Fixture::new(b"");
    fs::OpenOptions::new()
        .write(true)
        .open(&f.source)
        .unwrap()
        .set_len(32 * 1024 * 1024 + 1)
        .unwrap();
    let mut last = 0;
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.encrypted.clone(),
        },
        Mode::Encrypt,
        password(),
        &AtomicBool::new(false),
        &mut |done, _| {
            assert!(done - last <= BUFFER_SIZE as u64);
            last = done;
        },
        10,
    )
    .unwrap();
    process(&f.encrypted, &f.output, Mode::Decrypt).unwrap();
    assert_eq!(fs::metadata(&f.output).unwrap().len(), 32 * 1024 * 1024 + 1);
    let mut reader = std::fs::File::open(f.output).unwrap();
    let mut buffer = [1u8; 65536];
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        assert!(buffer[..count].iter().all(|b| *b == 0));
    }
}
#[test]
fn external_recipient_key_file_is_rejected_cleanly() {
    let f = Fixture::new(b"x");
    let identity = age::x25519::Identity::generate();
    let encrypted = age::encrypt(&identity.to_public(), b"private").unwrap();
    fs::write(&f.encrypted, encrypted).unwrap();
    assert!(
        process(&f.encrypted, &f.output, Mode::Decrypt)
            .unwrap_err()
            .contains("recipient key")
    );
    f.no_partials();
}
#[test]
fn password_whitespace_and_unicode_are_not_normalized() {
    let f = Fixture::new(b"precise password");
    let text = "  å 日本語 🔐 e\u{301}  ";
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.encrypted.clone(),
        },
        Mode::Encrypt,
        SecretString::from(text.to_owned()),
        &AtomicBool::new(false),
        &mut |_, _| {},
        10,
    )
    .unwrap();
    for candidate in [text.trim(), "  å 日本語 🔐 é  "] {
        assert!(
            transform(
                &Job {
                    input: f.encrypted.clone(),
                    output: f.output.clone()
                },
                Mode::Decrypt,
                SecretString::from(candidate.to_owned()),
                &AtomicBool::new(false),
                &mut |_, _| {}
            )
            .is_err()
        );
    }
    transform(
        &Job {
            input: f.encrypted.clone(),
            output: f.output.clone(),
        },
        Mode::Decrypt,
        SecretString::from(text.to_owned()),
        &AtomicBool::new(false),
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(fs::read(f.output).unwrap(), b"precise password");
}
#[test]
fn direct_age_library_writer_can_be_read() {
    let f = Fixture::new(b"external age");
    let mut recipient = age::scrypt::Recipient::new(password());
    recipient.set_work_factor(10);
    let data = age::encrypt(&recipient, b"external age").unwrap();
    fs::write(&f.encrypted, data).unwrap();
    process(&f.encrypted, &f.output, Mode::Decrypt).unwrap();
    assert_eq!(fs::read(f.output).unwrap(), b"external age");
}
#[test]
fn header_budget_stops_exactly_at_limit() {
    let active = Rc::new(Cell::new(true));
    let mut reader = HeaderLimited {
        inner: Cursor::new(vec![1; 65]),
        active: active.clone(),
        remaining: 64,
    };
    let mut buf = [0; 128];
    assert_eq!(reader.read(&mut buf).unwrap(), 64);
    assert_eq!(
        reader.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    active.set(false);
    assert_eq!(reader.read(&mut buf).unwrap(), 1);
}
#[test]
fn short_reads_and_short_writes_are_handled() {
    struct ShortReader(Cursor<Vec<u8>>);
    impl Read for ShortReader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = b.len().min(7);
            self.0.read(&mut b[..n])
        }
    }
    struct ShortWriter(Vec<u8>);
    impl Write for ShortWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let n = b.len().min(3);
            self.0.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let data: Vec<u8> = (0..255).collect();
    let mut reader = ShortReader(Cursor::new(data.clone()));
    let mut writer = ShortWriter(vec![]);
    copy_stream(
        &mut reader,
        &mut writer,
        255,
        &AtomicBool::new(false),
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(writer.0, data);
}
#[test]
fn zero_write_is_an_error() {
    struct ZeroWriter;
    impl Write for ZeroWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(
        copy_stream(
            &mut Cursor::new(b"x"),
            &mut ZeroWriter,
            1,
            &AtomicBool::new(false),
            &mut |_, _| {}
        )
        .is_err()
    );
}
#[test]
fn disk_full_is_reported() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected disk full",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(
        copy_stream(
            &mut Cursor::new(b"x"),
            &mut Full,
            1,
            &AtomicBool::new(false),
            &mut |_, _| {}
        )
        .unwrap_err()
        .contains("disk full")
    );
}
#[test]
fn read_error_is_reported() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "injected read failure",
            ))
        }
    }
    assert!(
        copy_stream(
            &mut Broken,
            &mut Vec::new(),
            1,
            &AtomicBool::new(false),
            &mut |_, _| {}
        )
        .unwrap_err()
        .contains("read failure")
    );
}
#[test]
fn passwords_have_expected_length_alphabet_and_no_repeats_in_sample() {
    let mut seen = HashSet::new();
    for _ in 0..1024 {
        let p = generated_password().unwrap();
        assert_eq!(p.len(), 24);
        assert!(
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert!(seen.insert(p));
    }
}
#[cfg(windows)]
#[test]
fn source_cannot_be_written_or_deleted_during_processing() {
    let f = Fixture::new(&vec![5; BUFFER_SIZE * 2]);
    let mut checked = false;
    transform_with_factor(
        &Job {
            input: f.source.clone(),
            output: f.encrypted.clone(),
        },
        Mode::Encrypt,
        password(),
        &AtomicBool::new(false),
        &mut |done, total| {
            if done < total {
                assert!(OpenOptions::new().write(true).open(&f.source).is_err());
                assert!(fs::remove_file(&f.source).is_err());
                checked = true;
            }
        },
        10,
    )
    .unwrap();
    assert!(checked);
}
#[cfg(windows)]
#[test]
fn source_already_open_for_writing_is_rejected() {
    let f = Fixture::new(b"keep");
    let _writer = OpenOptions::new().write(true).open(&f.source).unwrap();
    assert!(process(&f.source, &f.output, Mode::Encrypt).is_err());
    assert!(!f.output.exists());
    f.no_partials();
}
#[cfg(windows)]
#[test]
fn failed_temporary_cleanup_is_reported_with_path() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new(&vec![17; BUFFER_SIZE * 2]);
    f.encrypt();
    let cancel = AtomicBool::new(false);
    let mut blocker = None;
    let mut leftover = None;
    let result = transform_with_factor(
        &Job {
            input: f.encrypted.clone(),
            output: f.output.clone(),
        },
        Mode::Decrypt,
        password(),
        &cancel,
        &mut |_, _| {
            if blocker.is_none() {
                let path = fs::read_dir(f.dir.path())
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".pebblecrypt-")
                    })
                    .unwrap();
                blocker = Some(
                    OpenOptions::new()
                        .read(true)
                        .share_mode(3)
                        .open(&path)
                        .unwrap(),
                );
                leftover = Some(path);
                cancel.store(true, Ordering::Relaxed);
            }
        },
        10,
    )
    .unwrap_err();
    let leftover = leftover.unwrap();
    assert!(result.contains("Could not remove the temporary file"));
    assert!(result.contains("plaintext"));
    assert!(result.contains(leftover.file_name().unwrap().to_str().unwrap()));
    assert!(leftover.exists());
    assert!(!f.output.exists());
    drop(blocker);
    fs::remove_file(leftover).unwrap();
    f.no_partials();
}
#[test]
fn panic_during_processing_does_not_publish_partial_output() {
    let f = Fixture::new(&vec![1; BUFFER_SIZE * 2]);
    let result = std::panic::catch_unwind(|| {
        transform_with_factor(
            &Job {
                input: f.source.clone(),
                output: f.output.clone(),
            },
            Mode::Encrypt,
            password(),
            &AtomicBool::new(false),
            &mut |_, _| panic!("injected panic"),
            10,
        )
    });
    assert!(result.is_err());
    assert!(!f.output.exists());
    f.no_partials();
}
