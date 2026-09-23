use super::*;
use std::fs;

fn ready() -> PebbleCrypt {
    PebbleCrypt {
        files: vec![PathBuf::from("example.txt")],
        password: "a twelve-plus-character passphrase".into(),
        confirmation: "a twelve-plus-character passphrase".into(),
        ..Default::default()
    }
}
fn context() -> egui::Context {
    let ctx = egui::Context::default();
    configure_style(&ctx);
    ctx
}
fn render(
    app: &mut PebbleCrypt,
    ctx: &egui::Context,
    size: [f32; 2],
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(size[0], size[1]),
            )),
            events,
            ..Default::default()
        },
        |ui| app.render(ui),
    )
}
fn text_rects(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    output
        .shapes
        .iter()
        .filter_map(|clipped| {
            if let egui::Shape::Text(shape) = &clipped.shape {
                Some((
                    shape.galley.job.text.clone(),
                    shape.galley.rect.translate(shape.pos.to_vec2()),
                ))
            } else {
                None
            }
        })
        .collect()
}
fn click_text(app: &mut PebbleCrypt, ctx: &egui::Context, label: &str) {
    let output = render(app, ctx, [480.0, 540.0], vec![]);
    let rect = text_rects(&output)
        .into_iter()
        .find(|(t, _)| t == label)
        .unwrap_or_else(|| panic!("missing label {label}"))
        .1;
    let pos = rect.center();
    let events = vec![
        egui::Event::PointerMoved(pos),
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        },
    ];
    let _ = render(app, ctx, [480.0, 540.0], events);
}
fn attach_channel(app: &mut PebbleCrypt) -> mpsc::Sender<Event> {
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx
}

fn wait_for_worker(app: &mut PebbleCrypt) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while app.busy() {
        app.poll();
        assert!(
            Instant::now() < deadline,
            "worker timed out: {}",
            app.status
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_worker_round_trip_and_partial_batch_failure() {
    // Exercise the real thread, production scrypt factor, event channel, and UI
    // state transitions together. Other tests use cheaper test-only derivation.
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    let encrypted = directory.path().join("encrypted");
    let restored = directory.path().join("restored");
    let partial = directory.path().join("partial");
    for folder in [&original, &encrypted, &restored, &partial] {
        fs::create_dir(folder).unwrap();
    }
    let data: Vec<u8> = (0..300_001).map(|i| (i % 251) as u8).collect();
    let first = original.join("binary.dat");
    let second = original.join("empty.txt");
    fs::write(&first, &data).unwrap();
    fs::write(&second, []).unwrap();
    let passphrase = "real worker test passphrase 🔐";
    let ctx = context();
    let mut app = PebbleCrypt::default();
    app.add_files(vec![first.clone(), second.clone()], &ctx);
    app.destination = Some(encrypted.clone());
    app.password = passphrase.into();
    app.confirmation = passphrase.into();
    app.start(&ctx);
    assert!(app.busy());
    assert!(app.password.is_empty() && app.confirmation.is_empty());
    wait_for_worker(&mut app);
    assert!(!app.error, "{}", app.status);
    assert_eq!(app.outputs.len(), 2);
    assert_eq!(app.progress, 1.0);
    assert!(
        fs::read(&app.outputs[0])
            .unwrap()
            .windows(3)
            .any(|w| w == b" 18")
    );
    assert_eq!(fs::read(&first).unwrap(), data);
    assert!(fs::read(&second).unwrap().is_empty());

    let mut decrypt = PebbleCrypt::default();
    decrypt.add_files(app.outputs.clone(), &ctx);
    assert_eq!(decrypt.mode, Mode::Decrypt);
    decrypt.destination = Some(restored.clone());
    decrypt.password = passphrase.into();
    decrypt.start(&ctx);
    assert!(decrypt.busy());
    wait_for_worker(&mut decrypt);
    assert!(!decrypt.error, "{}", decrypt.status);
    assert_eq!(decrypt.outputs.len(), 2);
    assert_eq!(fs::read(restored.join("binary.dat")).unwrap(), data);
    assert!(fs::read(restored.join("empty.txt")).unwrap().is_empty());

    let invalid = encrypted.join("damaged.age");
    fs::write(&invalid, b"not an age file").unwrap();
    let mut failed = PebbleCrypt::default();
    failed.add_files(vec![app.outputs[0].clone(), invalid.clone()], &ctx);
    failed.destination = Some(partial.clone());
    failed.password = passphrase.into();
    failed.start(&ctx);
    wait_for_worker(&mut failed);
    assert!(failed.error);
    assert_eq!(failed.outputs.len(), 1);
    assert!(failed.status.contains("damaged.age"));
    assert!(failed.status.contains("1 completed"));
    assert_eq!(fs::read(&failed.outputs[0]).unwrap(), data);
    assert_eq!(fs::read_dir(partial).unwrap().count(), 1);
    assert_eq!(fs::read(invalid).unwrap(), b"not an age file");
}

#[test]
fn encryption_requires_files() {
    let mut app = ready();
    app.files.clear();
    assert!(app.validation().unwrap().contains("files"));
}
#[test]
fn encryption_requires_nonempty_password() {
    let mut app = ready();
    app.password.clear();
    assert!(app.validation().is_some());
}
#[test]
fn encryption_rejects_short_password() {
    let mut app = ready();
    app.password = "12345678901".into();
    app.confirmation = app.password.clone();
    assert!(app.validation().unwrap().contains("12"));
}
#[test]
fn twelve_unicode_characters_are_accepted() {
    let mut app = ready();
    app.password = "🔐".repeat(12);
    app.confirmation = app.password.clone();
    assert!(app.validation().is_none());
}
#[test]
fn multibyte_bytes_do_not_bypass_length_requirement() {
    let mut app = ready();
    app.password = "🔐".repeat(3);
    app.confirmation = app.password.clone();
    assert!(app.validation().is_some());
}
#[test]
fn password_confirmation_must_match_exactly() {
    let mut app = ready();
    app.confirmation.push(' ');
    assert!(app.validation().unwrap().contains("match"));
}
#[test]
fn generated_password_requires_saved_confirmation() {
    let mut app = ready();
    app.generated = true;
    assert!(app.validation().is_some());
    app.password_saved = true;
    assert!(app.validation().is_none());
}
#[test]
fn short_external_password_can_be_decrypted() {
    let mut app = ready();
    app.mode = Mode::Decrypt;
    app.password = "x".into();
    app.confirmation.clear();
    assert!(app.validation().is_none());
}
#[test]
fn clear_password_removes_strings_flags_and_undo_state() {
    let mut app = ready();
    let ctx = context();
    let id = egui::Id::new(("password", app.password_epoch));
    egui::text_edit::TextEditState::default().store(&ctx, id);
    app.show_password = true;
    app.generated = true;
    app.password_saved = true;
    app.clear_password(&ctx);
    assert!(app.password.is_empty() && app.confirmation.is_empty());
    assert!(!app.show_password && !app.generated && !app.password_saved);
    assert!(egui::text_edit::TextEditState::load(&ctx, id).is_none());
    assert_eq!(app.password_epoch, 1);
}
#[test]
fn regenerating_password_discards_previous_undo_state() {
    let mut app = ready();
    let ctx = context();
    let id = egui::Id::new(("password", app.password_epoch));
    egui::text_edit::TextEditState::default().store(&ctx, id);
    app.password_saved = true;
    app.set_generated_password("new generated password".into(), &ctx);
    assert!(egui::text_edit::TextEditState::load(&ctx, id).is_none());
    assert_eq!(app.password, app.confirmation);
    assert!(!app.password_saved);
    assert!(app.generated && app.show_password);
}
#[test]
fn clear_queue_also_clears_secrets_errors_and_results() {
    let mut app = ready();
    app.error = true;
    app.outputs.push("old.out".into());
    app.progress = 1.0;
    app.clear_files(&context());
    assert!(
        app.files.is_empty() && app.outputs.is_empty() && app.password.is_empty() && !app.error
    );
    assert_eq!(app.progress, 0.0);
}
#[test]
fn switching_mode_clears_secrets() {
    let mut app = ready();
    app.set_mode(Mode::Decrypt, &context());
    assert_eq!(app.mode, Mode::Decrypt);
    assert!(app.password.is_empty() && app.confirmation.is_empty());
    assert_eq!(app.files.len(), 1);
}
#[test]
fn selecting_same_mode_does_not_erase_password() {
    let mut app = ready();
    let before = app.password.clone();
    app.set_mode(Mode::Encrypt, &context());
    assert_eq!(app.password, before);
}
#[test]
fn adding_only_age_files_selects_decrypt_and_clears_old_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.AGE");
    fs::write(&path, b"x").unwrap();
    let mut app = ready();
    app.files.clear();
    app.add_files(vec![path], &context());
    assert_eq!(app.mode, Mode::Decrypt);
    assert!(app.password.is_empty());
}
#[test]
fn mixed_selection_defaults_to_encrypt() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.age");
    let b = dir.path().join("b.txt");
    fs::write(&a, b"a").unwrap();
    fs::write(&b, b"b").unwrap();
    let mut app = PebbleCrypt::default();
    app.add_files(vec![a, b], &context());
    assert_eq!(app.mode, Mode::Encrypt);
    assert_eq!(app.files.len(), 2);
}
#[test]
fn duplicate_selection_does_not_double_count_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    fs::write(&path, b"12345").unwrap();
    let mut app = PebbleCrypt::default();
    app.add_files(vec![path.clone(), path], &context());
    assert_eq!(app.files.len(), 1);
    assert_eq!(app.total_file_size(), 5);
}
#[test]
fn folder_selection_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = PebbleCrypt::default();
    app.add_files(vec![dir.path().into()], &context());
    assert!(app.error && app.files.is_empty());
}
#[test]
fn empty_selection_does_not_change_state() {
    let mut app = ready();
    app.status = "keep".into();
    app.add_files(vec![], &context());
    assert_eq!(app.files.len(), 1);
    assert_eq!(app.status, "keep");
}
#[test]
fn busy_app_ignores_new_file_selection() {
    let mut app = ready();
    let _tx = attach_channel(&mut app);
    app.add_files(vec![PathBuf::from("does-not-exist")], &context());
    assert_eq!(app.files.len(), 1);
    assert!(!app.error);
}
#[test]
fn total_size_saturates_without_panicking() {
    let mut app = PebbleCrypt::default();
    app.file_sizes.insert("a".into(), u64::MAX);
    app.file_sizes.insert("b".into(), 1);
    assert_eq!(app.total_file_size(), u64::MAX);
}
#[test]
fn progress_does_not_overwrite_cancelling_message() {
    let mut app = ready();
    let tx = attach_channel(&mut app);
    app.cancel.store(true, Ordering::Relaxed);
    app.status = "Cancelling…".into();
    tx.send(Event::Progress(0.5, "Encrypting file".into()))
        .unwrap();
    app.poll();
    assert_eq!(app.status, "Cancelling…");
    assert_eq!(app.progress, 0.5);
}
#[test]
fn completed_batch_updates_results_and_releases_busy_state() {
    let mut app = ready();
    let tx = attach_channel(&mut app);
    tx.send(Event::Finished {
        outputs: vec!["out.age".into()],
        error: None,
        cancelled: false,
    })
    .unwrap();
    drop(tx);
    app.poll();
    assert!(!app.busy() && !app.error);
    assert_eq!(app.outputs.len(), 1);
    assert_eq!(app.progress, 1.0);
}
#[test]
fn partial_batch_error_preserves_completed_outputs() {
    let mut app = ready();
    let tx = attach_channel(&mut app);
    tx.send(Event::Finished {
        outputs: vec!["out.age".into()],
        error: Some("disk failure".into()),
        cancelled: false,
    })
    .unwrap();
    app.poll();
    assert!(app.error && !app.busy());
    assert_eq!(app.outputs.len(), 1);
    assert!(app.status.contains("disk failure"));
}
#[test]
fn unexpected_worker_disconnect_is_reported() {
    let mut app = ready();
    drop(attach_channel(&mut app));
    app.poll();
    assert!(app.error && !app.busy());
    assert!(app.status.contains("unexpectedly"));
}
#[test]
fn failed_preflight_keeps_password_for_retry() {
    let mut app = ready();
    let before = app.password.clone();
    app.files = vec![PathBuf::from("definitely-missing-audit-file")];
    app.start(&context());
    assert!(app.error && !app.busy());
    assert_eq!(app.password, before);
}
#[test]
fn invalid_form_cannot_start_worker() {
    let mut app = ready();
    app.confirmation.clear();
    app.start(&context());
    assert!(!app.busy());
    assert!(!app.password.is_empty());
}
#[test]
fn compact_empty_layout_has_visible_primary_controls() {
    let mut app = PebbleCrypt::default();
    let ctx = context();
    let _ = render(&mut app, &ctx, [480.0, 540.0], vec![]);
    let output = render(&mut app, &ctx, [480.0, 540.0], vec![]);
    let labels = text_rects(&output);
    for label in [
        "Browse files",
        "Generate password",
        "Choose folder",
        "Offline encryption · Originals always kept",
    ] {
        let rect = labels.iter().find(|(text, _)| text == label).unwrap().1;
        assert!(
            rect.min.x >= 0.0 && rect.max.x <= 480.5 && rect.min.y >= 0.0 && rect.max.y <= 540.5,
            "{label}: {rect:?}"
        );
    }
}
#[test]
fn generated_password_controls_fit_compact_window() {
    let mut app = PebbleCrypt::default();
    let ctx = context();
    app.set_generated_password("x".repeat(24), &ctx);
    let _ = render(&mut app, &ctx, [480.0, 540.0], vec![]);
    let output = render(&mut app, &ctx, [480.0, 540.0], vec![]);
    let labels = text_rects(&output);
    let rect = labels
        .iter()
        .find(|(text, _)| text == "I have saved this password somewhere safe.")
        .unwrap()
        .1;
    assert!(rect.max.x <= 480.5 && rect.max.y <= 540.5);
}
#[test]
fn gui_generate_button_updates_both_fields() {
    let mut app = PebbleCrypt::default();
    let ctx = context();
    click_text(&mut app, &ctx, "Generate password");
    assert_eq!(app.password.len(), 24);
    assert_eq!(app.password, app.confirmation);
    assert!(app.generated && !app.password_saved);
}
#[test]
fn gui_mode_button_clears_password() {
    let mut app = ready();
    let ctx = context();
    click_text(&mut app, &ctx, "Decrypt files");
    assert_eq!(app.mode, Mode::Decrypt);
    assert!(app.password.is_empty());
}
#[test]
fn gui_clear_button_clears_queue_and_password() {
    let mut app = ready();
    let ctx = context();
    click_text(&mut app, &ctx, "Clear");
    assert!(app.files.is_empty() && app.password.is_empty());
}
#[test]
fn gui_cancel_button_signals_worker() {
    let mut app = ready();
    let _tx = attach_channel(&mut app);
    let ctx = context();
    click_text(&mut app, &ctx, "Cancel");
    assert!(app.cancel.load(Ordering::Relaxed));
    assert!(app.status.starts_with("Cancelling"));
}
#[test]
fn compact_long_filename_keeps_remove_button_visible() {
    let mut app = ready();
    app.files = vec![PathBuf::from(format!("{}.txt", "long-name".repeat(20)))];
    let ctx = context();
    let _ = render(&mut app, &ctx, [440.0, 460.0], vec![]);
    let output = render(&mut app, &ctx, [440.0, 460.0], vec![]);
    let labels = text_rects(&output);
    let rect = labels.iter().find(|(text, _)| text == "×").unwrap().1;
    assert!(rect.max.x <= 440.5 && rect.max.y <= 460.5);
}
#[test]
fn rendering_uses_cached_sizes_after_source_disappears() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    fs::write(&path, b"123456").unwrap();
    let mut app = PebbleCrypt::default();
    let ctx = context();
    app.add_files(vec![path.clone()], &ctx);
    fs::remove_file(path).unwrap();
    let _ = render(&mut app, &ctx, [480.0, 540.0], vec![]);
    assert_eq!(app.total_file_size(), 6);
}
#[test]
fn cancelled_without_outputs_remains_visible() {
    let mut app = PebbleCrypt::default();
    let tx = attach_channel(&mut app);
    tx.send(Event::Finished {
        outputs: vec![],
        error: None,
        cancelled: true,
    })
    .unwrap();
    app.poll();
    let output = render(&mut app, &context(), [480.0, 540.0], vec![]);
    assert!(
        text_rects(&output)
            .iter()
            .any(|(s, _)| s.starts_with("Cancelled."))
    );
}
