#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod batch;
mod crypto;

#[cfg(test)]
mod app_tests;

use age::secrecy::SecretString;
use crypto::Mode;
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const BG: Color32 = Color32::from_rgb(15, 23, 28);
const CARD: Color32 = Color32::from_rgb(23, 34, 40);
const LINE: Color32 = Color32::from_rgb(46, 65, 72);
const TEXT: Color32 = Color32::from_rgb(233, 240, 241);
const MUTED: Color32 = Color32::from_rgb(153, 172, 180);
const ACCENT: Color32 = Color32::from_rgb(151, 230, 201);
const ERROR: Color32 = Color32::from_rgb(255, 166, 153);

fn main() {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/pebblecrypt.png"))
        .expect("embedded icon");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 540.0])
            .with_min_inner_size([440.0, 460.0])
            .with_icon(icon)
            .with_drag_and_drop(true),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    if let Err(error) = eframe::run_native(
        "PebbleCrypt",
        options,
        Box::new(|cc| Ok(Box::new(PebbleCrypt::new(cc)))),
    ) {
        rfd::MessageDialog::new()
            .set_title("PebbleCrypt could not start")
            .set_description(format!("The app could not open its window.\n\n{error}"))
            .set_level(rfd::MessageLevel::Error)
            .show();
    }
}

enum Event {
    Progress(f32, String),
    Finished {
        outputs: Vec<PathBuf>,
        error: Option<String>,
        cancelled: bool,
    },
}

#[derive(Default)]
struct PebbleCrypt {
    mode: Mode,
    files: Vec<PathBuf>,
    file_sizes: HashMap<PathBuf, u64>,
    destination: Option<PathBuf>,
    password: String,
    confirmation: String,
    show_password: bool,
    generated: bool,
    password_saved: bool,
    receiver: Option<Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    progress: f32,
    status: String,
    error: bool,
    outputs: Vec<PathBuf>,
    about: bool,
    password_epoch: u64,
}

impl PebbleCrypt {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let mut app = Self {
            status: "Ready when you are.".into(),
            ..Default::default()
        };
        app.add_files(
            std::env::args_os().skip(1).map(PathBuf::from).collect(),
            &cc.egui_ctx,
        );
        app
    }

    fn busy(&self) -> bool {
        self.receiver.is_some()
    }

    fn clear_password(&mut self, ctx: &egui::Context) {
        self.password.zeroize();
        self.confirmation.zeroize();
        // Drop text edit undo state, which could otherwise restore a cleared password.
        for name in ["password", "confirmation"] {
            let id = egui::Id::new((name, self.password_epoch));
            ctx.data_mut(|data| data.remove::<egui::text_edit::TextEditState>(id));
        }
        self.password_epoch += 1;
        self.show_password = false;
        self.generated = false;
        self.password_saved = false;
    }

    fn clear_files(&mut self, ctx: &egui::Context) {
        self.files.clear();
        self.file_sizes.clear();
        self.outputs.clear();
        self.progress = 0.0;
        self.error = false;
        self.status = "Ready when you are.".into();
        self.clear_password(ctx);
    }

    fn set_mode(&mut self, mode: Mode, ctx: &egui::Context) {
        if self.mode != mode {
            self.mode = mode;
            self.clear_password(ctx);
            self.outputs.clear();
            self.progress = 0.0;
            self.error = false;
            self.status = "Ready when you are.".into();
        }
    }

    fn set_generated_password(&mut self, password: String, ctx: &egui::Context) {
        self.clear_password(ctx);
        self.confirmation = password.clone();
        self.password = password;
        self.show_password = true;
        self.generated = true;
    }

    fn total_file_size(&self) -> u64 {
        self.file_sizes
            .values()
            .copied()
            .fold(0, u64::saturating_add)
    }

    fn add_files(&mut self, paths: Vec<PathBuf>, ctx: &egui::Context) {
        if self.busy() || paths.is_empty() {
            return;
        }
        let was_empty = self.files.is_empty();
        let mut rejected = 0;
        for path in paths {
            if path.is_file() {
                let path = path.canonicalize().unwrap_or(path);
                if !self.files.contains(&path) {
                    self.file_sizes
                        .insert(path.clone(), crypto::file_size(&path));
                    self.files.push(path);
                }
            } else {
                rejected += 1;
            }
        }
        if was_empty && !self.files.is_empty() {
            let mode = if self
                .files
                .iter()
                .all(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("age")))
            {
                Mode::Decrypt
            } else {
                Mode::Encrypt
            };
            self.set_mode(mode, ctx);
        }
        self.outputs.clear();
        self.progress = 0.0;
        self.error = rejected > 0;
        self.status = if rejected > 0 {
            "Folders cannot be added directly. Zip a folder first.".into()
        } else {
            "Files added. Set your password to continue.".into()
        };
    }

    fn pick_files(&mut self, ctx: &egui::Context) {
        let dialog = rfd::FileDialog::new().set_title("Choose files for PebbleCrypt");
        if let Some(files) = dialog.pick_files() {
            self.add_files(files, ctx);
        }
    }

    fn validation(&self) -> Option<&'static str> {
        if self.files.is_empty() {
            return Some("Add files to get started.");
        }
        if self.password.is_empty() {
            return Some("Enter your password.");
        }
        if self.mode == Mode::Encrypt {
            if self.password.chars().count() < 12 {
                return Some("Use at least 12 characters; a long, unique passphrase is best.");
            }
            if self.password != self.confirmation {
                return Some("The two passwords must match.");
            }
            if self.generated && !self.password_saved {
                return Some("Save the generated password and check its confirmation box.");
            }
        }
        None
    }

    fn start(&mut self, ctx: &egui::Context) {
        if self.busy() || self.validation().is_some() {
            return;
        }
        let jobs = match crypto::plan_jobs(&self.files, self.destination.as_deref(), self.mode) {
            Ok(jobs) => jobs,
            Err(error) => {
                self.status = error;
                self.error = true;
                return;
            }
        };
        let password = SecretString::from(std::mem::take(&mut self.password));
        self.clear_password(ctx);
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        self.progress = 0.0;
        self.error = false;
        self.outputs.clear();
        self.status = "Preparing password…".into();
        let cancelled = self.cancel.clone();
        let context = ctx.clone();
        let mode = self.mode;
        let spawned = std::thread::Builder::new()
            .name("pebblecrypt-worker".into())
            .spawn(move || {
                let mut last_update = Instant::now();
                let report = batch::run(&jobs, mode, password, &cancelled, &mut |update| {
                    if update.preparing || last_update.elapsed() >= Duration::from_millis(70) {
                        let (fraction, message) = if update.preparing {
                            (
                                0.0,
                                format!(
                                    "Preparing password · File {} of {}",
                                    update.index + 1,
                                    update.count
                                ),
                            )
                        } else {
                            let fraction = if update.total == 0 {
                                0.0
                            } else {
                                (update.done as f64 / update.total as f64).min(0.99) as f32
                            };
                            let action = if mode == Mode::Encrypt {
                                "Encrypting"
                            } else {
                                "Decrypting"
                            };
                            let name = jobs[update.index]
                                .input
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy();
                            (
                                fraction,
                                format!(
                                    "{action} {name} · {} of {}",
                                    update.index + 1,
                                    update.count
                                ),
                            )
                        };
                        let _ = tx.send(Event::Progress(
                            (update.index as f32 + fraction) / update.count as f32,
                            message,
                        ));
                        context.request_repaint();
                        last_update = Instant::now();
                    }
                });
                let _ = tx.send(Event::Finished {
                    outputs: report.outputs,
                    error: report.error,
                    cancelled: report.cancelled,
                });
                context.request_repaint();
            });
        if let Err(error) = spawned {
            self.receiver = None;
            self.error = true;
            self.status = format!("Could not start the worker: {error}. No files were processed.");
        }
    }

    fn poll(&mut self) {
        let mut events = Vec::new();
        let mut disconnected = false;
        if let Some(receiver) = &self.receiver {
            loop {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        for event in events {
            match event {
                Event::Progress(value, message) => {
                    self.progress = value;
                    if !self.cancel.load(Ordering::Relaxed) {
                        self.status = message;
                    }
                }
                Event::Finished {
                    outputs,
                    error,
                    cancelled,
                } => {
                    self.receiver = None;
                    self.outputs = outputs;
                    self.error = error.is_some();
                    let n = self.outputs.len();
                    self.status = if let Some(message) = error {
                        format!("{message}\n{n} completed file(s) kept. Originals are unchanged.")
                    } else if cancelled {
                        format!("Cancelled. {n} completed file(s) kept. Originals are unchanged.")
                    } else {
                        self.progress = 1.0;
                        format!(
                            "All done. {n} file(s) {}. Originals are unchanged.",
                            if self.mode == Mode::Encrypt {
                                "encrypted"
                            } else {
                                "decrypted"
                            }
                        )
                    };
                }
            }
        }
        if disconnected && self.busy() {
            self.receiver = None;
            self.error = true;
            self.status = "The worker stopped unexpectedly. Check the output folder for completed files. Originals are unchanged.".into();
        }
    }

    fn files_card(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Files").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Browse files").clicked() {
                        self.pick_files(ui.ctx());
                    }
                    if !self.files.is_empty() && ui.small_button("Clear").clicked() {
                        self.clear_files(ui.ctx());
                    }
                });
            });
            if self.files.is_empty() {
                let (rect, response) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 54.0),
                    egui::Sense::click(),
                );
                ui.painter().rect_filled(rect, 10, BG);
                ui.painter().rect_stroke(
                    rect,
                    10,
                    Stroke::new(1.0, if response.hovered() { ACCENT } else { LINE }),
                    egui::StrokeKind::Inside,
                );
                ui.painter().text(
                    rect.center() - Vec2::new(0.0, 8.0),
                    egui::Align2::CENTER_CENTER,
                    "Drop files here",
                    FontId::proportional(15.0),
                    TEXT,
                );
                ui.painter().text(
                    rect.center() + Vec2::new(0.0, 12.0),
                    egui::Align2::CENTER_CENTER,
                    "or click to browse · zip folders first",
                    FontId::proportional(11.0),
                    MUTED,
                );
                if response.clicked() {
                    self.pick_files(ui.ctx());
                }
            } else {
                let mut remove = None;
                egui::ScrollArea::vertical()
                    .id_salt("files")
                    .max_height(72.0)
                    .show(ui, |ui| {
                        for (index, file) in self.files.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(if self.mode == Mode::Encrypt {
                                        "FILE"
                                    } else {
                                        "AGE"
                                    })
                                    .size(10.0)
                                    .color(ACCENT),
                                );
                                let label = file.file_name().unwrap_or_default().to_string_lossy();
                                // Reserve room for size and removal in the compact window.
                                let name_width = (ui.available_width() - 108.0).max(60.0);
                                ui.add_sized(
                                    [name_width, 26.0],
                                    egui::Label::new(label).truncate(),
                                )
                                .on_hover_text(file.display().to_string());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .small_button("×")
                                            .on_hover_text("Remove file")
                                            .clicked()
                                        {
                                            remove = Some(index);
                                        }
                                        ui.label(
                                            RichText::new(format_size(
                                                self.file_sizes.get(file).copied().unwrap_or(0),
                                            ))
                                            .small()
                                            .color(MUTED),
                                        );
                                    },
                                );
                            });
                        }
                    });
                if let Some(index) = remove {
                    let path = self.files.remove(index);
                    self.file_sizes.remove(&path);
                    if self.files.is_empty() {
                        self.clear_files(ui.ctx());
                    }
                }
                ui.label(
                    RichText::new(format!(
                        "{} file(s) · {} total",
                        self.files.len(),
                        format_size(self.total_file_size())
                    ))
                    .small()
                    .color(MUTED),
                );
            }
        });
    }

    fn password_card(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let width = if self.mode == Mode::Encrypt {
                (ui.available_width() - ui.spacing().item_spacing.x) / 2.0
            } else {
                ui.available_width()
            };
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("Password").small().color(MUTED));
                    let changed = ui
                        .add_sized(
                            [width, 28.0],
                            egui::TextEdit::singleline(&mut self.password)
                                .id(egui::Id::new(("password", self.password_epoch)))
                                .password(!self.show_password)
                                .char_limit(1024)
                                .hint_text(if self.mode == Mode::Encrypt {
                                    "At least 12 characters"
                                } else {
                                    "Enter the original password"
                                }),
                        )
                        .changed();
                    if changed {
                        self.generated = false;
                        self.password_saved = false;
                    }
                });
                if self.mode == Mode::Encrypt {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Confirm password").small().color(MUTED));
                        ui.add_sized(
                            [width, 28.0],
                            egui::TextEdit::singleline(&mut self.confirmation)
                                .id(egui::Id::new(("confirmation", self.password_epoch)))
                                .password(!self.show_password)
                                .char_limit(1024)
                                .hint_text("Enter it again"),
                        );
                    });
                }
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.show_password, "Show password");
                if self.mode == Mode::Encrypt {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Generate password").clicked() {
                            match crypto::generated_password() {
                                Ok(password) => {
                                    self.set_generated_password(password, ui.ctx());
                                }
                                Err(error) => {
                                    self.error = true;
                                    self.status = error;
                                }
                            }
                        }
                    });
                }
            });
            if self.generated {
                ui.checkbox(
                    &mut self.password_saved,
                    "I have saved this password somewhere safe.",
                );
            }
            ui.label(
                RichText::new("Keep your password safe. Lost passwords cannot be recovered.")
                    .small()
                    .color(MUTED),
            );
        });
    }

    fn destination_card(&mut self, ui: &mut egui::Ui) {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Output").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Choose folder").clicked()
                        && let Some(folder) = rfd::FileDialog::new()
                            .set_title("Save processed files in…")
                            .pick_folder()
                    {
                        self.destination = Some(folder);
                    }
                    if self.destination.is_some() && ui.small_button("Reset").clicked() {
                        self.destination = None;
                    }
                });
            });
            let location = self
                .destination
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "Same folder as each original file".into());
            ui.add(egui::Label::new(RichText::new(&location).color(MUTED)).truncate())
                .on_hover_text(location);
        });
    }
}

impl eframe::App for PebbleCrypt {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll();
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
            if ctx.input(|i| i.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.status = "An operation is running. Click Cancel, wait for it to finish, then close the app.".into();
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        self.render(ui);
    }

    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl PebbleCrypt {
    fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if !self.busy() {
            let dropped: Vec<_> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect()
            });
            self.add_files(dropped, &ctx);
            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::O)) {
                self.pick_files(ui.ctx());
            }
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(12))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("PebbleCrypt").size(21.0).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("About").clicked() {
                                self.about = true;
                            }
                            ui.label(RichText::new("LOCAL & OFFLINE").size(10.0).color(ACCENT));
                        });
                    });
                    ui.add_space(2.0);
                    let busy = self.busy();
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.horizontal(|ui| {
                            for (mode, label) in [
                                (Mode::Encrypt, "Encrypt files"),
                                (Mode::Decrypt, "Decrypt files"),
                            ] {
                                let selected = self.mode == mode;
                                let button =
                                    egui::Button::new(RichText::new(label).color(if selected {
                                        BG
                                    } else {
                                        TEXT
                                    }))
                                    .fill(if selected { ACCENT } else { CARD })
                                    .corner_radius(8);
                                if ui.add_sized([110.0, 28.0], button).clicked()
                                    && self.mode != mode
                                {
                                    self.set_mode(mode, &ctx);
                                }
                            }
                        });
                        self.files_card(ui);
                        self.password_card(ui);
                        self.destination_card(ui);
                    });
                    ui.add_space(2.0);
                    if busy {
                        ui.add(
                            egui::ProgressBar::new(self.progress)
                                .desired_width(ui.available_width())
                                .fill(ACCENT)
                                .show_percentage(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    !self.cancel.load(Ordering::Relaxed),
                                    egui::Button::new("Cancel"),
                                )
                                .clicked()
                            {
                                self.cancel.store(true, Ordering::Relaxed);
                                self.status =
                                    "Cancelling… Password setup may need a moment to finish."
                                        .into();
                            }
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.spinner();
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&self.status).small().color(MUTED),
                                        )
                                        .wrap(),
                                    );
                                },
                            );
                        });
                    } else {
                        let validation = self.validation();
                        let label = if self.mode == Mode::Encrypt {
                            "Encrypt files"
                        } else {
                            "Decrypt files"
                        };
                        if ui
                            .add_enabled(
                                validation.is_none(),
                                egui::Button::new(
                                    RichText::new(label).size(14.0).strong().color(BG),
                                )
                                .fill(ACCENT)
                                .corner_radius(8)
                                .min_size(Vec2::new(ui.available_width(), 34.0)),
                            )
                            .clicked()
                        {
                            self.start(&ctx);
                        }
                        let has_result = self.error
                            || !self.outputs.is_empty()
                            || self.status.starts_with("Cancelled.");
                        if let Some(hint) = validation.filter(|_| !has_result) {
                            ui.label(RichText::new(hint).small().color(MUTED));
                        }
                        if has_result {
                            ui.label(RichText::new(&self.status).small().color(if self.error {
                                ERROR
                            } else if !self.outputs.is_empty() {
                                ACCENT
                            } else {
                                MUTED
                            }));
                        }
                        if !self.outputs.is_empty() {
                            if ui.button("Show output folder").clicked()
                                && let Some(folder) = self.outputs[0].parent()
                                && let Err(error) = std::process::Command::new("explorer.exe")
                                    .arg(folder)
                                    .spawn()
                            {
                                self.status = format!("Could not open the folder: {error}");
                                self.error = true;
                            }
                            egui::CollapsingHeader::new("Completed files").show(ui, |ui| {
                                for output in &self.outputs {
                                    ui.label(output.display().to_string());
                                }
                            });
                        }
                    }
                    ui.add_space(2.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Offline encryption · Originals always kept")
                                .small()
                                .color(MUTED),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                                    .small()
                                    .color(MUTED),
                            );
                        });
                    });
                });
            });
        if self.about {
            egui::Window::new("About PebbleCrypt").open(&mut self.about).resizable(false).collapsible(false).default_width(420.0).show(&ctx, |ui| {
                ui.heading("Small app. Standard encryption.");
                ui.label("PebbleCrypt is a Rust desktop app inspired by PicoCrypt's simple workflow. It uses the age file format with scrypt and authenticated ChaCha20-Poly1305 encryption.");
                ui.label("Opens binary, password-encrypted .age files. PicoCrypt .pcv files and age recipient keys are not supported.");
                ui.label("Nothing is uploaded. Original files are kept. File names and approximate sizes remain visible; rename files if that matters.");
                ui.label("This app has not been independently security-audited. Keep backups and test decryption before relying on it.");
                ui.label("Decryption uses a temporary file in the output folder. Normal cancellation cleans it up; a crash or power loss may leave a .pebblecrypt-*.partial file. This app does not securely erase disk data.");
                ui.label(RichText::new("Built with Rust, egui and age. MIT license.").small().color(MUTED));
            });
        }
        if !ctx.input(|i| i.raw.hovered_files.is_empty()) && !self.busy() {
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("file-drop"),
            ));
            let rect = ctx.content_rect();
            painter.rect_filled(rect, 0, Color32::from_rgba_unmultiplied(15, 35, 32, 235));
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Drop to add files",
                FontId::proportional(30.0),
                ACCENT,
            );
        }
    }
}

fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(8)
        .inner_margin(9)
}
fn format_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{size} bytes")
    }
}

fn configure_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = Vec2::new(6.0, 6.0);
    style.spacing.button_padding = Vec2::new(9.0, 5.0);
    style.spacing.interact_size.y = 26.0;
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, FontId::proportional(11.0));
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = CARD;
    style.visuals.extreme_bg_color = BG;
    style.visuals.faint_bg_color = CARD;
    style.visuals.selection.bg_fill = Color32::from_rgb(43, 88, 79);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(34, 48, 55);
    style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(34, 48, 55);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(47, 69, 73);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(47, 69, 73);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    ctx.set_global_style(style);
}
