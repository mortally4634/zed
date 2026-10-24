//! ZedCompress GUI (`zed-gui`) - a sleek, minimal egui front-end.
//! Build: cargo build --release --features gui --bin zed-gui

use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use zedcompress::{compress, extract, human, Cipher, Filter, Format};

const CIPHERS: [(Cipher, &str); 3] = [
    (Cipher::Rabbit, "Rabbit (default)"),
    (Cipher::ChaCha20, "ChaCha20"),
    (Cipher::Aes256Ctr, "AES-256-CTR"),
];
const FORMATS: [(&str, &str); 3] = [
    (".zed", "  .zed — best, encryptable"),
    (".tar.xz", "  .tar.xz — standard"),
    (".zip", "  .zip — compatible"),
];

struct App {
    inputs: Vec<PathBuf>,
    level: u32,
    cipher_idx: usize,
    fmt_idx: usize,
    password: String,
    show_pw: bool,
    keyfile: Option<PathBuf>,
    status: String,
    working: bool,
    rx: Option<Receiver<String>>,
}

impl Default for App {
    fn default() -> Self {
        App {
            inputs: Vec::new(),
            level: 9,
            cipher_idx: 0,
            fmt_idx: 0,
            password: String::new(),
            show_pw: false,
            keyfile: None,
            status: "Ready.".into(),
            working: false,
            rx: None,
        }
    }
}

impl App {
    fn fmt(&self) -> Format {
        match self.fmt_idx {
            1 => Format::TarXz,
            2 => Format::Zip,
            _ => Format::Zed,
        }
    }

    fn start(&mut self, work: impl FnOnce() -> String + Send + 'static) {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.working = true;
        std::thread::spawn(move || {
            let _ = tx.send(work());
        });
    }

    fn do_compress(&mut self) {
        if self.inputs.is_empty() {
            self.status = "Add some files or folders first.".into();
            return;
        }
        let (ext, _) = FORMATS[self.fmt_idx];
        let Some(out) = rfd::FileDialog::new()
            .set_file_name(format!("archive{ext}"))
            .save_file()
        else {
            return;
        };
        let fmt = self.fmt();
        let pw = self.password.clone();
        let encrypt = !pw.is_empty() && fmt.supports_encryption();
        if !pw.is_empty() && !fmt.supports_encryption() {
            self.status = "Encryption is only available for .zed — password ignored.".into();
        }
        let inputs = self.inputs.clone();
        let level = self.level;
        let cipher = CIPHERS[self.cipher_idx].0;
        let keyfile = self.keyfile.clone();
        let cname = CIPHERS[self.cipher_idx].1;
        self.status = "Compressing…".into();
        self.start(move || {
            let pw_opt = if encrypt { Some(pw.as_str()) } else { None };
            match compress(&inputs, &out, level, pw_opt, keyfile.as_deref(), cipher, Filter::Auto, fmt) {
                Ok((orig, size, _used)) => {
                    let ratio = if size > 0 { orig as f64 / size as f64 } else { 0.0 };
                    let saved = if orig > 0 { 100.0 * (1.0 - size as f64 / orig as f64) } else { 0.0 };
                    let enc = if encrypt { format!("  · encrypted ({cname})") } else { String::new() };
                    format!(
                        "✓ {} → {}   ratio {:.1}×   saved {:.1}%{}",
                        human(orig as f64), human(size as f64), ratio, saved, enc
                    )
                }
                Err(e) => format!("Error: {e}"),
            }
        });
    }

    fn do_extract(&mut self) {
        let Some(archive) = rfd::FileDialog::new()
            .add_filter("Archives", &["zed", "zip", "xz", "txz"])
            .pick_file()
        else {
            return;
        };
        let Some(outdir) = rfd::FileDialog::new().set_title("Extract into folder").pick_folder() else {
            return;
        };
        let pw = self.password.clone();
        let keyfile = self.keyfile.clone();
        self.status = "Extracting…".into();
        self.start(move || {
            let pw_opt = if pw.is_empty() { None } else { Some(pw.as_str()) };
            match extract(&archive, &outdir, pw_opt, keyfile.as_deref()) {
                Ok(()) => format!("✓ Extracted to {}", outdir.display()),
                Err(e) => format!("Error: {e}"),
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(msg) => {
                    self.status = msg;
                    self.working = false;
                    self.rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint(); // keep polling the worker
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // worker panicked without sending - don't spin forever
                    self.status = "Operation failed unexpectedly.".into();
                    self.working = false;
                    self.rx = None;
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("ZedCompress");
            ui.label(
                egui::RichText::new("Solid LZMA archiver · Rabbit / ChaCha20 / AES-256 encryption")
                    .weak(),
            );
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui.button("Add Files").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        for f in files {
                            if !self.inputs.contains(&f) {
                                self.inputs.push(f);
                            }
                        }
                    }
                }
                if ui.button("Add Folder").clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        if !self.inputs.contains(&d) {
                            self.inputs.push(d);
                        }
                    }
                }
                if ui.button("Clear").clicked() {
                    self.inputs.clear();
                }
            });

            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::ScrollArea::vertical().min_scrolled_height(160.0).max_height(200.0).show(ui, |ui| {
                    ui.set_min_height(160.0);
                    if self.inputs.is_empty() {
                        ui.weak("No files added yet.");
                    }
                    let mut remove = None;
                    for (i, p) in self.inputs.iter().enumerate() {
                        ui.horizontal(|ui| {
                            let icon = if p.is_dir() { "📁" } else { "📄" };
                            if ui.small_button("✕").clicked() {
                                remove = Some(i);
                            }
                            ui.monospace(format!("{icon} {}", p.display()));
                        });
                    }
                    if let Some(i) = remove {
                        self.inputs.remove(i);
                    }
                });
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_source("fmt")
                    .selected_text(FORMATS[self.fmt_idx].0)
                    .show_ui(ui, |ui| {
                        for (i, (_, label)) in FORMATS.iter().enumerate() {
                            ui.selectable_value(&mut self.fmt_idx, i, *label);
                        }
                    });
                ui.add(egui::Slider::new(&mut self.level, 0..=9).text("level"));
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Encrypt:");
                egui::ComboBox::from_id_source("cipher")
                    .selected_text(CIPHERS[self.cipher_idx].1)
                    .show_ui(ui, |ui| {
                        for (i, (_, label)) in CIPHERS.iter().enumerate() {
                            ui.selectable_value(&mut self.cipher_idx, i, *label);
                        }
                    });
            });
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_pw).desired_width(220.0));
                ui.checkbox(&mut self.show_pw, "show");
            });
            ui.horizontal(|ui| {
                if ui.button("Key file…").clicked() {
                    self.keyfile = rfd::FileDialog::new().pick_file();
                }
                match &self.keyfile {
                    Some(k) => {
                        ui.monospace(k.file_name().unwrap_or_default().to_string_lossy());
                        if ui.small_button("✕").clicked() {
                            self.keyfile = None;
                        }
                    }
                    None => {
                        ui.weak("(optional)");
                    }
                }
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!self.working, |ui| {
                    if ui.add(egui::Button::new("  Compress  ")).clicked() {
                        self.do_compress();
                    }
                    if ui.button("  Extract…  ").clicked() {
                        self.do_extract();
                    }
                });
                if self.working {
                    ui.spinner();
                }
            });

            ui.add_space(10.0);
            ui.separator();
            ui.label(&self.status);
            ui.add_space(6.0);
            ui.weak(
                "Honest note: huge ratios only happen on redundant data — random or already-\
                 compressed data barely shrinks, and encrypted data will not compress at all.",
            );
        });
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 640.0])
            .with_min_inner_size([640.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("ZedCompress", opts, Box::new(|_cc| Ok(Box::<App>::default())))
}
