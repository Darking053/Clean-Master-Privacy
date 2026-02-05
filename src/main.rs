#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::sync::mpsc::{Receiver, Sender, self};
use std::thread;
use rfd::FileDialog;
use chrono::Local;

#[derive(PartialEq)]
enum NavPage { Dashboard, Scanner, Privacy, Logs }

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([950.0, 650.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title_shown(true),
        ..Default::default()
    };
    
    eframe::run_native(
        "Clean-Master-Privacy Pro",
        options,
        Box::new(|_cc| {
            setup_custom_fonts(&_cc.egui_ctx);
            _cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(ClamRustApp::new())
        }),
    )
}

struct ClamRustApp {
    page: NavPage,
    is_scanning: bool,
    logs: Vec<String>,
    rx: Receiver<String>,
    tx: Sender<String>,
    
    // Analiz Verileri
    scanned_count: usize,
    threat_count: usize,
    current_path: String,
    progress: f32,
    disk_speed: String,
}

impl ClamRustApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            page: NavPage::Dashboard,
            is_scanning: false,
            logs: vec![],
            rx,
            tx,
            scanned_count: 0,
            threat_count: 0,
            current_path: String::from("System Idle"),
            progress: 0.0,
            disk_speed: String::from("0 file/s"),
        }
    }

    fn run_scan(&mut self, ctx: egui::Context, target: String) {
        self.is_scanning = true;
        self.scanned_count = 0;
        self.threat_count = 0;
        let tx = self.tx.clone();

        thread::spawn(move || {
            let mut child = Command::new("clamscan")
                .args(["-r", "--no-summary", &target])
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start scanner engine");

            let reader = BufReader::new(child.stdout.take().unwrap());
            for line in reader.lines() {
                if let Ok(l) = line {
                    if l.contains("FOUND") {
                        let _ = tx.send(format!("FOUND:{}", l));
                    } else {
                        let _ = tx.send(format!("FILE:{}", l));
                    }
                    ctx.request_repaint();
                }
            }
            let _ = tx.send("FINISH:1".to_string());
        });
    }
}

impl eframe::App for ClamRustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Background Process Listener
        while let Ok(msg) = self.rx.try_recv() {
            if msg.starts_with("FILE:") {
                self.scanned_count += 1;
                self.current_path = msg.replace("FILE:", "").replace(": OK", "");
            } else if msg.starts_with("FOUND:") {
                self.threat_count += 1;
                let timestamp = Local::now().format("%H:%M:%S").to_string();
                self.logs.push(format!("[{}] ⚠️ THREAT: {}", timestamp, msg.replace("FOUND:", "")));
            } else if msg.starts_with("FINISH") {
                self.is_scanning = false;
                self.current_path = "Scan Complete".into();
            }
        }

        // Sidebar Navigation
        egui::SidePanel::left("nav_panel").resizable(false).default_width(220.0).show(ctx, |ui| {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("🛡️ CMP PRO").size(24.0).strong().color(egui::Color32::from_rgb(0, 150, 255)));
                ui.label("Enterprise Security");
            });
            ui.add_space(40.0);

            ui.vertical(|ui| {
                ui.style_mut().spacing.item_spacing.y = 10.0;
                ui.selectable_value(&mut self.page, NavPage::Dashboard, "📊 Dashboard");
                ui.selectable_value(&mut self.page, NavPage::Scanner, "🔍 Scan Engine");
                ui.selectable_value(&mut self.page, NavPage::Privacy, "🧹 Privacy Guard");
                ui.selectable_value(&mut self.page, NavPage::Logs, "📜 Security Logs");
            });

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(20.0);
                if ui.button("🌐 Check Updates").clicked() {}
                ui.separator();
            });
        });

        // Main Content Area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.page {
                NavPage::Dashboard => self.render_dashboard(ui),
                NavPage::Scanner => self.render_scanner(ui, ctx),
                NavPage::Privacy => self.render_privacy(ui),
                NavPage::Logs => self.render_logs(ui),
            }
        });
    }
}

impl ClamRustApp {
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Overview");
        ui.add_space(20.0);

        egui::Grid::new("dash_grid").spacing([20.0, 20.0]).show(ui, |ui| {
            // Status Card
            ui.group(|ui| {
                ui.set_min_size(egui::vec2(280.0, 140.0));
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    let color = if self.threat_count > 0 { egui::Color32::RED } else { egui::Color32::GREEN };
                    ui.label(egui::RichText::new(if self.threat_count > 0 { "⚠️ ACTION REQUIRED" } else { "✅ SYSTEM SECURE" }).color(color).strong());
                    ui.add_space(10.0);
                    ui.label(format!("Scanned: {} files", self.scanned_count));
                    ui.label(format!("Threats: {}", self.threat_count));
                });
            });

            // Quick Actions Card
            ui.group(|ui| {
                ui.set_min_size(egui::vec2(280.0, 140.0));
                ui.vertical(|ui| {
                    ui.strong("Quick Actions");
                    if ui.button("⚡ Fast Optimizer").clicked() {}
                    if ui.button("🛡️ Update Database").clicked() {}
                });
            });
            ui.end_row();
        });
    }

    fn render_scanner(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Analysis Engine");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.add_enabled(!self.is_scanning, egui::Button::new("📂 Custom Scan")).clicked() {
                if let Some(path) = FileDialog::new().pick_folder() {
                    self.run_scan(ctx.clone(), path.display().to_string());
                }
            }
            if self.is_scanning { ui.spinner(); }
        });

        ui.add_space(20.0);
        
        // Progress Section
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new("Current Object:").strong());
            ui.label(egui::RichText::new(&self.current_path).monospace().size(11.0));
            ui.add_space(10.0);
            ui.add(egui::ProgressBar::new(0.5).animated(self.is_scanning).text("Heuristic Analysis Active"));
        });

        ui.add_space(20.0);
        ui.label("Detection Stream:");
        egui::Frame::none().fill(egui::Color32::from_black_alpha(100)).show(ui, |ui| {
            egui::ScrollArea::vertical().max_height(200.0).stick_to_bottom(true).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                for log in self.logs.iter().rev().take(10) {
                    ui.colored_label(egui::Color32::LIGHT_RED, log);
                }
            });
        });
    }

    fn render_privacy(&mut self, ui: &mut egui::Ui) {
        ui.heading("Privacy Cleanup");
        ui.add_space(20.0);
        ui.label("Deep cleaning will remove trackers and temporary system files.");
        
        static mut JUNK: bool = true;
        static mut TRACKERS: bool = true;
        unsafe {
            ui.checkbox(&mut JUNK, "System Junk (Logs & Cache)");
            ui.checkbox(&mut TRACKERS, "Browser Trackers");
        }
        
        ui.add_space(20.0);
        if ui.add_sized([180.0, 40.0], egui::Button::new("🚀 Start Cleanup")).clicked() {}
    }

    fn render_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Event History");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for log in &self.logs {
                ui.label(log);
            }
        });
    }
}

fn setup_custom_fonts(_ctx: &egui::Context) {
    // Burada özel fontlar eklenebilir
}
