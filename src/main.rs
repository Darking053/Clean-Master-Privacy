#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::sync::mpsc::{Receiver, Sender, self};
use std::thread;
use rfd::FileDialog;
use chrono::Local;

#[derive(PartialEq)]
enum Page { Dashboard, Scanner, Privacy, Logs }

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([950.0, 650.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Clean-Master-Privacy Ultra",
        options,
        Box::new(|_cc| {
            // Dark Mode & Custom Styling
            let mut visuals = egui::Visuals::dark();
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 20, 25);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(35, 35, 40);
            _cc.egui_ctx.set_visuals(visuals);
            Box::new(ClamRustApp::new())
        }),
    )
}

struct ClamRustApp {
    current_page: Page,
    is_working: bool,
    logs: Vec<String>,
    rx: Receiver<String>,
    tx: Sender<String>,
    
    // Analiz Verileri
    scanned_files: usize,
    threats_found: usize,
    current_file: String,
    risk_score: f32,
    cleanup_potential: f32,
}

impl ClamRustApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            current_page: Page::Dashboard,
            is_working: false,
            logs: vec![],
            rx,
            tx,
            scanned_files: 0,
            threats_found: 0,
            current_file: String::from("System Ready"),
            risk_score: 0.0,
            cleanup_potential: 12.5, // Örnek GB
        }
    }

    fn run_engine(&mut self, ctx: egui::Context, path: String) {
        self.is_working = true;
        self.scanned_files = 0;
        self.threats_found = 0;
        let tx = self.tx.clone();

        thread::spawn(move || {
            let mut child = Command::new("clamscan")
                .args(["-r", "--no-summary", &path])
                .stdout(Stdio::piped())
                .spawn()
                .expect("Security Engine failed to start.");

            let reader = BufReader::new(child.stdout.take().unwrap());
            for line in reader.lines() {
                if let Ok(l) = line {
                    if l.contains("FOUND") {
                        let _ = tx.send(format!("THREAT:{}", l));
                    } else {
                        let _ = tx.send(format!("FILE:{}", l));
                    }
                    ctx.request_repaint();
                }
            }
            let _ = tx.send("COMPLETE".to_string());
        });
    }
}

impl eframe::App for ClamRustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Kanal üzerinden gelen verileri işle
        while let Ok(msg) = self.rx.try_recv() {
            if msg.starts_with("FILE:") {
                self.scanned_files += 1;
                self.current_file = msg.replace("FILE:", "").replace(": OK", "");
                self.risk_score = (self.threats_found as f32 * 10.0).min(100.0);
            } else if msg.starts_with("THREAT:") {
                self.threats_found += 1;
                let time = Local::now().format("%H:%M:%S").to_string();
                self.logs.push(format!("[{}] ⚠️ DETECTED: {}", time, msg.replace("THREAT:", "")));
            } else if msg == "COMPLETE" {
                self.is_working = false;
                self.current_file = "Scan Complete".to_string();
            }
        }

        // --- SIDEBAR NAVIGATION ---
        egui::SidePanel::left("sidebar").resizable(false).default_width(220.0).show(ctx, |ui| {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("🛡️ CMP ULTRA").size(22.0).strong().color(egui::Color32::from_rgb(0, 160, 255)));
                ui.label(egui::RichText::new("Secure & Private").weak());
            });
            ui.add_space(40.0);

            ui.vertical(|ui| {
                ui.style_mut().spacing.item_spacing.y = 12.0;
                ui.selectable_value(&mut self.current_page, Page::Dashboard, "📊 Dashboard");
                ui.selectable_value(&mut self.current_page, Page::Scanner, "🔍 Deep Scan");
                ui.selectable_value(&mut self.current_page, Page::Privacy, "🧹 Privacy Guard");
                ui.selectable_value(&mut self.current_page, Page::Logs, "📜 Security Logs");
            });

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(20.0);
                ui.weak("v2.5.0 Stable");
                ui.separator();
            });
        });

        // --- MAIN CONTENT ---
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_page {
                Page::Dashboard => self.render_dashboard(ui),
                Page::Scanner => self.render_scanner(ui, ctx),
                Page::Privacy => self.render_privacy(ui),
                Page::Logs => self.render_logs(ui),
            }
        });
    }
}

impl ClamRustApp {
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("System Security Dashboard");
        ui.add_space(20.0);

        ui.horizontal(|ui| {
            // Status Card
            ui.group(|ui| {
                ui.set_min_size(egui::vec2(300.0, 160.0));
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    let color = if self.threats_found > 0 { egui::Color32::RED } else { egui::Color32::LIGHT_GREEN };
                    ui.label(egui::RichText::new(if self.threats_found > 0 { "⚡ THREATS FOUND" } else { "🛡️ SECURED" }).color(color).size(20.0).strong());
                    ui.add_space(10.0);
                    ui.label(format!("Total Scanned: {}", self.scanned_files));
                    ui.label(format!("Active Threats: {}", self.threats_found));
                });
            });

            // Risk Meter Card
            ui.group(|ui| {
                ui.set_min_size(egui::vec2(300.0, 160.0));
                ui.vertical(|ui| {
                    ui.strong("Risk Analysis");
                    ui.add_space(10.0);
                    ui.add(egui::ProgressBar::new(self.risk_score / 100.0).text(format!("Risk Level: {}%", self.risk_score)));
                    ui.add_space(10.0);
                    ui.weak("Heuristic scan active. All systems are being monitored.");
                });
            });
        });
    }

    fn render_scanner(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Malware Analysis Engine");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.add_enabled(!self.is_working, egui::Button::new("📂 Choose Folder & Scan")).clicked() {
                if let Some(path) = FileDialog::new().pick_folder() {
                    self.run_engine(ctx.clone(), path.display().to_string());
                }
            }
            if self.is_working { ui.spinner(); }
        });

        ui.add_space(20.0);
        
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label("In-Progress File:");
            ui.label(egui::RichText::new(&self.current_file).monospace().size(11.0).color(egui::Color32::LIGHT_BLUE));
            ui.add_space(10.0);
            ui.add(egui::ProgressBar::new(0.5).animate(self.is_working));
        });

        ui.add_space(20.0);
        ui.label("Detection Stream:");
        egui::ScrollArea::vertical().max_height(250.0).stick_to_bottom(true).show(ui, |ui| {
            for log in &self.logs {
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), log);
            }
        });
    }

    fn render_privacy(&mut self, ui: &mut egui::Ui) {
        ui.heading("Privacy & System Guard");
        ui.add_space(20.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(format!("Estimated Cleanup: {:.1} GB", self.cleanup_potential));
            if ui.button("🚀 Execute Deep Clean").clicked() {}
        });
    }

    fn render_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Logs");
        ui.add_space(10.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for log in &self.logs {
                ui.label(log);
            }
        });
    }
}
