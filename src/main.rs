#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::sync::mpsc::{Receiver, Sender, self};
use std::thread;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_resizable(true),
        ..Default::default()
    };
    
    eframe::run_native(
        "Clean-Master-Privacy",
        options,
        Box::new(|_cc| {
            // Başlangıç teması olarak Dark Mode seçiyoruz
            _cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(ClamRustApp::new())
        }),
    )
}

struct ClamRustApp {
    status: String,
    logs: Vec<String>,
    is_working: bool,
    rx: Receiver<String>,
    tx: Sender<String>,
    is_dark_mode: bool,
}

impl ClamRustApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            status: "System Ready".to_string(),
            logs: vec!["Welcome to Clean-Master-Privacy".to_string()],
            is_working: false,
            rx,
            tx,
            is_dark_mode: true,
        }
    }

    fn run_scan(&mut self, ctx: egui::Context) {
        let tx = self.tx.clone();
        self.is_working = true;
        self.status = "Scanning...".to_string();

        thread::spawn(move || {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
            let child = Command::new("clamscan")
                .arg("-r")
                .arg(home)
                .stdout(Stdio::piped())
                .spawn();

            match child {
                Ok(mut child) => {
                    let stdout = child.stdout.take().unwrap();
                    let reader = BufReader::new(stdout);

                    for line in reader.lines() {
                        if let Ok(l) = line {
                            let _ = tx.send(l);
                            ctx.request_repaint();
                        }
                    }
                }
                Err(_) => {
                    let _ = tx.send("Error: 'clamscan' not found! Please install ClamAV.".to_string());
                }
            }
            let _ = tx.send("FINISH_SCAN".to_string());
        });
    }

    fn run_cleanup(&mut self) {
        self.is_working = true;
        self.status = "Cleaning cache...".to_string();
        
        let _ = Command::new("sh")
            .arg("-c")
            .arg("rm -rf ~/.cache/* && journalctl --vacuum-time=1s")
            .output();

        self.logs.push("Privacy cleanup: Cache and journal logs cleared.".to_string());
        self.status = "Cleanup Completed".to_string();
        self.is_working = false;
    }
}

impl eframe::App for ClamRustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle background messages
        while let Ok(msg) = self.rx.try_recv() {
            if msg == "FINISH_SCAN" {
                self.is_working = false;
                self.status = "Task Finished".to_string();
            } else {
                self.logs.push(msg);
                if self.logs.len() > 100 { self.logs.remove(0); }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // TOP BAR: Theme Switch and Title
            ui.horizontal(|ui| {
                ui.heading("🛡️ Clean-Master-Privacy");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let theme_icon = if self.is_dark_mode { "🌙 Dark" } else { "☀️ Light" };
                    if ui.button(theme_icon).clicked() {
                        self.is_dark_mode = !self.is_dark_mode;
                        if self.is_dark_mode {
                            ctx.set_visuals(egui::Visuals::dark());
                        } else {
                            ctx.set_visuals(egui::Visuals::light());
                        }
                    }
                });
            });

            ui.add_space(5.0);
            ui.separator();
            ui.add_space(10.0);

            // ACTION BUTTONS
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!self.is_working, |ui| {
                    if ui.button("🔍 Full Scan").on_hover_text("Scan home directory for threats").clicked() {
                        self.run_scan(ctx.clone());
                    }
                });

                ui.add_enabled_ui(!self.is_working, |ui| {
                    if ui.button("🧹 Privacy Cleanup").on_hover_text("Clear cache and system logs").clicked() {
                        self.run_cleanup();
                    }
                });

                if self.is_working {
                    ui.spinner();
                    ui.label(egui::RichText::new("Processing...").italics());
                }
            });

            ui.add_space(10.0);
            
            // STATUS LABEL
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.label(format!("Status: {}", self.status));
            });

            ui.add_space(10.0);

            // CONSOLE / LOGS
            ui.label("Activity Log:");
            egui::Frame::canvas(ui.style()).show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for log in &self.logs {
                            ui.label(egui::RichText::new(log).monospace().size(11.0));
                        }
                    });
            });

            // BOTTOM INFO
            ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
                ui.add_space(5.0);
                ui.weak("v1.0.0 - Powered by Rust & ClamAV");
            });
        });
    }
}
