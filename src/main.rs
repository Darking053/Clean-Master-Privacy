#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::process::Command;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(500.0, 400.0)),
        ..Default::default()
    };
    eframe::run_native(
        "Clean-Master-Privacy",
        options,
        Box::new(|_cc| Box::new(ClamRustApp::default())),
    )
}

struct ClamRustApp {
    status: String,
    last_scan: String,
}

impl Default for ClamRustApp {
    fn default() -> Self {
        Self {
            status: "Ready to Scan".to_string(),
            last_scan: "Never".to_string(),
        }
    }
}

impl eframe::App for ClamRustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Clean-Master-Privacy");
                ui.label("Rust-based ClamTK Alternative");
            });

            ui.add_space(20.0);

            // 2x2 Grid Layout similar to ClamTk
            egui::Grid::new("main_grid")
                .spacing([40.0, 20.0])
                .min_col_width(200.0)
                .show(ui, |ui| {
                    // --- Column 1: Cleaning & Privacy ---
                    ui.vertical(|ui| {
                        ui.strong("Configuration");
                        if ui.button("⚙ Settings").clicked() {
                            self.status = "Settings clicked".to_string();
                        }
                        if ui.button("📜 History").clicked() {
                            self.status = "Viewing logs...".to_string();
                        }
                    });

                    // --- Column 2: Scanning ---
                    ui.vertical(|ui| {
                        ui.strong("Analysis");
                        if ui.button("🔍 Scan Home Folder").clicked() {
                            self.run_scan("~");
                        }
                        if ui.button("🧹 Deep Cleanup").clicked() {
                            self.run_cleanup();
                        }
                    });
                    ui.end_row();
                });

            ui.add_space(30.0);
            ui.separator();
            ui.label(format!("Status: {}", self.status));
            ui.label(format!("Last Action: {}", self.last_scan));
        });
    }
}

impl ClamRustApp {
    fn run_scan(&mut self, path: &str) {
        self.status = format!("Scanning {}...", path);
        // Triggers ClamScan (requires clamav installed)
        let _ = Command::new("clamscan").arg("-r").arg(path).spawn();
        self.last_scan = "Virus Scan started".to_string();
    }

    fn run_cleanup(&mut self) {
        self.status = "Cleaning cache and privacy logs...".to_string();
        let _ = Command::new("sh")
            .arg("-c")
            .arg("rm -rf ~/.cache/* && journalctl --vacuum-time=1s")
            .output();
        self.last_scan = "System Cleaned".to_string();
        self.status = "Cleanup Completed Successfully".to_string();
    }
}
