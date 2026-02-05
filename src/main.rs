#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::process::Command;

fn main() -> Result<(), eframe::Error> {
    // eframe 0.24+ için yeni pencere ayarları yapısı
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 400.0])
            .with_resizable(true),
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
            status: "System Ready".to_string(),
            last_scan: "No recent actions".to_string(),
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

            // ClamTk tarzı 2x2 Izgara (Grid)
            egui::Grid::new("main_grid")
                .spacing([40.0, 20.0])
                .min_col_width(200.0)
                .show(ui, |ui| {
                    // Sütun 1: Ayarlar ve Geçmiş
                    ui.vertical(|ui| {
                        ui.strong("Maintenance");
                        if ui.button("⚙ Settings").clicked() {
                            self.status = "Settings menu opened".to_string();
                        }
                        ui.add_space(5.0);
                        if ui.button("📜 History").clicked() {
                            self.status = "Analyzing logs...".to_string();
                        }
                    });

                    // Sütun 2: Tarama ve Temizlik
                    ui.vertical(|ui| {
                        ui.strong("Scanner");
                        if ui.button("🔍 Scan Home Folder").clicked() {
                            self.run_scan();
                        }
                        ui.add_space(5.0);
                        if ui.button("🧹 Privacy Cleanup").clicked() {
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
    fn run_scan(&mut self) {
        self.status = "Scanning...".to_string();
        // Clamscan komutunu arkada çalıştırır
        let _ = Command::new("clamscan").arg("-r").arg("~").spawn();
        self.last_scan = "Virus scan started in background".to_string();
    }

    fn run_cleanup(&mut self) {
        self.status = "Cleaning...".to_string();
        let _ = Command::new("sh")
            .arg("-c")
            .arg("rm -rf ~/.cache/* && journalctl --vacuum-time=1s")
            .output();
        self.last_scan = "Privacy logs and cache cleared".to_string();
        self.status = "Cleanup Completed".to_string();
    }
}
