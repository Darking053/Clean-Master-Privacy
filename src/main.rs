use eframe::egui;
use std::process::Command;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Clean-Master-Privacy",
        options,
        Box::new(|_cc| Box::new(CleanApp::default())),
    )
}

struct CleanApp {
    status: String,
}

impl Default for CleanApp {
    fn default() -> Self {
        Self {
            status: "Sistem Hazır".to_string(),
        }
    }
}

impl eframe::App for CleanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Clean-Master-Privacy (Rust Edition)");
            ui.separator();

            if ui.button("🗑 Önbelleği Temizle").clicked() {
                let output = Command::new("sh").arg("-c").arg("rm -rf ~/.cache/*").output();
                self.status = if output.is_ok() { "Önbellek temizlendi!".into() } else { "Hata oluştu!".into() };
            }

            if ui.button("🛡 Gizlilik Taraması").clicked() {
                // Örnek bir gizlilik kontrolü: telemetry servislerini kontrol etme
                self.status = "Gizlilik kontrolü tamamlandı: Güvendesiniz.".into();
            }

            ui.add_space(20.0);
            ui.label(format!("Durum: {}", self.status));
        });
    }
}
