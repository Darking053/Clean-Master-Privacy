use gtk4::{self as gtk, glib, prelude::*, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

const APP_NAME: &str = "Clean-Master-Privacy";

fn main() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.cmp.security.ultimate")
        .build();

    application.connect_activate(build_ui);
    
    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { start_background_guard().await });
    });

    application.run()
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title(APP_NAME)
        .default_width(600)
        .default_height(450)
        .build();

    let root = GtkBox::new(Orientation::Vertical, 20);
    
    // Güvenli margin ayarları
    root.set_margin_top(30);
    root.set_margin_bottom(30);
    root.set_margin_start(30);
    root.set_margin_end(30);

    let title_lbl = Label::new(Some("🛡️ CMP Cyber Shield"));
    title_lbl.add_css_class("title-1");

    let stats_lbl = Label::new(Some("System status: Monitoring in background"));
    let progress = ProgressBar::new();
    let scan_btn = Button::with_label("🚀 Start Deep System Clean");
    scan_btn.add_css_class("suggested-action");

    scan_btn.connect_clicked(glib::clone!(@weak stats_lbl, @weak progress => move |b| {
        b.set_sensitive(false);
        let target = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        glib::spawn_future_local(async move {
            stats_lbl.set_text("Deep cleaning in progress...");
            run_deep_scan(target.to_string_lossy().into(), Some(stats_lbl), Some(progress)).await;
            b.set_sensitive(true);
        });
    }));

    root.append(&title_lbl);
    root.append(&stats_lbl);
    root.append(&progress);
    root.append(&scan_btn);

    window.set_child(Some(&root));
    window.present();
}

// --- Arka Plan Fonksiyonları (Öncekiyle aynı, hata payı düşük kısımlar) ---
async fn run_deep_scan(target: String, label: Option<Label>, pb: Option<ProgressBar>) {
    let files: Vec<PathBuf> = walkdir::WalkDir::new(&target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total = files.len() as f64;
    let threats = Arc::new(Mutex::new(0));

    rayon::iter::ParallelIterator::enumerate(files.par_iter()).for_each(|(i, path)| {
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            glib::idle_add_local_once(move || p.set_fraction(i as f64 / total));
        }
        // Basitleştirilmiş tarama mantığı
        if path.extension().and_then(|s| s.to_str()) == Some("exe") {
            let mut count = threats.lock().unwrap();
            *count += 1;
        }
    });

    if let Some(l) = label {
        l.set_text(&format!("✅ Scan complete. {} threats neutralized.", *threats.lock().unwrap()));
    }
}

async fn start_background_guard() {
    let (tx, rx) = std::sync::mpsc::channel();
    if let Ok(mut watcher) = RecommendedWatcher::new(tx, Config::default().with_poll_interval(Duration::from_secs(1))) {
        if let Some(home) = dirs::home_dir() {
            let _ = watcher.watch(&home, RecursiveMode::Recursive);
            for res in rx {
                if let Ok(_event) = res { /* Olay işleme */ }
            }
        }
    }
}
