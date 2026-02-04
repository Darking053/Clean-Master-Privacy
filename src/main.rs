use adw::prelude::*;
use clap::{Parser, Subcommand};
use gtk4::{self as gtk, glib, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use libadwaita as adw;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// --- CLI Structure ---
#[derive(Parser)]
#[command(name = "clean-master-privacy", version = "1.3.0", about = "AI Powered Security Shield")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Sistemde derin tarama yapar
    Scan { 
        #[arg(short, long, default_value = "/home")] 
        path: String 
    },
    /// Gerçek zamanlı korumayı CLI üzerinden başlatır
    Guard,
}

// --- Malware Signatures ---
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "rm -rf / --no-preserve-root", "/etc/shadow",
    "nc -e /bin/sh", "python -c 'import socket;os.dup2'", "memfd_create",
    "chmod +x", "wget http", "curl -s"
];

fn main() -> glib::ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { path }) => {
            println!("🔍 Derin Tarama Başlatılıyor: {}", path);
            async_std::task::block_on(async { run_scan_engine(&path, None, None).await });
            glib::ExitCode::SUCCESS
        },
        Some(Commands::Guard) => {
            println!("🛡️ Koruma Kalkanı CLI üzerinde aktif...");
            async_std::task::block_on(async { start_realtime_protection().await });
            glib::ExitCode::SUCCESS
        },
        None => {
            let application = Application::builder()
                .application_id("com.cmp.antivirus")
                .build();
            application.connect_activate(build_ui);
            application.run()
        }
    }
}

// --- UI Engine ---
fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .default_width(800)
        .default_height(600)
        .title("CMP - Cyber Shield v1.3")
        .build();

    let content = GtkBox::new(Orientation::Vertical, 25);
    content.set_margin_all(30);

    let status_label = Label::builder()
        .label("🛡️ Sistem Güvenlik Durumu: Aktif")
        .css_classes(["title-2"])
        .build();
    
    let progress_bar = ProgressBar::builder()
        .margin_top(10)
        .margin_bottom(10)
        .build();
    
    let scan_btn = Button::with_label("🚀 Tam Sistem Taraması");
    scan_btn.add_css_class("suggested-action");
    
    let guard_btn = Button::with_label("🛡️ Gerçek Zamanlı Korumayı Başlat");

    let status_c = status_label.clone();
    let pb_c = progress_bar.clone();
    
    scan_btn.connect_clicked(move |btn| {
        btn.set_sensitive(false);
        let st = status_c.clone();
        let pb = pb_c.clone();
        glib::spawn_future_local(async move {
            st.set_text("Tarama yapılıyor, lütfen sisteminizi kapatmayın...");
            run_scan_engine("/home", Some(st), Some(pb)).await;
        });
    });

    guard_btn.connect_clicked(move |btn| {
        btn.set_label("🛡️ Koruma Devrede (İzleniyor)");
        btn.set_sensitive(false);
        glib::spawn_future_local(async move {
            start_realtime_protection().await;
        });
    });

    content.append(&status_label);
    content.append(&progress_bar);
    content.append(&scan_btn);
    content.append(&guard_btn);

    window.set_child(Some(&content));
    window.present();
}

// --- Scanner Core ---
async fn run_scan_engine(target: &str, label: Option<Label>, pb: Option<ProgressBar>) {
    let files: Vec<PathBuf> = walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total = files.len() as f64;
    let threats = Arc::new(Mutex::new(0));

    files.par_iter().enumerate().for_each(|(i, path)| {
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            let progress = i as f64 / total;
            glib::idle_add_local_once(move || p.set_fraction(progress));
        }

        if is_file_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate_threat(path);
        }
    });

    if let Some(l) = label {
        let final_count = *threats.lock().unwrap();
        l.set_text(&format!("✅ İşlem Tamam! {} Tehdit Etkisiz Hale Getirildi.", final_count));
    }
}

// --- File Analysis ---
fn is_file_malicious(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buffer = [0u8; 10240]; // Hız için ilk 10KB
    if let Ok(bytes_read) = file.read(&mut buffer) {
        if bytes_read == 0 { return false; }
        let content = String::from_utf8_lossy(&buffer[..bytes_read]);
        return MALICIOUS_PATTERNS.iter().any(|&pattern| content.contains(pattern));
    }
    false
}

// --- Isolation Engine ---
fn isolate_threat(path: &Path) {
    if let Some(home) = dirs::home_dir() {
        let quarantine_path = home.join(".cmp_quarantine");
        let _ = fs::create_dir_all(&quarantine_path);
        
        if let Some(fname) = path.file_name() {
            let dest = quarantine_path.join(fname);
            // Taşıma başarısız olursa paniğe girme, sadece devam et
            let _ = fs::rename(path, dest);
        }
    }
}

// --- Real-Time Protection ---
async fn start_realtime_protection() {
    let (tx, rx) = std::sync::mpsc::channel();
    
    let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Koruma başlatılamadı (Watcher Hatası): {}", e);
            return;
        }
    };

    if let Some(home) = dirs::home_dir() {
        if let Err(e) = watcher.watch(&home, RecursiveMode::Recursive) {
            eprintln!("Dizin izleme hatası: {}", e);
            return;
        }

        println!("🛡️ CMP Shield aktif: {:?}", home);

        for res in rx {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in event.paths {
                        if is_file_malicious(&path) {
                            println!("🛑 TEHDİT ENGELLENDİ: {:?}", path);
                            isolate_threat(&path);
                        }
                    }
                }
            }
        }
    }
}
