use adw::prelude::*;
use async_std::task;
use clap::{Parser, Subcommand};
use gtk4::{self as gtk, glib, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use libadwaita as adw;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// --- CLI Yapısı ---
#[derive(Parser)]
#[command(name = "clean-master-privacy", version = "1.2.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan { 
        #[arg(short, long, default_value = "/home")] 
        path: String 
    },
    Guard,
}

// --- Tehdit İstihbarat Veritabanı ---
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "rm -rf / --no-preserve-root", "/etc/shadow",
    "nc -e /bin/sh", "python -c 'import socket;os.dup2'", "memfd_create"
];

fn main() -> glib::ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { path }) => {
            println!("Starting CLI Scan on {}...", path);
            task::block_on(async { run_scan_engine(&path, None, None).await });
            glib::ExitCode::SUCCESS
        },
        Some(Commands::Guard) => {
            println!("Starting Real-Time Guard...");
            task::block_on(async { start_realtime_protection().await });
            glib::ExitCode::SUCCESS
        },
        None => {
            // GUI başlatma
            let application = Application::builder()
                .application_id("com.cmp.antivirus")
                .build();
            application.connect_activate(build_ui);
            application.run()
        }
    }
}

// --- GUI Arayüzü ---
fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
                .default_width(800)
        .default_height(600)
        .title("CMP - Cyber Shield")
        .build();

    let content = GtkBox::new(Orientation::Vertical, 20);
    content.set_margin_all(30);

    let status_label = Label::builder()
        .label("🛡️ Sistem Durumu: Güvende")
        .css_classes(["title-2"])
        .build();
    
    let progress_bar = ProgressBar::new();
    progress_bar.set_hexpand(true);
    
    let scan_btn = Button::with_label("🚀 Derin Taramayı Başlat");
    scan_btn.add_css_class("suggested-action");
    
    let guard_btn = Button::with_label("🛡️ Gerçek Zamanlı Korumayı Aç");

    // UI Mantığı
    let status_clone = status_label.clone();
    let progress_clone = progress_bar.clone();
    
    scan_btn.connect_clicked(move |btn| {
        let st = status_clone.clone();
        let pb = progress_clone.clone();
        btn.set_sensitive(false); // Tarama sırasında butonu kapat
        
        glib::spawn_future_local(async move {
            st.set_text("Sistem taranıyor, lütfen bekleyin...");
            run_scan_engine("/home", Some(st), Some(pb)).await;
        });
    });

    guard_btn.connect_clicked(move |btn| {
        btn.set_label("🛡️ Kalkan Aktif");
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

// --- Tarama Motoru ---
async fn run_scan_engine(target: &str, label: Option<Label>, pb: Option<ProgressBar>) {
    let target_path = PathBuf::from(target);
    let files: Vec<PathBuf> = walkdir::WalkDir::new(target_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total = files.len() as f64;
    let threats = Arc::new(Mutex::new(0));

    // Paralel tarama
    files.par_iter().enumerate().for_each(|(i, path)| {
        let progress = i as f64 / total;
        
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            glib::idle_add_local_once(move || {
                p.set_fraction(progress);
            });
        }

        if is_file_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate_threat(path);
        }
    });

    let found = *threats.lock().unwrap();
    if let Some(ref l) = label {
        l.set_text(&format!("Tarama Tamamlandı! {} tehdit izole edildi.", found));
    }
}

// --- Gerçek Zamanlı Koruma ---
async fn start_realtime_protection() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).expect("Watcher başlatılamadı");
    
    let watch_path = dirs::home_dir().expect("Home dizini bulunamadı");
    watcher.watch(&watch_path, RecursiveMode::Recursive).expect("İzleme başarısız");

    for res in rx {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in event.paths {
                    if is_file_malicious(&path) {
                        isolate_threat(&path);
                        println!("🛑 TEHDİT ENGELLENDİ: {:?}", path);
                    }
                }
            }
        }
    }
}

// --- Yardımcı Fonksiyonlar ---
fn is_file_malicious(path: &Path) -> bool {
    if let Ok(mut file) = File::open(path) {
        let mut buffer = [0u8; 10240]; 
        if let Ok(bytes_read) = file.read(&mut buffer) {
            let content = String::from_utf8_lossy(&buffer[..bytes_read]);
            return MALICIOUS_PATTERNS.iter().any(|pattern| content.contains(pattern));
        }
    }
    false
}

fn isolate_threat(path: &Path) {
    if let Some(home) = dirs::home_dir() {
        let quarantine_path = home.join(".cmp_quarantine");
        let _ = fs::create_dir_all(&quarantine_path);
        if let Some(fname) = path.file_name() {
            let _ = fs::rename(path, quarantine_path.join(fname));
        }
    }
}
