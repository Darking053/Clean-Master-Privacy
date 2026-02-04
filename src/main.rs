use clap::{Parser, Subcommand};
use colored::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use sysinfo::{ProcessExt, System, SystemExt};
use gtk4::{self as gtk, glib, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use libadwaita as adw;
use async_std::task;
use notify::{Watcher, RecursiveMode, Config, EventKind};

// --- CLI Structure ---
#[derive(Parser)]
#[command(name = "clean-master-privacy", version = "1.2.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan { #[arg(short, long, default_value = "/home")] path: String },
    Guard,
    Clean,
}

// --- Threat Intelligence Database ---
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "rm -rf / --no-preserve-root", "/etc/shadow",
    "nc -e /bin/sh", "python -c 'import socket;os.dup2'", "memfd_create"
];

// --- APP STATE ---
struct AppState {
    threat_count: usize,
    is_guard_active: bool,
}

// --- MAIN ---
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
        _ => start_gui_application(),
    }
}

// --- GUI IMPLEMENTATION ---
fn start_gui_application() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.cmp.antivirus")
        .build();
    application.connect_activate(build_ui);
    application.run()
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .default_width(850)
        .default_height(650)
        .title("Clean Master Privacy - Cyber Shield")
        .build();

    let content = GtkBox::new(Orientation::Vertical, 15);
    content.set_margin_all(30);

    let status_label = Label::new(Some("🛡️ System Status: Secure"));
    status_label.set_margin_bottom(10);
    
    let progress_bar = ProgressBar::new();
    
    // Scan Button
    let scan_btn = Button::with_label("🚀 Start Deep Scan");
    scan_btn.add_css_class("suggested-action");
    
    // Real-Time Guard Toggle
    let guard_btn = Button::with_label("🛡️ Enable Real-Time Guard");

    // UI Logic
    let status_clone = status_label.clone();
    let progress_clone = progress_bar.clone();
    
    scan_btn.connect_clicked(move |_| {
        let st = status_clone.clone();
        let pb = progress_clone.clone();
        task::spawn_local(async move {
            st.set_text("Scanning system for threats...");
            run_scan_engine("/home", Some(st.clone()), Some(pb)).await;
        });
    });

    guard_btn.connect_clicked(move |btn| {
        btn.set_label("🛡️ Guard Active (Watching /home)");
        btn.set_sensitive(false);
        task::spawn_local(async move {
            start_realtime_protection().await;
        });
    });

    content.append(&status_label);
    content.append(&progress_bar);
    content.append(&scan_btn);
    content.append(&guard_btn);

    window.set_child(Some(&content));
    window.show();
}

// --- CORE ENGINE: SCANNER ---
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
        let progress = i as f64 / total;
        
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            glib::idle_add_local_once(move || p.set_fraction(progress));
        }

        if is_file_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate_threat(path);
        }
    });

    let found = *threats.lock().unwrap();
    if let Some(ref l) = label {
        l.set_text(&format!("Scan Complete! Found {} threats. System isolated.", found));
    }
}

// --- CORE ENGINE: REAL-TIME GUARD ---
async fn start_realtime_protection() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::RecommendedWatcher::new(tx, Config::default()).unwrap();
    
    let watch_path = dirs::home_dir().unwrap_or(PathBuf::from("/home"));
    watcher.watch(&watch_path, RecursiveMode::Recursive).unwrap();

    println!("Shield Active on {:?}", watch_path);

    for res in rx {
        if let Ok(event) = res {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        if is_file_malicious(&path) {
                            println!("🛑 THREAT BLOCKED: {:?}", path);
                            isolate_threat(&path);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// --- UTILS ---
fn is_file_malicious(path: &Path) -> bool {
    if let Ok(mut file) = File::open(path) {
        let mut buffer = [0u8; 10240]; // Scan first 10KB for speed
        if file.read(&mut buffer).is_ok() {
            let content = String::from_utf8_lossy(&buffer);
            for pattern in MALICIOUS_PATTERNS {
                if content.contains(pattern) { return true; }
            }
        }
    }
    false
}

fn isolate_threat(path: &Path) {
    let quarantine_path = dirs::home_dir().unwrap().join(".cmp_quarantine");
    let _ = fs::create_dir_all(&quarantine_path);
    if let Some(fname) = path.file_name() {
        let _ = fs::rename(path, quarantine_path.join(fname));
    }
}
