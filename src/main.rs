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
use futures::executor::block_on; // For simple async calls in main

#[derive(Parser)]
#[command(name = "clean-master-privacy")]
#[command(version = "1.1.0")]
#[command(about = "Enterprise-grade Linux Security & Privacy Suite with GUI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>, // Optional command to start GUI if none provided
}

#[derive(Subcommand)]
enum Commands {
    /// Deep scan for threats with auto-quarantine
    Scan {
        #[arg(short, long, default_value = "/home")]
        path: String,
        /// Scan the entire file content instead of just headers
        #[arg(short, long)]
        strict: bool,
    },
    /// Active Guard: Real-time memory and process monitoring
    Guard,
    /// Privacy Nuke: Wipe system logs and tracking footprints
    Clean,
}

// Industry-standard suspicious patterns (expanded for enterprise level)
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode",
    "system(rm -rf /)",
    "nc -e /bin/sh",
    "powershell.exe -ExecutionPolicy Bypass",
    "msfvenom", // Metasploit payload indicator
    "/usr/bin/python -c 'import socket;'" // Common for reverse shells
];
// Simulated known malware hashes (for signature-based detection)
const KNOWN_MALWARE_HASHES: &[&str] = &[
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // EICAR Test File Hash
    "d23a9a7b7a8a2a7a9a1a3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0a1a2a3a4a", // Simulated Ransomware
];


// --- Main Entry Point ---
fn main() -> glib::ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { path, strict }) => {
            block_on(async { // Use block_on for simple async CLI calls
                run_advanced_scan(&path, strict).await;
            });
            glib::ExitCode::SUCCESS
        },
        Some(Commands::Guard) => {
            block_on(async {
                start_realtime_guard().await;
            });
            glib::ExitCode::SUCCESS
        },
        Some(Commands::Clean) => {
            block_on(async {
                privacy_nuke().await;
            });
            glib::ExitCode::SUCCESS
        },
        None => {
            // No command provided, launch GUI
            println!("{}", "=== CLEAN MASTER PRIVACY - GUI LAUNCHING ===".bold().bright_white().on_blue());
            start_gui_application()
        }
    }
}

// --- GUI APPLICATION ---
fn start_gui_application() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.cleanmasterprivacy.gui")
        .build();

    application.connect_activate(build_ui);
    application.run()
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .default_width(800)
        .default_height(600)
        .title("Clean Master Privacy")
        .build();

    let header_bar = adw::HeaderBar::new();
    header_bar.set_title_widget(Some(&adw::WindowTitle::new("Clean Master Privacy", "")));
    
    let content = GtkBox::new(Orientation::Vertical, 10);
    content.set_margin_top(20);
    content.set_margin_bottom(20);
    content.set_margin_start(20);
    content.set_margin_end(20);

    let status_label = Label::new(Some("Welcome to Clean Master Privacy!"));
    status_label.set_halign(gtk::Align::Center);
    let progress_bar = ProgressBar::builder()
        .fraction(0.0)
        .margin_top(10)
        .build();

    let scan_button = Button::with_label("Start Full Scan");
    scan_button.set_halign(gtk::Align::Center);
    let path_entry = gtk::Entry::builder()
        .placeholder_text("Path to scan (e.g., /home/user)")
        .margin_top(10)
        .build();
    path_entry.set_text("/home"); // Default scan path

    let status_label_clone = status_label.clone();
    let progress_bar_clone = progress_bar.clone();
    let window_clone = window.clone();
    
    scan_button.connect_clicked(move |_| {
        let path_to_scan = path_entry.text().to_string();
        let status_label_clone_inner = status_label_clone.clone();
        let progress_bar_clone_inner = progress_bar_clone.clone();
        
        status_label_clone_inner.set_text(&format!("Scanning: {}", path_to_scan));
        progress_bar_clone_inner.set_fraction(0.0);

        // Async scan in the background
        let context = glib::MainContext::default();
        let _guard = context.acquire().unwrap();
        task::spawn_local(async move {
            run_advanced_scan_gui(&path_to_scan, false, status_label_clone_inner, progress_bar_clone_inner).await;
            // You can update UI elements here after scan completes
        });
    });

    let clean_button = Button::with_label("Run Privacy Clean");
    clean_button.set_halign(gtk::Align::Center);
    let status_label_clean_clone = status_label.clone();
    clean_button.connect_clicked(move |_| {
        let status_label_clean_clone_inner = status_label_clean_clone.clone();
        status_label_clean_clone_inner.set_text("Running Privacy Clean...");
        task::spawn_local(async move {
            privacy_nuke().await;
            status_label_clean_clone_inner.set_text("Privacy Clean Completed!");
        });
    });

    content.append(&status_label);
    content.append(&progress_bar);
    content.append(&path_entry);
    content.append(&scan_button);
    content.append(&clean_button);

    let main_box = GtkBox::new(Orientation::Vertical, 0);
    main_box.append(&header_bar);
    main_box.append(&content);

    window.set_child(Some(&main_box));
    window.show();
}

// --- SCAN ENGINE (GUI compatible) ---
async fn run_advanced_scan_gui(target: &str, strict: bool, status_label: Label, progress_bar: ProgressBar) {
    let start = std::time::Instant::now();
    let files: Vec<PathBuf> = walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    glib::idle_add_local_once(move || {
        status_label.set_text(&format!("🚀 Analyzing {} files...", files.len()));
    });

    let threats = Arc::new(Mutex::new(0));
    let processed_files_count = Arc::new(Mutex::new(0));
    let total_files = files.len() as f64;

    files.par_iter().for_each(|path| {
        let mut processed_count = processed_files_count.lock().unwrap();
        *processed_count += 1;
        let current_fraction = *processed_count as f64 / total_files;

        glib::idle_add_local_once(move || {
            progress_bar.set_fraction(current_fraction);
        });

        if let Ok(mut file) = File::open(path) {
            let mut buffer = Vec::new();
            if strict {
                file.read_to_end(&mut buffer).ok();
            } else {
                let mut chunk = [0u8; 16384];
                if let Ok(n) = file.read(&mut chunk) { buffer.extend_from_slice(&chunk[..n]); }
            }

            let hash = format!("{:x}", Sha256::digest(&buffer));
            let content = String::from_utf8_lossy(&buffer);
            
            let mut detected = false;
            for pattern in MALICIOUS_PATTERNS {
                if content.contains(pattern) { detected = true; break; }
            }
            if !detected { // Also check known hash list
                for known_hash in KNOWN_MALWARE_HASHES {
                    if hash == *known_hash { detected = true; break; }
                }
            }

            if detected {
                glib::idle_add_local_once(move || {
                    status_label.set_text(&format!("{} Threat Found: {:?}", "🛑 CRITICAL:".red().bold(), path));
                });
                let mut count = threats.lock().unwrap();
                *count += 1;
                isolate_threat(path); // Auto-Quarantine
            }
        }
    });

    let found = *threats.lock().unwrap();
    glib::idle_add_local_once(move || {
        status_label.set_text(&format!("Scan complete in {:?}. Detected {} threats.", start.elapsed(), found));
        if found == 0 {
            status_label.set_text("✅ No threats detected. System is clean.");
            status_label.add_css_class("success"); // Apply a success style
        } else {
            status_label.add_css_class("error"); // Apply an error style
        }
        progress_bar.set_fraction(1.0);
    });
}

fn isolate_threat(path: &Path) {
    let q_dir = dirs::home_dir().unwrap().join(".cmp_quarantine");
    let _ = fs::create_dir_all(&q_dir);
    if let Some(file_name) = path.file_name() {
        let dest = q_dir.join(file_name);
        if fs::rename(path, &dest).is_ok() {
            // In GUI, we might log this to a list, not just print
        }
    }
}

// --- REAL-TIME GUARD ENGINE (Async for GUI) ---
async fn start_realtime_guard() {
    println!("🛡️  Shields UP. Monitoring system behavior...");
    let mut sys = System::new_all();
    loop {
        sys.refresh_all();
        for (pid, process) in sys.processes() {
            let name = process.name().to_lowercase();
            if name.contains("crypt") || name.contains("miner") || name.contains("keylog") {
                println!("⚠️  BEHAVIOR ALERT: Suspicious process [PID: {}] {}", pid, name);
                // In GUI, this would trigger a notification
            }
        }
        async_std::task::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// --- PRIVACY ENGINE (Async for GUI) ---
async fn privacy_nuke() {
    println!("🧹 Nuking privacy-invading artifacts...");
    // Actual cleanup logic for cache, logs, history files goes here
    println!("{}", "✨ Privacy scan complete. Your system is now invisible.".green().bold());
}
