use clap::{Parser, Subcommand};
use gtk4::{self as gtk, glib, prelude::*, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use sha2::{Sha256, Digest};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

// --- Hardcoded Security Intelligence ---
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "Powershell -ExecutionPolicy", "Invoke-WebRequest",
    "rm -rf /", "del /f /s /q", "net user /add", "nc -e /bin/sh",
    "CreateRemoteThread", "AdjustTokenPrivileges", "SetWindowsHookEx",
    "ReflectiveLoader", "LdrLoadDll", "EtwEventWrite", "GlobalAlloc", "WriteProcessMemory"
];

const EXECUTABLE_MAGIC_NUMBERS: [[u8; 2]; 2] = [
    [0x4D, 0x5A], // Windows PE (EXE/DLL)
    [0x7F, 0x45], // Linux ELF
];

const PROTECTED_EXTENSIONS: &[&str] = &["exe", "dll", "so", "sh", "bat", "ps1", "js", "vbs", "py", "bin"];
const SKIPPED_DIRS: &[&str] = &["node_modules", ".git", "target", "System32", "Library", ".cargo", ".cache"];

#[derive(Parser)]
#[command(name = "shield-x", version = "3.0.0", about = "Ultimate Cross-Platform Heuristic Security")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan { #[arg(short, long)] path: Option<String> },
    Guard,
}

fn main() -> glib::ExitCode {
    let cli = Cli::parse();
    
    // Initialize Global Logging
    log_event("Shield-X Ultimate Kernel Initialized.");

    match cli.command {
        Some(Commands::Scan { path }) => {
            let target = path.unwrap_or_else(|| get_user_home().to_string_lossy().into());
            futures::executor::block_on(run_scan_engine(target, None, None));
            glib::ExitCode::SUCCESS
        },
        Some(Commands::Guard) => {
            futures::executor::block_on(start_realtime_protection());
            glib::ExitCode::SUCCESS
        },
        None => {
            let application = Application::builder().application_id("com.shieldx.ultimate").build();
            application.connect_activate(build_ui);
            application.run()
        }
    }
}

// --- Logic & Analysis Engines ---

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0usize; 256];
    for &b in data { freq[b as usize] += 1; }
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / data.len() as f64;
        -p * p.log2()
    }).sum()
}

fn is_disguised_executable(path: &Path, buffer: &[u8]) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let has_exe_magic = EXECUTABLE_MAGIC_NUMBERS.iter().any(|m| buffer.starts_with(m));
    
    // Alert if a .jpg or .txt has an EXE header (Classic malware trick)
    has_exe_magic && !PROTECTED_EXTENSIONS.contains(&ext.as_str())
}

fn is_file_malicious(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buffer = [0u8; 32768]; // 32KB buffer for deeper analysis
    if let Ok(n) = file.read(&mut buffer) {
        if n == 0 { return false; }
        let data = &buffer[..n];

        // 1. Static Signature Disguise Check
        if is_disguised_executable(path, data) {
            log_event(&format!("CRITICAL: Disguised executable detected: {:?}", path));
            return true;
        }

        // 2. Pattern Analysis
        let content = String::from_utf8_lossy(data).to_lowercase();
        if MALICIOUS_PATTERNS.iter().any(|&p| content.contains(&p.to_lowercase())) {
            log_event(&format!("THREAT: Malicious code pattern in {:?}", path));
            return true;
        }

        // 3. High-Entropy (Encryption/Packing) Check
        if calculate_entropy(data) > 7.6 {
            log_event(&format!("SUSPICIOUS: Encrypted/Packed content in {:?}", path));
            return true;
        }
    }
    false
}

// --- System Actions ---

fn isolate_threat(path: &Path) {
    let q_dir = get_user_home().join(".shield_quarantine");
    let _ = fs::create_dir_all(&q_dir);
    if let Some(name) = path.file_name() {
        let dest = q_dir.join(name);
        if fs::copy(path, &dest).is_ok() {
            let _ = fs::remove_file(path);
            log_event(&format!("SUCCESS: File {:?} moved to quarantine.", name));
        }
    }
}

async fn run_scan_engine(target: String, label: Option<Label>, pb: Option<ProgressBar>) {
    let files: Vec<PathBuf> = walkdir::WalkDir::new(&target)
        .into_iter()
        .filter_entry(|e| !SKIPPED_DIRS.iter().any(|&d| e.file_name().to_string_lossy().contains(d)))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total = files.len() as f64;
    let threats = Arc::new(Mutex::new(0));

    files.par_iter().enumerate().for_each(|(i, path)| {
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            glib::idle_add_local_once(move || p.set_fraction(i as f64 / total));
        }

        if is_file_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate_threat(path);
        }
    });

    if let Some(l) = label {
        l.set_text(&format!("Scan Finished: {} Threats Neutralized", *threats.lock().unwrap()));
    }
}

// --- UI & Environment ---

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Shield-X Ultimate")
        .default_width(550)
        .resizable(false)
        .build();

    let root = GtkBox::new(Orientation::Vertical, 25);
    root.set_margin_all(40);

    let status = Label::new(Some("Shield Status: Active & Monitoring"));
    let progress = ProgressBar::new();
    let btn = Button::with_label("Initiate Full Heuristic Analysis");
    btn.add_css_class("suggested-action");

    btn.connect_clicked(glib::clone!(@weak status, @weak progress => move |b| {
        b.set_sensitive(false);
        glib::spawn_future_local(async move {
            run_scan_engine(get_user_home().to_string_lossy().into(), Some(status), Some(progress)).await;
            b.set_sensitive(true);
        });
    }));

    root.append(&status);
    root.append(&progress);
    root.append(&btn);
    window.set_child(Some(&root));
    window.present();
}

fn get_user_home() -> PathBuf { dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")) }

fn log_event(msg: &str) {
    let ts = humantime::format_rfc3339(SystemTime::now());
    let line = format!("[{}] {}\n", ts, msg);
    let _ = OpenOptions::new().append(true).create(true).open("shield_x_audit.log")
        .and_then(|mut f| f.write_all(line.as_bytes()));
    println!("{}", line.trim());
}

async fn start_realtime_protection() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default().with_poll_interval(Duration::from_secs(1))).unwrap();
    watcher.watch(&get_user_home(), RecursiveMode::Recursive).unwrap();

    for res in rx {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in event.paths {
                    if is_file_malicious(&path) { isolate_threat(&path); }
                }
            }
        }
    }
}
