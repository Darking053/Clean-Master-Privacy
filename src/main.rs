use gtk4::{self as gtk, glib, prelude::*, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use libadwaita as adw;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const APP_NAME: &str = "Clean-Master-Privacy";
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "Powershell -ExecutionPolicy", "Invoke-WebRequest",
    "rm -rf /", "del /f /s /q", "net user /add", "nc -e /bin/sh",
    "CreateRemoteThread", "AdjustTokenPrivileges", "SetWindowsHookEx",
    "GlobalAlloc", "WriteProcessMemory", "shell_exec", "passthru"
];

fn main() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.cmp.security.ultimate")
        .build();

    application.connect_activate(build_ui);
    
    // Background guard monitoring logic
    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { start_background_guard().await });
    });

    application.run()
}

// --- Analysis Engine ---

fn is_malicious(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let dangerous_exts = ["exe", "dll", "bin", "sh", "bat", "ps1", "js", "php", "py"];
    
    if !dangerous_exts.contains(&ext.as_str()) { return false; }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buffer = [0u8; 16384];
    if let Ok(n) = file.read(&mut buffer) {
        if n == 0 { return false; }
        let content = String::from_utf8_lossy(&buffer[..n]).to_lowercase();
        return MALICIOUS_PATTERNS.iter().any(|&p| content.contains(&p.to_lowercase()));
    }
    false
}

fn isolate(path: &Path) {
    let q_dir = dirs::home_dir().unwrap().join(".cmp_quarantine");
    let _ = fs::create_dir_all(&q_dir);
    if let Some(name) = path.file_name() {
        let dest = q_dir.join(name);
        if fs::copy(path, &dest).is_ok() {
            let _ = fs::remove_file(path);
            log_security_event(&format!("CMP isolated threat: {:?}", name));
        }
    }
}

// --- UI Logic ---

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title(APP_NAME)
        .default_width(600)
        .default_height(450)
        .resizable(false)
        .build();

    let root = GtkBox::new(Orientation::Vertical, 20);
    
    // Fix: set_margin_all is replaced with explicit margins for cross-version compatibility
    root.set_margin_top(30);
    root.set_margin_bottom(30);
    root.set_margin_start(30);
    root.set_margin_end(30);

    let title_lbl = Label::builder()
        .label("🛡️ CMP Cyber Shield")
        .build();
    title_lbl.add_css_class("title-1");

    let stats_lbl = Label::new(Some("System status: Monitoring in background"));
    let progress = ProgressBar::new();
    let scan_btn = Button::with_label("🚀 Start Deep System Clean");
    scan_btn.add_css_class("suggested-action");

    scan_btn.connect_clicked(glib::clone!(@weak stats_lbl, @weak progress => move |b| {
        b.set_sensitive(false);
        let target = dirs::home_dir().unwrap();
        
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

async fn run_deep_scan(target: String, label: Option<Label>, pb: Option<ProgressBar>) {
    let files: Vec<PathBuf> = walkdir::WalkDir::new(&target)
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
            glib::idle_add_local_once(move || p.set_fraction(i as f64 / total));
        }

        if is_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate(path);
        }
    });

    if let Some(l) = label {
        l.set_text(&format!("✅ Scan complete. {} threats neutralized.", *threats.lock().unwrap()));
    }
}

async fn start_background_guard() {
    let (tx, rx) = std::sync::mpsc::channel();
    let config = Config::default().with_poll_interval(Duration::from_secs(1));
    let mut watcher = RecommendedWatcher::new(tx, config).unwrap();
    
    if let Some(home) = dirs::home_dir() {
        let _ = watcher.watch(&home, RecursiveMode::Recursive);
        for res in rx {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in event.paths {
                        if is_malicious(&path) { isolate(&path); }
                    }
                }
            }
        }
    }
}

fn log_security_event(msg: &str) {
    let ts = humantime::format_rfc3339(SystemTime::now());
    let line = format!("[{}] {}\n", ts, msg);
    let _ = OpenOptions::new().append(true).create(true).open("cmp_security.log")
        .and_then(|mut f| f.write_all(line.as_bytes()));
}
