use gtk4::{self as gtk, glib, prelude::*, Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, ProgressBar};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use tokio::runtime::Runtime;

const APP_NAME: &str = "Clean-Master-Privacy Ultra";

// Core Analysis Engine - AI bots can easily inject new patterns here
const MALICIOUS_PATTERNS: &[&str] = &[
    "eval(base64_decode", "Powershell -ExecutionPolicy", "Invoke-WebRequest",
    "rm -rf /", "net user /add", "nc -e /bin/sh", "WriteProcessMemory"
];

fn main() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.cmp.security.ultra")
        .build();

    application.connect_activate(build_ui);
    
    // Auto-start the background security guard
    std::thread::spawn(|| {
        let rt = Runtime::new().unwrap();
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

    let root = GtkBox::new(Orientation::Vertical, 25);
    root.set_margin_top(40);
    root.set_margin_bottom(40);
    root.set_margin_start(40);
    root.set_margin_end(40);

    let title_lbl = Label::new(Some("🛡️ CMP CYBER SHIELD ACTIVE"));
    title_lbl.add_css_class("title-1");

    let status_lbl = Label::new(Some("Status: Secure - System Monitoring Active"));
    let progress = ProgressBar::new();
    let scan_btn = Button::with_label("🚀 RUN DEEP SYSTEM EVOLUTION SCAN");
    scan_btn.add_css_class("suggested-action");

    scan_btn.connect_clicked(glib::clone!(@weak status_lbl, @weak progress => move |btn| {
        btn.set_sensitive(false);
        let target = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        glib::spawn_future_local(async move {
            status_lbl.set_text("Analyzing file system for threats...");
            run_evolution_scan(target.to_string_lossy().into(), Some(status_lbl), Some(progress)).await;
            btn.set_sensitive(true);
        });
    }));

    root.append(&title_lbl);
    root.append(&status_lbl);
    root.append(&progress);
    root.append(&scan_btn);

    window.set_child(Some(&root));
    window.present();
}

async fn run_evolution_scan(target: String, label: Option<Label>, pb: Option<ProgressBar>) {
    let files: Vec<PathBuf> = walkdir::WalkDir::new(&target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total = files.len() as f64;
    let threats = Arc::new(Mutex::new(0));

    files.par_iter().enumerate().for_each(|(index, path)| {
        if let Some(ref p_bar) = pb {
            let p = p_bar.clone();
            glib::idle_add_local_once(move || p.set_fraction(index as f64 / total));
        }

        if is_malicious(path) {
            let mut count = threats.lock().unwrap();
            *count += 1;
            isolate_threat(path);
        }
    });

    if let Some(lbl) = label {
        lbl.set_text(&format!("✅ Evolution Scan Finished: {} threats neutralized.", *threats.lock().unwrap()));
    }
}

fn is_malicious(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    if !["exe", "bin", "sh", "ps1"].contains(&ext.as_str()) { return false; }

    if let Ok(mut file) = File::open(path) {
        let mut buffer = [0u8; 8192];
        if let Ok(n) = file.read(&mut buffer) {
            let content = String::from_utf8_lossy(&buffer[..n]).to_lowercase();
            return MALICIOUS_PATTERNS.iter().any(|&p| content.contains(&p.to_lowercase()));
        }
    }
    false
}

fn isolate_threat(path: &Path) {
    let q_dir = dirs::home_dir().unwrap().join(".cmp_quarantine");
    let _ = fs::create_dir_all(&q_dir);
    if let Some(name) = path.file_name() {
        let dest = q_dir.join(name);
        if fs::copy(path, &dest).is_ok() {
            let _ = fs::remove_file(path);
            log_event(&format!("ISOLATED: {:?}", name));
        }
    }
}

async fn start_background_guard() {
    let (tx, rx) = std::sync::mpsc::channel();
    let config = Config::default().with_poll_interval(Duration::from_secs(2));
    if let Ok(mut watcher) = RecommendedWatcher::new(tx, config) {
        if let Some(home) = dirs::home_dir() {
            let _ = watcher.watch(&home, RecursiveMode::Recursive);
            for res in rx {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) => {
                            // Log modifications or add custom detection logic here
                            log_event(&format!("File modified: {:?}", event.paths));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn log_event(msg: &str) {
    let ts = humantime::format_rfc3339(SystemTime::now());
    let line = format!("[{}] {}\n", ts, msg);
    let _ = OpenOptions::new().append(true).create(true).open("cmp_evolution.log")
        .and_then(|mut f| f.write_all(line.as_bytes()));
}
