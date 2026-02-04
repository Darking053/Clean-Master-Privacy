use clap::{Parser, Subcommand};
use colored::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use chrono::Local;

#[derive(Parser)]
#[command(name = "clean-master-privacy")]
#[command(version = "0.1.1")]
#[command(about = "High-Performance Linux Security & Privacy Ecosystem", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory for threats
    Scan {
        #[arg(short, long, default_value = ".")]
        path: String,
        /// Automatically move threats to quarantine
        #[arg(short, long)]
        quarantine: bool,
    },
    /// Manage isolated threats
    Quarantine {
        #[arg(short, long)]
        list: bool,
        #[arg(short, long)]
        empty: bool,
    },
    /// Privacy Clean: Remove sensitive logs and cache
    Clean,
}

const MALWARE_DB: &[&str] = &[
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // Test Hash
];

fn main() {
    let cli = Cli::parse();
    println!("{}", "=== Clean Master Privacy ===".bold().bright_cyan());

    match cli.command {
        Commands::Scan { path, quarantine } => {
            run_scan(&path, quarantine);
        }
        Commands::Quarantine { list, empty } => {
            manage_quarantine(list, empty);
        }
        Commands::Clean => {
            privacy_clean();
        }
    }
}

fn run_scan(target: &str, auto_quarantine: bool) {
    let start = std::time::Instant::now();
    let walker = walkdir::WalkDir::new(target).into_iter().filter_map(|e| e.ok());
    let files: Vec<PathBuf> = walker.filter(|e| e.path().is_file()).map(|e| e.path().to_owned()).collect();

    let threats = Arc::new(Mutex::new(Vec::new()));
    println!("🔍 Scanning {} files...", files.len());

    files.par_iter().for_each(|path| {
        if let Ok(mut file) = File::open(path) {
            let mut hasher = Sha256::new();
            let mut buffer = [0; 8192];
            if let Ok(n) = file.read(&mut buffer) {
                hasher.update(&buffer[..n]);
                let hash = format!("{:x}", hasher.finalize());

                if MALWARE_DB.contains(&hash.as_str()) {
                    println!("{} {}", "DETECTION:".red().bold(), path.display());
                    threats.lock().unwrap().push(path.clone());
                    if auto_quarantine {
                        isolate_file(path);
                    }
                }
            }
        }
    });

    let found = threats.lock().unwrap().len();
    println!("\nScan finished in {:?}", start.elapsed());
    if found == 0 {
        println!("{}", "✅ No threats detected.".green());
    } else {
        println!("{}", format!("⚠️ Found {} threats!", found).red().bold());
    }
}

fn isolate_file(path: &Path) {
    let q_dir = dirs::home_dir().unwrap().join(".cmp_quarantine");
    fs::create_dir_all(&q_dir).ok();
    let dest = q_dir.join(path.file_name().unwrap());
    if fs::rename(path, dest).is_ok() {
        println!("{} Isolated.", "->".yellow());
    }
}

fn manage_quarantine(list: bool, empty: bool) {
    let q_dir = dirs::home_dir().unwrap().join(".cmp_quarantine");
    if list {
        println!("{}", "🔒 Quarantined Files:".yellow());
        if let Ok(entries) = fs::read_dir(&q_dir) {
            for entry in entries.flatten() {
                println!(" - {}", entry.file_name().to_string_lossy());
            }
        }
    }
    if empty {
        fs::remove_dir_all(&q_dir).ok();
        println!("🗑️ Quarantine emptied.");
    }
}

fn privacy_clean() {
    println!("🧹 Starting Privacy Clean...");
    let home = dirs::home_dir().unwrap();
    let targets = vec![
        home.join(".cache"),
        home.join(".bash_history"),
        PathBuf::from("/var/tmp"),
    ];

    for path in targets {
        if path.exists() {
            println!("Cleaning: {:?}", path);
            if path.is_dir() { fs::remove_dir_all(&path).ok(); }
            else { fs::remove_file(&path).ok(); }
        }
    }
    println!("{}", "✨ Privacy cleaning completed.".green());
}
