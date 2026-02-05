# 🛡️ Clean-Master-Privacy Ultra

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Framework](https://img.shields.io/badge/framework-egui-blue.svg)](https://github.com/emilk/egui)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://github.com/gamestime102/Clean-Master-Privacy/actions/workflows/build-linux.yml/badge.svg)](https://github.com/gamestime102/Clean-Master-Privacy/actions)

**Clean-Master-Privacy (CMP) Ultra** is a high-performance, enterprise-grade security dashboard and system optimizer built entirely in Rust. It leverages the power of the ClamAV engine with a modern, hardware-accelerated GUI to provide deep heuristic analysis and privacy cleanup.



## ✨ Key Features

* **🔍 Deep Scan Engine:** Multithreaded integration with `clamscan` for real-time malware detection.
* **📊 Security Dashboard:** At-a-glance overview of system health, risk scores, and scan statistics.
* **🧹 Privacy Guard:** Advanced cleanup tool to remove system junk, journal logs, and browser trackers.
* **🚀 Ultra-Responsive UI:** Built with `egui`, providing a smooth 60fps experience with zero-latency input.
* **📜 Event Logging:** Chronological security event tracking with detailed threat reports.
* **🌗 Adaptive Themes:** Fully optimized Dark Mode for professional workstations.

## 🏗️ Architecture

The application follows a **Message-Passing Architecture** to ensure the UI never freezes during heavy security operations:

1.  **Main Thread (GUI):** Handles rendering and user interaction using `eframe` (egui).
2.  **Worker Threads:** Spawned for heavy CLI operations (ClamAV).
3.  **MPSC Channels:** Asynchronous communication between the scanner engine and the UI for real-time log streaming.



## 🚀 Getting Started

### Prerequisites

* **Rust Toolchain:** [Install Rust](https://rustup.rs/)
* **ClamAV Engine:** * Ubuntu: `sudo apt install clamav clamav-daemon`
    * Fedora: `sudo dnf install clamav clamav-update`
* **GTK Development Files (Linux only):**
    * Ubuntu: `sudo apt install libgtk-3-dev libwayland-dev libx11-dev libasound2-dev`

### Installation & Build

1. Clone the repository:
   ```bash
   git clone [https://github.com/gamestime102/Clean-Master-Privacy.git](https://github.com/gamestime102/Clean-Master-Privacy.git)
   cd Clean-Master-Privacy
