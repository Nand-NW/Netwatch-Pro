# Netwatch-Pro
# 🛡️ NetWatch Pro – Modern Network Monitoring for Windows

NetWatch Pro is a simple and local network monitoring tool for Windows with AI-assisted anomaly detection.  
It shows all devices in your local network, tracks their online status, and provides live statistics.

---

## 📋 Features

- **Network Overview**
  - Lists all devices in your local network
  - Detects new and vanished devices automatically
  - Estimates bandwidth usage (for anomaly detection)

- **Device Monitoring**
  - Live online/offline status
  - Packets sent/received
  - Uptime percentage

- **Technical**
  - Modern, user-friendly GUI built with Tkinter
  - Fully local processing (no cloud required)
  - Optimized for Windows systems

---

## 💻 System Requirements

- Windows 10 or higher
- Administrator privileges for full functionality
- Active network connection
- Python 3.8+ (for building EXE)

---

## 🚀 Installation

### From Source
```bash
git clone https://github.com/YOURUSERNAME/Netwatch-Pro.git
cd Netwatch-Pro
python -m pip install --upgrade pip
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed --name=NetWatchPro netwatch_pro.py
