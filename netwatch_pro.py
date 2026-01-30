"""
NetWatch Pro - Netzwerküberwachung für Windows
Legales Tool zur Überwachung des eigenen Netzwerks
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import subprocess
import re
import platform
from datetime import datetime
from collections import defaultdict
import random

class NetworkDevice:
    def __init__(self, ip, mac, hostname="Unbekannt"):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.bandwidth_history = []
        self.is_new = True
        
    def update_seen(self):
        self.last_seen = datetime.now()
        self.is_new = False
        
    def estimate_bandwidth(self):
        bandwidth = random.randint(0, 1000)  # KB/s (simuliert)
        self.bandwidth_history.append(bandwidth)
        if len(self.bandwidth_history) > 10:
            self.bandwidth_history.pop(0)
        return bandwidth
    
    def get_avg_bandwidth(self):
        if not self.bandwidth_history:
            return 0
        return sum(self.bandwidth_history) / len(self.bandwidth_history)


class AnomalyDetector:
    """Einfache KI-basierte Anomalieerkennung"""
    
    def __init__(self):
        self.baseline = {}
        
    def check_anomaly(self, device_ip, current_bandwidth):
        if device_ip not in self.baseline:
            self.baseline[device_ip] = {'values': [], 'threshold': 0}
            
        baseline = self.baseline[device_ip]
        baseline['values'].append(current_bandwidth)
        
        if len(baseline['values']) > 20:
            baseline['values'].pop(0)
            
        if len(baseline['values']) >= 5:
            avg = sum(baseline['values']) / len(baseline['values'])
            std_dev = (sum((x - avg) ** 2 for x in baseline['values']) / len(baseline['values'])) ** 0.5
            baseline['threshold'] = avg + (2 * std_dev)
            
            if current_bandwidth > baseline['threshold'] and current_bandwidth > avg * 2:
                return True, f"Ungewöhnlich hoch: {current_bandwidth:.0f} KB/s (Normal: {avg:.0f} KB/s)"
                
        return False, None


class NetWatchProGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ NetWatch Pro - Netzwerküberwachung")
        self.root.geometry("900x650")
        self.root.configure(bg='#1e1e1e')
        
        self.devices = {}
        self.anomaly_detector = AnomalyDetector()
        self.scanning = False
        self.scan_thread = None
        
        self.setup_ui()
        self.check_admin()
        
    def check_admin(self):
        try:
            if platform.system() == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.log_message("⚠️ WARNUNG: Nicht als Administrator gestartet. Einige Funktionen könnten eingeschränkt sein.", "warning")
        except:
            pass
    
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#2d2d2d', height=80)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ NetWatch Pro", 
                              font=('Segoe UI', 20, 'bold'), 
                              bg='#2d2d2d', fg='#00ff88')
        title_label.pack(pady=20)
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg='#1e1e1e')
        control_frame.pack(fill='x', padx=20, pady=10)
        
        self.start_btn = tk.Button(control_frame, text="▶️ Scan starten", 
                                   command=self.start_scan,
                                   bg='#00ff88', fg='black', 
                                   font=('Segoe UI', 11, 'bold'),
                                   relief='flat', padx=20, pady=8,
                                   cursor='hand2')
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = tk.Button(control_frame, text="⏸️ Scan stoppen", 
                                  command=self.stop_scan,
                                  bg='#ff4444', fg='white', 
                                  font=('Segoe UI', 11, 'bold'),
                                  relief='flat', padx=20, pady=8,
                                  state='disabled', cursor='hand2')
        self.stop_btn.pack(side='left', padx=5)
        
        self.clear_btn = tk.Button(control_frame, text="🗑️ Liste leeren", 
                                   command=self.clear_devices,
                                   bg='#444444', fg='white', 
                                   font=('Segoe UI', 11),
                                   relief='flat', padx=20, pady=8,
                                   cursor='hand2')
        self.clear_btn.pack(side='left', padx=5)
        
        self.status_label = tk.Label(control_frame, text="Status: Bereit", 
                                     bg='#1e1e1e', fg='#00ff88',
                                     font=('Segoe UI', 10))
        self.status_label.pack(side='right', padx=10)
        
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Tab 1: Geräte-Liste
        devices_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(devices_frame, text='📱 Geräte')
        
        tree_frame = tk.Frame(devices_frame, bg='#2d2d2d')
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ('IP', 'MAC', 'Hostname', 'Bandwidth', 'Status', 'Zuletzt gesehen')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', height=15)
        
        self.tree.heading('#0', text='#')
        self.tree.heading('IP', text='IP-Adresse')
        self.tree.heading('MAC', text='MAC-Adresse')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('Bandwidth', text='Bandbreite')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Zuletzt gesehen', text='Zuletzt gesehen')
        
        self.tree.column('#0', width=40)
        self.tree.column('IP', width=120)
        self.tree.column('MAC', width=130)
        self.tree.column('Hostname', width=150)
        self.tree.column('Bandwidth', width=100)
        self.tree.column('Status', width=100)
        self.tree.column('Zuletzt gesehen', width=150)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Tab 2: Log
        log_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(log_frame, text='📋 Log')
        
        self.log_text = scrolledtext.ScrolledText(log_frame, 
                                                  bg='#1e1e1e', 
                                                  fg='#00ff88',
                                                  font=('Consolas', 9),
                                                  wrap='word')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 3: Info
        info_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(info_frame, text='ℹ️ Info')
        
        info_text = tk.Text(info_frame, bg='#1e1e1e', fg='white', 
                           font=('Segoe UI', 10), wrap='word')
        info_text.pack(fill='both', expand=True, padx=20, pady=20)
        info_text.insert('1.0', """
🛡️ NetWatch Pro - Netzwerküberwachung

Funktionen:
• Erkennt alle Geräte im lokalen Netzwerk
• Zeigt neue und verschwundene Geräte an
• Schätzt Bandbreitennutzung (simuliert)
• KI-basierte Anomalieerkennung
• 100% lokal, keine Cloud-Verbindung

⚠️ Rechtliche Hinweise:
Dieses Tool darf NUR im eigenen Netzwerk verwendet werden!
Die Überwachung fremder Netzwerke ohne Erlaubnis ist illegal.

💡 Hinweise:
• Für volle Funktion als Administrator starten
• Bandbreitenwerte sind Schätzungen
• Die Anomalieerkennung lernt nach einigen Scans

Version: 1.0
© 2025 NetWatch Pro
        """)
        info_text.config(state='disabled')
        
        self.log_message("✅ NetWatch Pro gestartet", "info")
        self.log_message("ℹ️ Klicke auf 'Scan starten' um dein Netzwerk zu überwachen", "info")
        
    def log_message(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert('end', f"[{timestamp}] {message}\n")
        self.log_text.see('end')
        
    def scan_network(self):
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            output = result.stdout
            
            ip_pattern = r'IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)'
            matches = re.findall(ip_pattern, output)
            
            if not matches:
                self.log_message("❌ Keine Netzwerkverbindung gefunden", "error")
                return []
            
            local_ip = matches[0]
            network_prefix = '.'.join(local_ip.split('.')[0:3])
            
            self.log_message(f"🔍 Scanne Netzwerk {network_prefix}.0/24...", "info")
            
            arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            arp_output = arp_result.stdout
            
            devices_found = []
            
            arp_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+'
            for match in re.finditer(arp_pattern, arp_output, re.IGNORECASE):
                ip = match.group(1)
                mac = match.group(2).upper()
                
                if ip.startswith(network_prefix):
                    devices_found.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': self.get_hostname(ip)
                    })
            
            return devices_found
            
        except Exception as e:
            self.log_message(f"❌ Fehler beim Scannen: {str(e)}", "error")
            return []
    
    def get_hostname(self, ip):
        try:
            result = subprocess.run(['nslookup', ip], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=2)
            output = result.stdout
            
            name_pattern = r'Name:\s+(.+)'
            match = re.search(name_pattern, output)
            if match:
                return match.group(1).strip()
        except:
            pass
        
        return "Unbekannt"
    
    def scan_loop(self):
        scan_count = 0
        
        while self.scanning:
            scan_count += 1
            self.status_label.config(text=f"Status: Scanne... (#{scan_count})")
            
            devices_found = self.scan_network()
            current_ips = set()
            
            for device_data in devices_found:
                ip = device_data['ip']
                mac = device_data['mac']
                hostname = device_data['hostname']
                current_ips.add(ip)
                
                if ip not in self.devices:
                    self.devices[ip] = NetworkDevice(ip, mac, hostname)
                    self.log_message(f"🆕 Neues Gerät gefunden: {ip} ({mac})", "info")
                else:
                    self.devices[ip].update_seen()
                
                bandwidth = self.devices[ip].estimate_bandwidth()
                is_anomaly, msg = self.anomaly_detector.check_anomaly(ip, bandwidth)
                
                if is_anomaly:
                    self.log_message(f"⚠️ ANOMALIE bei {ip}: {msg}", "anomaly")
            
            for ip, device in self.devices.items():
                if ip not in current_ips:
                    time_diff = (datetime.now() - device.last_seen).total_seconds()
                    if time_diff > 300:
                        self.log_message(f"👋 Gerät verschwunden: {ip}", "warning")
            
            self.update_device_list()
            
            for _ in range(10):
                if not self.scanning:
                    break
                time.sleep(1)
        
        self.status_label.config(text="Status: Gestoppt")
    
    def update_device_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for idx, (ip, device) in enumerate(sorted(self.devices.items()), 1):
            bandwidth = device.get_avg_bandwidth()
            time_diff = (datetime.now() - device.last_seen).total_seconds()
            
            if time_diff < 60:
                status = "🟢 Online"
            elif time_diff < 300:
                status = "🟡 Kürzlich offline"
            else:
                status = "🔴 Offline"
            
            last_seen = device.last_seen.strftime("%H:%M:%S")
            
            tag = 'new' if device.is_new else 'normal'
            
            self.tree.insert('', 'end', text=str(idx),
                           values=(ip, device.mac, device.hostname, 
                                  f"{bandwidth:.0f} KB/s", status, last_seen),
                           tags=(tag,))
        
        self.tree.tag_configure('new', background='#004400')
        self.tree.tag_configure('normal', background='#2d2d2d')
    
    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.log_message("▶️ Scan gestartet", "info")
            
            self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
            self.scan_thread.start()
    
    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.log_message("⏸️ Scan gestoppt", "warning")
    
    def clear_devices(self):
        if messagebox.askyesno("Bestätigung", "Alle Geräte aus der Liste entfernen?"):
            self.devices.clear()
            self.update_device_list()
            self.log_message("🗑️ Geräteliste geleert", "info")


def main():
    root = tk.Tk()
    app = NetWatchProGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
