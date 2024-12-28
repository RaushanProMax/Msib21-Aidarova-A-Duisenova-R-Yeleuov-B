import os
import json
import logging
import pika
import hashlib
import threading
import time
import shutil
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

class PolymorphicAntivirus:
    def __init__(self, rabbitmq_host='localhost'):
        self.setup_logging()
        self.logger.info("Initializing antivirus")

        # RabbitMQ setup
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='antivirus_logs')
        
    def setup_logging(self):
        os.makedirs("logs", exist_ok=True)
        log_filename = f"logs/antivirus_{time.strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)
        self.logger = logging.getLogger("PolymorphicAntivirus")

    def hash_file(self, file_path):
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {e}")
            return None

    def quarantine_file(self, file_path):
        try:
            quarantine_dir = "quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            destination = os.path.join(quarantine_dir, os.path.basename(file_path))
            shutil.move(file_path, destination)
            self.logger.warning(f"File moved to quarantine: {file_path}")
        except Exception as e:
            self.logger.error(f"Error moving file to quarantine: {file_path}: {e}")

    def terminate_process(self, file_path):
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if proc.info['exe'] and os.path.samefile(proc.info['exe'], file_path):
                    proc.terminate()
                    self.logger.warning(f"Terminated process using file: {file_path}")
        except Exception as e:
            self.logger.error(f"Error terminating process for file {file_path}: {e}")

    def scan_file(self, file_path, threat_db):
        try:
            file_hash = self.hash_file(file_path)
            if not file_hash:
                return False

            file_size = os.path.getsize(file_path)

            for threat in threat_db:
                if threat['hash'] == file_hash and threat['size'] == file_size:
                    self.logger.warning(f"Threat detected in {file_path}: {threat['name']}")
                    self.send_log(f"Threat detected: {file_path} -> {threat['name']}")
                    self.quarantine_file(file_path)
                    self.terminate_process(file_path)
                    return True
            return False
        except FileNotFoundError:
            self.logger.error(f"File not found during scan: {file_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return False

    def scan_memory(self):
        # Stub for scanning memory. To implement this, you need OS-specific libraries.
        self.logger.info("Scanning memory...")
        # Example: Scan loaded modules (requires elevated privileges).

    def scan_network(self):
        self.logger.info("Scanning network for threats...")
        # Stub for network scanning logic. Could include port scanning, packet inspection, etc.
        # For example, using `scapy` or `socket` to inspect packets.

    def send_log(self, message):
        try:
            self.channel.basic_publish(exchange='', routing_key='antivirus_logs', body=message)
            self.logger.info("Sent log to RabbitMQ: " + message)
        except Exception as e:
            self.logger.error(f"Error sending log to RabbitMQ: {e}")

    def load_threat_db(self, db_path):
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Threat database file not found: {db_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading threat database: {e}")
            return []

    def run(self, scan_path, threat_db_path):
        self.logger.info("Starting scan")

        threat_db = self.load_threat_db(threat_db_path)
        if not threat_db:
            self.logger.error("Threat database is empty. Exiting.")
            return

        for root, _, files in os.walk(scan_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path, threat_db)

        self.scan_memory()
        self.scan_network()
        self.logger.info("Scan completed")

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Polymorphic Antivirus")
        self.root.geometry("600x400")

        # Antivirus instance
        self.antivirus = PolymorphicAntivirus()

        # Default database path
        self.default_db_path = "threat_db.json"

        # UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Path selection for scanning
        self.scan_label = tk.Label(self.root, text="Path to Scan:")
        self.scan_label.pack(pady=5)

        self.scan_path_entry = tk.Entry(self.root, width=50)
        self.scan_path_entry.pack(pady=5)

        self.browse_button = tk.Button(self.root, text="Browse", command=self.browse_scan_path)
        self.browse_button.pack(pady=5)

        # Buttons for actions
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        self.memory_button = tk.Button(self.root, text="Scan Memory", command=self.scan_memory)
        self.memory_button.pack(pady=5)

        self.network_button = tk.Button(self.root, text="Scan Network", command=self.scan_network)
        self.network_button.pack(pady=5)

        # Logs Section
        self.logs_label = tk.Label(self.root, text="Logs:")
        self.logs_label.pack(pady=5)

        self.logs_text = tk.Text(self.root, height=10, width=70)
        self.logs_text.pack(pady=5)

        self.clear_logs_button = tk.Button(self.root, text="Clear Logs", command=self.clear_logs)
        self.clear_logs_button.pack(pady=5)

    def browse_scan_path(self):
        path = filedialog.askdirectory()
        if path:
            self.scan_path_entry.delete(0, tk.END)
            self.scan_path_entry.insert(0, path)

    def append_log(self, message):
        self.logs_text.insert(tk.END, message + "\n")
        self.logs_text.see(tk.END)

    def start_scan(self):
        scan_path = self.scan_path_entry.get()

        if not os.path.exists(scan_path):
            messagebox.showerror("Error", "Invalid scan path!")
            return

        if not os.path.exists(self.default_db_path):
            messagebox.showerror("Error", f"Threat database not found at {self.default_db_path}!")
            return

        self.append_log("Starting scan...")

        def scan_task():
            self.antivirus.run(scan_path, self.default_db_path)
            self.append_log("Scan completed.")

        threading.Thread(target=scan_task, daemon=True).start()

    def scan_memory(self):
        self.append_log("Scanning memory...")

        def memory_task():
            self.antivirus.scan_memory()
            self.append_log("Memory scan completed.")

        threading.Thread(target=memory_task, daemon=True).start()

    def scan_network(self):
        self.append_log("Scanning network...")

        def network_task():
            self.antivirus.scan_network()
            self.append_log("Network scan completed.")

        threading.Thread(target=network_task, daemon=True).start()

    def clear_logs(self):
        self.logs_text.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()
