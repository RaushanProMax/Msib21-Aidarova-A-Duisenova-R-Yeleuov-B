
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
from tkinter import filedialog, messagebox

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

    def scan_network(self):
        self.logger.info("Scanning network for threats...")

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


# GUI Part
class AntivirusGUI:
    def __init__(self, master, antivirus):
        self.master = master
        self.master.title("Polymorphic Antivirus")

        self.antivirus = antivirus

        # UI components
        self.label = tk.Label(master, text="Select a directory to scan for threats", font=("Arial", 14))
        self.label.pack(pady=10)

        self.scan_button = tk.Button(master, text="Select Directory", font=("Arial", 12), command=self.select_directory)
        self.scan_button.pack(pady=10)

        self.log_button = tk.Button(master, text="Show Logs", font=("Arial", 12), command=self.show_logs)
        self.log_button.pack(pady=10)

        self.quit_button = tk.Button(master, text="Quit", font=("Arial", 12), command=self.quit)
        self.quit_button.pack(pady=10)

        self.status_label = tk.Label(master, text="Status: Idle", font=("Arial", 12))
        self.status_label.pack(pady=10)

    def select_directory(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.status_label.config(text=f"Scanning: {folder_path}")
            threading.Thread(target=self.scan_directory, args=(folder_path,), daemon=True).start()

    def scan_directory(self, directory):
        threat_db_path = "threat_db.json"
        self.antivirus.run(directory, threat_db_path)
        self.status_label.config(text="Scan Completed")

    def show_logs(self):
        log_files = os.listdir("logs")
        if not log_files:
            messagebox.showinfo("No Logs", "No logs available.")
            return
        
        log_file = log_files[-1]
        log_file_path = os.path.join("logs", log_file)

        with open(log_file_path, "r") as file:
            logs = file.read()

        logs_window = tk.Toplevel(self.master)
        logs_window.title("Antivirus Logs")
        logs_text = tk.Text(logs_window, wrap="word")
        logs_text.insert(tk.END, logs)
        logs_text.pack(expand=True, fill=tk.BOTH)

    def quit(self):
        self.master.quit()


def run_in_background(antivirus):
    antivirus.run(scan_path="/path/to/scan", threat_db_path="threat_db.json")
    time.sleep(3600)  # Run every hour


if __name__ == "__main__":
    antivirus = PolymorphicAntivirus()
    thread = threading.Thread(target=run_in_background, args=(antivirus,), daemon=True)
    thread.start()

    # Start GUI
    root = tk.Tk()
    gui = AntivirusGUI(root, antivirus)
    root.mainloop()
