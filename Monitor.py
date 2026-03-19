import time
import hashlib
import logging
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging to generate your final audit trail
logging.basicConfig(filename='security_audit.log', level=logging.INFO,
                    format='%(asctime)s - [ALERT] - %(message)s')

# Define a sensitive directory to monitor (Change this to your test folder)
MONITOR_DIR = "./sensitive_data"

def get_file_hash(filepath, retries=5, delay=0.5):
    """Calculates the SHA-256 hash of a file, with retries for locked files."""
    sha256_hash = hashlib.sha256()
    
    for attempt in range(retries):
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except PermissionError:
            # File is locked by the OS or the program creating it. Wait and try again.
            time.sleep(delay)
        except FileNotFoundError:
            # File was deleted before we could hash it
            return None
            
    # If it still fails after 5 retries, log it gracefully instead of crashing
    logging.warning(f"Could not read hash for {filepath} - File locked by another process.")
    return "FILE_LOCKED"

class SecurityMonitorHandler(FileSystemEventHandler):
    """Handles file system events and triggers alerts."""

    def on_created(self, event):
        if not event.is_directory:
            file_hash = get_file_hash(event.src_path)
            msg = f"FILE CREATED: {event.src_path} | Initial Hash: {file_hash}"
            print(msg)
            logging.info(msg)

    def on_deleted(self, event):
        if not event.is_directory:
            msg = f"UNAUTHORIZED DELETION: Sensitive file removed: {event.src_path}"
            print(msg)
            logging.warning(msg)

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = get_file_hash(event.src_path)
            msg = f"FILE MODIFIED: {event.src_path} | New Hash: {file_hash}"
            print(msg)
            logging.info(msg)

    def on_moved(self, event):
        if not event.is_directory:
            msg = f"SUSPICIOUS MOVEMENT: From {event.src_path} to {event.dest_path}"
            print(msg)
            logging.warning(msg)

if __name__ == "__main__":
    # Create the directory if it doesn't exist
    if not os.path.exists(MONITOR_DIR):
        os.makedirs(MONITOR_DIR)

    print(f"[*] Starting Secure File Transfer Monitor on directory: {MONITOR_DIR}")
    print("[*] Press Ctrl+C to stop monitoring and generate final logs.\n")

    event_handler = SecurityMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Monitoring stopped. Audit log saved to 'security_audit.log'.")
    observer.join()