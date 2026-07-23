import os
import json
import threading
from datetime import datetime

# Ensure data directory exists
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
STATUS_FILE = os.path.join(DATA_DIR, 'recovery_status.json')
RECOVERY_LOG_DIR = os.path.join(DATA_DIR, 'vault_logs')
RECOVERY_LOG_FILE = os.path.join(RECOVERY_LOG_DIR, 'vault_recovery.log')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(RECOVERY_LOG_DIR, exist_ok=True)

class RecoveryManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = "ACTIVE"  # ACTIVE, PROTECTED, RECOVERY MODE
        self.approvals = []
        self.protected_requests = 0
        self.load_status()

    def load_status(self):
        with self.lock:
            if os.path.exists(STATUS_FILE):
                try:
                    with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.state = data.get("state", "ACTIVE")
                        self.approvals = data.get("approvals", [])
                        self.protected_requests = data.get("protected_requests", 0)
                except Exception as e:
                    print(f"Error loading recovery status: {e}")

    def save_status(self):
        # Assumes lock is already held
        try:
            with open(STATUS_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    "state": self.state,
                    "approvals": self.approvals,
                    "protected_requests": self.protected_requests
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving recovery status: {e}")

    def log_event(self, entry):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(RECOVERY_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {entry}\n")
        except Exception as e:
            print(f"Error writing recovery log: {e}")

    def increment_protected_requests(self):
        with self.lock:
            self.protected_requests += 1
            self.save_status()
        return self.protected_requests

    def set_protected(self):
        with self.lock:
            if self.state == "ACTIVE":
                self.state = "PROTECTED"
                self.log_event("Shield activated: Vault status set to PROTECTED state due to anomaly detection.")
                self.save_status()
                return True
        return False

    def initiate_recovery(self, admin_id):
        with self.lock:
            self.state = "RECOVERY MODE"
            self.approvals = []
            self.log_event(f"Recovery sequence initiated by Administrator ({admin_id})")
            self.save_status()

    def add_approval(self, admin_id):
        with self.lock:
            if self.state != "RECOVERY MODE":
                return False, self.approvals
            
            if admin_id not in self.approvals:
                self.approvals.append(admin_id)
                self.log_event(f"Recovery consensus approval signed by: {admin_id}")
                self.save_status()
            
            if len(self.approvals) >= 2:
                self.state = "ACTIVE"
                self.approvals = []
                self.log_event("Dual-Admin consensus reached. System restored to ACTIVE state. ADTL Disabled.")
                self.save_status()
                return True, []
            
            return False, self.approvals

    def get_status_info(self):
        with self.lock:
            return {
                "state": self.state,
                "approvals": list(self.approvals),
                "protected_requests": self.protected_requests
            }

    def get_logs(self, max_lines=50):
        if not os.path.exists(RECOVERY_LOG_FILE):
            return []
        try:
            with open(RECOVERY_LOG_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            return lines[-max_lines:]
        except Exception as e:
            print(f"Error reading recovery log: {e}")
            return []

# Singleton instance
recovery_mgr = RecoveryManager()
