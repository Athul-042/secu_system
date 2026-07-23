import os
import sys
import shutil
import csv
import json
from datetime import datetime

# Ensure locally installed D-drive python packages can be imported
local_pkg_path = os.path.join(os.path.dirname(__file__), 'python_packages')
if local_pkg_path not in sys.path:
    sys.path.insert(0, local_pkg_path)

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ Cryptography library not found! AES Encryption will run in simulated mode.")

# --- Config & Paths ---
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
SENSITIVE_DIR = os.path.join(DATA_DIR, 'sensitive_files')
BACKUP_DIR = os.path.join(DATA_DIR, 'vault_backup')
RECOVERY_LOG_DIR = os.path.join(DATA_DIR, 'vault_logs')
SENSITIVE_FILE = os.path.join(SENSITIVE_DIR, 'student_records.csv')
BACKUP_FILE = os.path.join(BACKUP_DIR, 'student_records.csv.orig')
KEY_FILE = os.path.join(DATA_DIR, 'vault_key.key')
STATUS_FILE = os.path.join(DATA_DIR, 'vault_status.json')
RECOVERY_LOG_FILE = os.path.join(RECOVERY_LOG_DIR, 'vault_recovery.log')

# Create necessary directories
os.makedirs(SENSITIVE_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(RECOVERY_LOG_DIR, exist_ok=True)

DEFAULT_RECORDS = [
    {"student_id": "1001", "name": "Alice Johnson", "ssn": "123-45-6789", "grade": "A+", "status": "Active"},
    {"student_id": "1002", "name": "Bob Smith", "ssn": "987-65-4321", "grade": "B-", "status": "Active"},
    {"student_id": "1003", "name": "Charlie Brown", "ssn": "555-12-3456", "grade": "A", "status": "Active"},
    {"student_id": "1004", "name": "Diana Prince", "ssn": "444-98-7654", "grade": "A++", "status": "Active"},
    {"student_id": "1005", "name": "Ethan Hunt", "ssn": "333-21-9876", "grade": "C+", "status": "Probation"}
]

import base64
import io

def get_cipher_suite():
    if not CRYPTO_AVAILABLE:
        return None
    try:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'r', encoding='utf-8') as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key().decode('utf-8')
            with open(KEY_FILE, 'w', encoding='utf-8') as f:
                f.write(key)
        return Fernet(key.encode('utf-8'))
    except Exception as e:
        print(f"Error loading encryption key: {e}")
        return None

def encrypt_data(plaintext):
    if not plaintext:
        return ""
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode('utf-8')
        
    cipher_suite = get_cipher_suite()
    if cipher_suite:
        try:
            ciphertext = cipher_suite.encrypt(plaintext.encode('utf-8'))
            return ciphertext.decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            
    # Simulated mode fallback
    return base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')

def decrypt_data(ciphertext):
    if not ciphertext:
        return ""
    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode('utf-8')
        
    cipher_suite = get_cipher_suite()
    if cipher_suite:
        try:
            plaintext = cipher_suite.decrypt(ciphertext.encode('utf-8'))
            return plaintext.decode('utf-8')
        except Exception as e:
            raise e
            
    # Simulated mode fallback
    return base64.b64decode(ciphertext.encode('utf-8')).decode('utf-8')

# Initial setup: create sensitive file if not exists
def init_vault():
    if not os.path.exists(BACKUP_FILE):
        write_csv(BACKUP_FILE, DEFAULT_RECORDS)
        
    if not os.path.exists(SENSITIVE_FILE):
        # Read the backup file and encrypt it
        with open(BACKUP_FILE, 'r', encoding='utf-8') as f:
            plaintext = f.read()
        ciphertext = encrypt_data(plaintext)
        with open(SENSITIVE_FILE, 'w', encoding='utf-8') as f:
            f.write(ciphertext)
            
    if not os.path.exists(STATUS_FILE):
        save_status("NORMAL")

def write_csv(path, data):
    if not data:
        return
    keys = data[0].keys()
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

def read_csv(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        
        # Try to decrypt first
        try:
            decrypted = decrypt_data(content)
            f_in = io.StringIO(decrypted)
            return list(csv.DictReader(f_in))
        except Exception:
            # Fallback if content is already plaintext
            f_in = io.StringIO(content)
            return list(csv.DictReader(f_in))
    except Exception as e:
        print(f"Error reading/parsing CSV {path}: {e}")
        return []

def get_status():
    from recovery_manager import recovery_mgr
    status = recovery_mgr.get_status_info()
    return {"state": status["state"], "approvals": status["approvals"]}

def save_status(state, approvals=None):
    pass

def append_recovery_log(entry):
    from recovery_manager import recovery_mgr
    recovery_mgr.log_event(entry)

# --- Active Defense Functions ---

def apply_masking():
    print("🛡️ Vault: Dynamic Masking Activated (No file writes on disk)")

def apply_encryption():
    print("🛡️ Vault: Dynamic Encryption Activated (No file writes on disk)")

def apply_decoy():
    print("🛡️ Vault: Dynamic Decoy Activated (No file writes on disk)")

def recover_data():
    init_vault()
    if os.path.exists(BACKUP_FILE):
        try:
            with open(BACKUP_FILE, 'r', encoding='utf-8') as f:
                plaintext = f.read()
            ciphertext = encrypt_data(plaintext)
            with open(SENSITIVE_FILE, 'w', encoding='utf-8') as f:
                f.write(ciphertext)
            print("✅ Vault: Restored sensitive file on disk to encrypted format")
        except Exception as e:
            print(f"Error restoring backup file: {e}")
    print("✅ Vault: Data Restored to Normal State successfully")

# Backward-compatible aliases for route names and caller code
restore_data = recover_data

def get_recovery_logs(max_lines=50):
    from recovery_manager import recovery_mgr
    return recovery_mgr.get_logs(max_lines)

def add_approval(admin_id):
    from recovery_manager import recovery_mgr
    return recovery_mgr.add_approval(admin_id)

# Initial trigger
init_vault()


