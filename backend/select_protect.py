"""Select files to protect: backup + write encrypted copy to sensitive_files.

Usage:
    python select_protect.py path/to/file1 [path/to/file2 ...]

This script copies each given file to `data/vault_backup/` and writes an
encrypted blob to `data/sensitive_files/<basename>` using the project's
`vault_manager.encrypt_data` implementation (Fernet if available, else base64).
"""
import os
import sys
import shutil

ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(ROOT, 'data')
BACKUP_DIR = os.path.join(DATA_DIR, 'vault_backup')
SENSITIVE_DIR = os.path.join(DATA_DIR, 'sensitive_files')

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(SENSITIVE_DIR, exist_ok=True)

def protect_file(src_path):
    if not os.path.exists(src_path):
        print(f"[select_protect] File not found: {src_path}")
        return False

    from vault_manager import encrypt_data

    basename = os.path.basename(src_path)
    backup_dest = os.path.join(BACKUP_DIR, basename + '.orig')
    sensitive_dest = os.path.join(SENSITIVE_DIR, basename)

    try:
        # Copy original to backup (preserve original)
        shutil.copy2(src_path, backup_dest)

        # Read plaintext and encrypt
        with open(src_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = encrypt_data(plaintext)

        # Write ciphertext to sensitive file path (text mode)
        with open(sensitive_dest, 'w', encoding='utf-8') as f:
            f.write(ciphertext)

        print(f"[select_protect] Protected {src_path} -> {sensitive_dest} (backup at {backup_dest})")
        return True
    except Exception as e:
        print(f"[select_protect] Error protecting {src_path}: {e}")
        return False


def main(argv):
    if len(argv) < 2:
        print("Usage: python select_protect.py path/to/file1 [path/to/file2 ...]")
        return 1

    files = argv[1:]
    success = 0
    for p in files:
        ok = protect_file(p)
        if ok:
            success += 1

    print(f"[select_protect] Completed: {success}/{len(files)} files protected")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
