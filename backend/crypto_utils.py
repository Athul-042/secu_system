import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
MASTER_KEY_FILE = os.path.join(DATA_DIR, 'vault_master.key')


def generate_master_key():
    key = AESGCM.generate_key(bit_length=256)
    with open(MASTER_KEY_FILE, 'wb') as f:
        f.write(key)
    return key


def load_master_key():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, 'rb') as f:
            return f.read()
    return generate_master_key()


_MASTER_KEY = load_master_key()
_AESGCM = AESGCM(_MASTER_KEY)


def encrypt_bytes(plaintext: bytes) -> dict:
    """Encrypt bytes using AES-256-GCM.

    Returns a dict with base64-encoded nonce and ciphertext.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    nonce = os.urandom(12)
    ct = _AESGCM.encrypt(nonce, plaintext, None)
    return {
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ct).decode('utf-8')
    }


def decrypt_bytes(nonce_b64: str, ciphertext_b64: str) -> bytes:
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    pt = _AESGCM.decrypt(nonce, ct, None)
    return pt
