import os
import sqlite3
from datetime import datetime
import threading
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'vault_metadata.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

_lock = threading.Lock()


def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


ANON_USERNAME = '__public_anonymous__'


def init_db():
    with _lock:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT
        )
        ''')

        cur.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            nonce TEXT NOT NULL,
            upload_time TEXT NOT NULL,
            size INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        conn.commit()

        # Ensure a public anonymous uploader exists for unauthenticated uploads
        cur.execute('SELECT id FROM users WHERE username = ?', (ANON_USERNAME,))
        anon = cur.fetchone()
        if not anon:
            anon_id = uuid.uuid4().hex
            anon_pw = generate_password_hash('anonymous')
            conn.execute('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)', (anon_id, ANON_USERNAME, anon_pw))
            conn.commit()
        conn.close()


def create_user(username: str, password: str) -> dict:
    uid = uuid.uuid4().hex
    password_hash = generate_password_hash(password)
    with _lock:
        conn = _get_conn()
        try:
            conn.execute('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)', (uid, username, password_hash))
            conn.commit()
        finally:
            conn.close()
    return {'id': uid, 'username': username}


def authenticate_user(username: str, password: str) -> dict:
    with _lock:
        conn = _get_conn()
        cur = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return None
    if not check_password_hash(row['password_hash'], password):
        return None
    return {'id': row['id'], 'username': row['username']}


def set_user_token(user_id: str, token: str):
    with _lock:
        conn = _get_conn()
        conn.execute('UPDATE users SET token = ? WHERE id = ?', (token, user_id))
        conn.commit()
        conn.close()


def get_user_by_token(token: str) -> dict:
    with _lock:
        conn = _get_conn()
        cur = conn.execute('SELECT * FROM users WHERE token = ?', (token,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return None
    return {'id': row['id'], 'username': row['username']}


def get_anonymous_user_id() -> str:
    with _lock:
        conn = _get_conn()
        cur = conn.execute('SELECT id FROM users WHERE username = ?', (ANON_USERNAME,))
        row = cur.fetchone()
        conn.close()
    return row['id'] if row else None


def create_file_record(user_id: str, original_filename: str, encrypted_filename: str, nonce: str, size: int) -> dict:
    if not user_id:
        user_id = get_anonymous_user_id()
    fid = uuid.uuid4().hex
    upload_time = datetime.utcnow().isoformat()
    with _lock:
        conn = _get_conn()
        conn.execute('INSERT INTO files (id, user_id, original_filename, encrypted_filename, nonce, upload_time, size) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (fid, user_id, original_filename, encrypted_filename, nonce, upload_time, size))
        conn.commit()
        conn.close()
    return {'id': fid, 'user_id': user_id, 'original_filename': original_filename, 'encrypted_filename': encrypted_filename, 'nonce': nonce, 'upload_time': upload_time, 'size': size}


def get_file_record(file_id: str) -> dict:
    with _lock:
        conn = _get_conn()
        cur = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return None
    return dict(row)


def list_files_by_user(user_id: str = None) -> list:
    with _lock:
        conn = _get_conn()
        if user_id:
            cur = conn.execute('SELECT id, original_filename, upload_time, size FROM files WHERE user_id = ? ORDER BY upload_time DESC', (user_id,))
        else:
            cur = conn.execute('SELECT id, original_filename, upload_time, size FROM files ORDER BY upload_time DESC')
        rows = cur.fetchall()
        conn.close()
    return [dict(r) for r in rows]


# Initialize on import
init_db()
