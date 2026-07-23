import os
import io
import secrets
import base64
from flask import Blueprint, request, jsonify, current_app, send_file
from werkzeug.utils import secure_filename
from datetime import datetime
from crypto_utils import encrypt_bytes, decrypt_bytes
import vault_db

bp = Blueprint('protected_vault', __name__)

# Storage folder
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
FILES_DIR = os.path.join(DATA_DIR, 'protected_files')
os.makedirs(FILES_DIR, exist_ok=True)

# Allowed extensions
ALLOWED_EXT = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_filename(filename: str) -> bool:
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXT


def require_auth(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing auth token'}), 401
        token = auth.split(' ', 1)[1].strip()
        user = vault_db.get_user_by_token(token)
        if not user:
            return jsonify({'error': 'Invalid or expired token'}), 401
        request.user = user
        return func(*args, **kwargs)

    return wrapper


@bp.route('/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    try:
        user = vault_db.create_user(username, password)
        return jsonify({'message': 'user created', 'user': {'id': user['id'], 'username': user['username']}}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    user = vault_db.authenticate_user(username, password)
    if not user:
        return jsonify({'error': 'invalid credentials'}), 401
    token = secrets.token_urlsafe(32)
    vault_db.set_user_token(user['id'], token)
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username']}}), 200


@bp.route('/vault/files/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'file field required'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    if not allowed_filename(filename):
        return jsonify({'error': 'file type not allowed'}), 400

    # Enforce size limit (Flask will drop large requests via MAX_CONTENT_LENGTH)
    file_bytes = file.read()
    max_bytes = current_app.config.get('MAX_UPLOAD_BYTES') or 100 * 1024 * 1024
    if len(file_bytes) > max_bytes:
        return jsonify({'error': f'File exceeds maximum size of {max_bytes} bytes'}), 413

    enc = encrypt_bytes(file_bytes)
    # Encrypted payload (ciphertext is base64) -> store as raw bytes on disk
    encrypted_blob = base64.b64decode(enc['ciphertext'])
    # Use a random filename for storage
    stored_name = secrets.token_hex(32) + '.enc'
    stored_path = os.path.join(FILES_DIR, stored_name)
    with open(stored_path, 'wb') as f:
        f.write(encrypted_blob)

    # Save metadata (unauthenticated uploads are stored anonymously)
    record = vault_db.create_file_record(None, filename, stored_name, enc['nonce'], len(file_bytes))

    return jsonify({'message': 'uploaded', 'file_id': record['id']}), 201


@bp.route('/vault/files/list', methods=['GET'])
def list_files():
    files = vault_db.list_files_by_user()
    return jsonify({'files': files}), 200


@bp.route('/vault/files/download/<file_id>', methods=['GET'])
def download_file(file_id):
    rec = vault_db.get_file_record(file_id)
    if not rec:
        return jsonify({'error': 'file not found'}), 404

    stored_path = os.path.join(FILES_DIR, rec['encrypted_filename'])
    if not os.path.exists(stored_path):
        return jsonify({'error': 'encrypted file missing'}), 500

    with open(stored_path, 'rb') as f:
        enc_blob = f.read()

    attachment_name = f"{rec['original_filename']}.enc"
    return send_file(
        io.BytesIO(enc_blob),
        as_attachment=True,
        download_name=attachment_name,
        mimetype='application/octet-stream'
    )
