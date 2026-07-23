from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from packet_sniffer import PacketSniffer
import pandas as pd
import pickle
import os
import sys
import io
import base64

# Ensure local packages on D drive can be imported
local_pkg_path = os.path.join(os.path.dirname(__file__), 'python_packages')
if local_pkg_path not in sys.path:
    sys.path.insert(0, local_pkg_path)

import firewall_manager
import http_analyzer
import vault_manager
import adtl
import vault_db
from recovery_manager import recovery_mgr
from crypto_utils import decrypt_bytes


import yara
import geoip2.database
from datetime import datetime
from collections import Counter
from report_generator import generate_pdf_report
from flask import send_file
from protected_vault import bp as protected_vault_bp

import socket as _socket

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CUSTOM_MAX_MB = 100
# Max request size (prevent uploads > 100 MB)
app.config['MAX_CONTENT_LENGTH'] = CUSTOM_MAX_MB * 1024 * 1024
app.config['MAX_UPLOAD_BYTES'] = CUSTOM_MAX_MB * 1024 * 1024
CORS(app)  # Allow all origins for HTTP routes (fixes /analyze-http CORS error)
# async_mode='threading' is REQUIRED so socketio.emit() works from background sniffer thread
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=60, ping_interval=25, async_mode='threading')

# Register protected file vault blueprint
app.register_blueprint(protected_vault_bp)

# Auto-detect this machine's own IPs and add to firewall whitelist
try:
    local_ip = _socket.gethostbyname(_socket.gethostname())
    if local_ip not in firewall_manager.WHITELIST:
        firewall_manager.WHITELIST.append(local_ip)
        print(f"🛡️ Auto-whitelisted local IP: {local_ip}")
except Exception:
    pass

sniffer = None
model = None
MODEL_PATH = "model.pkl"

# Live stats counters
live_stats = {
    "total_packets": 0,
    "anomaly_count": 0,
    "blocked_count": 0,
    "safe_level": 100,
    "anomaly_rate": 0.0,
    "session_start": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# Behavioral Analytics (User Phase 8)
behavior_stats = {
    "avg_packet_size": 0,
    "peak_request_rate": 0,
    "active_ports": Counter(),
    "protocol_dist": Counter(),
    "total_bytes": 0
}

session_alerts = []  # To store alerts for the PDF report
recent_packets = []  # To store a sample of raw traffic for the PDF report

# Per-IP frequency tracking (User: High-frequency IP alerts)
ip_request_counts = Counter()
IP_ALERT_THRESHOLDS = [15, 30, 60]  # Warn at these counts
ip_alerted_at = {}  # Tracks last threshold at which each IP was alerted

# Adaptive Data Transformation Layer tracking
attacker_profiles = {}
ADTL_THRESHOLDS = {"MEDIUM": 25.0, "HIGH": 55.0, "CRITICAL": 85.0}

# Load YARA Rules
yara_rules = None
if os.path.exists("rules.yar"):
    try:
        yara_rules = yara.compile("rules.yar")
        print("🛡️ YARA Rules Compiled Successfully")
    except Exception as e:
        print(f"⚠️ YARA Compile Error: {e}")

# Load ML Model
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        print("✅ XGBoost ML Model Loaded Successfully")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
else:
    print("⚠️ Warning: model.pkl not found. Running without ML.")

# Load GeoIP Database
geoip_reader = None
GEOIP_PATH = "data/GeoLite2-Country.mmdb"
if os.path.exists(GEOIP_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_PATH)
        print("🌍 GeoIP Database Loaded")
    except Exception as e:
        print(f"⚠️ GeoIP Load Error: {e}")
else:
    print("🌍 GeoIP database not found. Skipping location details.")

# Load Model Info for Reporting
model_info = {"accuracy": 0.98, "features": ["protocol", "packet_length", "destination_port", "url_length", "request_count"], "model_type": "XGBoost"}
if os.path.exists("data/model_info.pkl"):
    with open("data/model_info.pkl", "rb") as f:
        model_info = pickle.load(f)

def classify_attack(packet_data):
    """Categorize the 'Reason' for detection and assign Severity"""
    features = packet_data.get('ml_features', {})
    reasons = []
    category = "Pattern Anomaly"
    severity = "Medium" # Default
    
    # 3. Rule-based classification (User Point 3)
    if features.get('request_count', 0) > 50:
        reasons.append("High Request Frequency (Bot-like)")
        category = "Bot Activity"
        severity = "Medium"
    if features.get('packet_length', 0) > 1500:
        reasons.append("Oversized Payload (Exfiltration Risk)")
        category = "Data Exfiltration"
        severity = "High"
    if features.get('url_length', 0) > 100:
        reasons.append("Extended URL Path (Sqli/Injection Risk)")
        category = "Web Injection Attempt"
        severity = "High"
    if packet_data.get('yara_hit'):
        reasons.append(f"Signature Match: {packet_data['yara_hit']}")
        category = "Malware/Exploit Signature"
        severity = "High"
        
    return category, ", ".join(reasons) if reasons else "Heuristic Pattern Match", severity


def calculate_threat_score(packet_data):
    score = 0.0
    if packet_data.get('is_anomaly'):
        score += 20.0

    confidence = float(packet_data.get('confidence', 0.0) or 0.0)
    score += min(confidence * 0.4, 30.0)

    if packet_data.get('yara_hit'):
        score += 30.0

    severity = str(packet_data.get('severity', '')).lower()
    if severity == 'high':
        score += 20.0
    elif severity == 'medium':
        score += 10.0

    if packet_data.get('attack_type') == 'Data Exfiltration':
        score += 10.0

    return min(score, 100.0)


def update_attacker_profile(src_ip, packet_data):
    if not src_ip or src_ip == 'Unknown':
        return

    existing = attacker_profiles.get(src_ip, {
        "score": 0.0,
        "level": "LOW",
        "reasons": []
    })

    score = calculate_threat_score(packet_data)
    existing["score"] = max(existing["score"], score)
    existing["level"] = adtl.determine_transformation_level(existing["score"], thresholds=ADTL_THRESHOLDS)

    reason = packet_data.get('reason')
    if reason and reason not in existing["reasons"]:
        existing["reasons"].append(reason)

    attacker_profiles[src_ip] = existing

    if existing["level"] != "LOW":
        if recovery_mgr.set_protected():
            status_info = recovery_mgr.get_status_info()
            socketio.emit('vault_status', {
                "state": status_info["state"],
                "transformation_level": existing["level"],
                "threat_score": existing["score"],
                "protected_requests": status_info["protected_requests"],
                "approvals": status_info["approvals"],
                "timestamp": datetime.now().isoformat()
            })


def get_request_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'Unknown'


def apply_adtl_for_ip(response_payload, ip):
    profile = attacker_profiles.get(ip, {"score": 0.0, "level": "LOW"})
    level = profile.get("level", "LOW")

    if level == "LOW":
        return response_payload

    recovery_mgr.increment_protected_requests()
    status_info = recovery_mgr.get_status_info()

    transformed = response_payload.copy()
    transformed["state"] = status_info["state"]
    transformed["transformation_level"] = level
    transformed["threat_score"] = profile.get("score", 0.0)
    transformed["protection_status"] = "PROTECTED"
    transformed["protected_requests"] = status_info["protected_requests"]

    if "public_records" in response_payload:
        transformed["public_records"] = adtl.transform_payload(response_payload["public_records"], level)
    if "original_records" in response_payload:
        transformed["original_records"] = adtl.transform_payload(response_payload["original_records"], level)

    return transformed



def packet_callback(packet_data):
    global live_stats, recent_packets
    # ML Prediction
    packet_data['action'] = 'ALLOW' # Default action
    live_stats['total_packets'] += 1
    
    recent_packets.append({
        'source': packet_data.get('source', 'Unknown'),
        'destination': packet_data.get('destination', 'Unknown'),
        'size': packet_data.get('size', 0),
        'protocol': packet_data.get('protocol', 'Unknown')
    })
    recent_packets = recent_packets[-5:]
    
    src_ip = packet_data.get('source', 'Unknown')
    
    # --- High-Frequency IP Tracking (User Request) ---
    if src_ip != 'Unknown':
        ip_request_counts[src_ip] += 1
        count = ip_request_counts[src_ip]
        
        # Check against thresholds
        for threshold in reversed(IP_ALERT_THRESHOLDS):
            if count >= threshold:
                # Only alert once per threshold level
                if ip_alerted_at.get(src_ip, 0) < threshold:
                    ip_alerted_at[src_ip] = threshold
                    label = "Slightly Elevated" if threshold == 15 else "Suspiciously High" if threshold == 30 else "Potential DoS / Brute-Force"
                    socketio.emit('high_freq_alert', {
                        'ip': src_ip,
                        'count': count,
                        'label': label
                    })
                    print(f"\n⚠️ [HIGH FREQUENCY ALERT] IP: {src_ip} hit {count} requests ({label})\n")
                break
    
    if model and 'ml_features' in packet_data:
        try:
            # ENSURE features match the retrained model (only 5 features, NO IPs)
            features = {k: v for k, v in packet_data['ml_features'].items() if k in model_info['features']}
            # Create DataFrame for prediction (must match training columns EXACTLY)
            input_df = pd.DataFrame([features], columns=model_info['features'])
            
            # Predict
            pred = model.predict(input_df)[0]
            # Try to get probability if available, else fallback
            try:
                probs = model.predict_proba(input_df)[0]
                confidence = probs[pred] * 100 if len(probs) > pred else 100.0
            except:
                confidence = 100.0

            is_mock_anomaly = packet_data.get('is_anomaly', False)
            packet_data['is_anomaly'] = bool(pred == 1) or is_mock_anomaly
            packet_data['confidence'] = float(round(confidence, 2)) if not is_mock_anomaly else packet_data.get('confidence', 95.0)
            
            if packet_data['is_anomaly']:
                if is_mock_anomaly:
                    category = packet_data.get('attack_type', 'Suspicious Activity')
                    reason = packet_data.get('reason', 'Mock Threat')
                    severity = packet_data.get('severity', 'High')
                else:
                    category, reason, severity = classify_attack(packet_data)
                    packet_data['attack_type'] = category
                    packet_data['reason'] = reason
                    packet_data['severity'] = severity
                
                live_stats['anomaly_count'] += 1
                
                # 6. Countermeasures Logic (Realistic Blocked Count)
                # If high confidence or high severity, simulate/actual block
                if packet_data['confidence'] > 90.0 or severity == "High":
                    fb_success = firewall_manager.block_ip(packet_data['source'])
                    if fb_success:
                        packet_data['action'] = 'BLOCKED'
                        live_stats['blocked_count'] += 1

                # Trigger Secure Vault Active Defense based on Severity
                try:
                    if severity == "High":
                        vault_manager.apply_decoy()
                    elif severity == "Medium":
                        vault_manager.apply_encryption()
                    else:
                        vault_manager.apply_masking()
                except Exception as vault_err:
                    print(f"Vault trigger error: {vault_err}")

                # 9. Link Intelligence Feed to real output
                print(f"🚨 ALERT [{severity}]: {category} from {packet_data['source']} at {packet_data['confidence']}% confidence")

        except Exception as e:
            print(f"Prediction Error: {e}")
            packet_data['is_anomaly'] = False
            packet_data['confidence'] = 0.0

    # YARA Rule Scanning (for live signatures)
    packet_data['yara_hit'] = None
    payload_to_scan = packet_data.get('payload', '')
    if yara_rules and payload_to_scan:
        try:
            matches = yara_rules.match(data=payload_to_scan)
            if matches:
                packet_data['yara_hit'] = matches[0].rule
                packet_data['is_anomaly'] = True # Force anomaly if signature matches
                packet_data['confidence'] = 100.0
                print(f"🛡️ YARA: Detected {packet_data['yara_hit']} from {packet_data['source']}")
        except:
            pass

    update_attacker_profile(src_ip, packet_data)

    # GeoIP Location Enrichment
    packet_data['country'] = "Unknown"
    packet_data['country_code'] = "UN"
    if geoip_reader and packet_data['source']:
        try:
            response = geoip_reader.country(packet_data['source'])
            packet_data['country'] = response.country.name
            packet_data['country_code'] = response.country.iso_code
        except:
            pass

    # Update Behavioral Stats (User Phase 8)
    live_stats['total_packets'] += 1
    size = packet_data.get('size', 0)
    behavior_stats['total_bytes'] += size
    total_pkts = live_stats['total_packets']
    if total_pkts > 0:
        behavior_stats['avg_packet_size'] = behavior_stats['total_bytes'] / total_pkts
    
    port = packet_data.get('destination_port')
    if port: behavior_stats['active_ports'][port] += 1
    
    proto = packet_data.get('protocol')
    if proto: behavior_stats['protocol_dist'][proto] += 1
    
    # Store all alerts for the report (100% sync)
    if packet_data.get('is_anomaly'):
        session_alerts.append(packet_data.copy())

    socketio.emit('new_packet', packet_data)
    socketio.emit('stats_update', live_stats)

@app.route('/')
def index():
    return "Packet Sniffer Backend Running (ML Enabled)"

@app.route('/analyze-http', methods=['POST'])
def analyze_http():
    data = request.json or {}
    csv_path = data.get('csv_path', 'data/http_capture.csv')
    
    def run_async_analysis():
        try:
            alerts = http_analyzer.analyze(csv_path)
            for alert in alerts:
                socketio.emit('http_alert', alert)
                socketio.sleep(0.1)
            socketio.emit('http_analysis_done', {'total_alerts': len(alerts)})
        except Exception as e:
            print(f"Error in http_analyzer: {e}")
            socketio.emit('http_analysis_done', {'total_alerts': 0})
            
    socketio.start_background_task(run_async_analysis)
    return jsonify({"message": "Analysis started"}), 200

@app.route('/vault/status', methods=['GET'])
def get_vault_status():
    try:
        status_info = recovery_mgr.get_status_info()
        state = status_info.get("state", "ACTIVE")
        approvals = status_info.get("approvals", [])
        
        if state in ["PROTECTED", "RECOVERY MODE"]:
            # Disable decryption! Load raw ciphertext directly
            with open(vault_manager.SENSITIVE_FILE, 'r', encoding='utf-8') as f:
                ciphertext = f.read().strip()
            
            # Format warning messages for Prompt 4 and Prompt 7
            msg = (
                "Unauthorized access detected.\n"
                "Original data is protected using AES encryption.\n\n"
                "Access Restricted due to Intrusion Detection.\n\n"
                f"Encrypted Data:\n{ciphertext}"
            )
            response_payload = {
                "state": state,
                "approvals": approvals,
                "protected_requests": status_info.get("protected_requests", 0),
                "public_records": msg,
                "original_records": "Access Restricted due to Intrusion Detection."
            }
            return jsonify(response_payload), 200

        # Normal ACTIVE state: decrypt on the fly
        public_records = vault_manager.read_csv(vault_manager.SENSITIVE_FILE)
        
        if os.path.exists(vault_manager.BACKUP_FILE):
            backup_records = vault_manager.read_csv(vault_manager.BACKUP_FILE)
        else:
            backup_records = vault_manager.DEFAULT_RECORDS
            
        response_payload = {
            "state": state,
            "approvals": approvals,
            "protected_requests": status_info.get("protected_requests", 0),
            "public_records": public_records,
            "original_records": backup_records
        }
        client_ip = get_request_ip()
        response_payload = apply_adtl_for_ip(response_payload, client_ip)
        return jsonify(response_payload), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/vault/upload', methods=['POST'])
def vault_upload():
    try:
        plaintext_content = ""
        
        if request.is_json:
            data = request.json
            input_data = None
            if isinstance(data, dict):
                input_data = data.get("data")
                if not input_data:
                    input_data = data
            else:
                input_data = data
                
            if isinstance(input_data, list):
                import io
                import csv
                f_out = io.StringIO()
                if input_data:
                    keys = input_data[0].keys()
                    writer = csv.DictWriter(f_out, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(input_data)
                    plaintext_content = f_out.getvalue()
            elif isinstance(input_data, dict):
                import io
                import csv
                f_out = io.StringIO()
                keys = input_data.keys()
                writer = csv.DictWriter(f_out, fieldnames=keys)
                writer.writeheader()
                writer.writerow(input_data)
                plaintext_content = f_out.getvalue()
            else:
                plaintext_content = str(input_data)
        elif 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400
            plaintext_content = file.read().decode('utf-8', errors='ignore')
        else:
            plaintext_content = request.data.decode('utf-8', errors='ignore')
            
        if not plaintext_content.strip():
            return jsonify({"error": "No content to encrypt"}), 400
            
        # Encrypt the plaintext first (never store plaintext)
        ciphertext = vault_manager.encrypt_data(plaintext_content)
        
        # Save only the encrypted version
        with open(vault_manager.SENSITIVE_FILE, 'w', encoding='utf-8') as f:
            f.write(ciphertext)
            
        # Update recovery backup file if it's a valid CSV
        try:
            import io
            import csv
            f_in = io.StringIO(plaintext_content)
            parsed = list(csv.DictReader(f_in))
            if parsed and len(parsed) > 0 and all(k in parsed[0] for k in ["student_id", "name"]):
                vault_manager.write_csv(vault_manager.BACKUP_FILE, parsed)
        except Exception:
            pass
            
        recovery_mgr.log_event("User uploaded confidential data. Encrypted and stored to secure vault disk.")
        
        return jsonify({
            "message": "Data encrypted and saved successfully",
            "status": "success"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/vault/logs', methods=['GET'])
def get_vault_logs():
    try:
        logs = recovery_mgr.get_logs()
        return jsonify({"logs": logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/vault/simulate', methods=['POST'])
def simulate_vault_threat():
    try:
        data = request.json or {}
        threat_level = data.get("threat_level", "NONE").upper()
        
        score = 0.0
        if threat_level == "NONE":
            attacker_profiles.clear()
            recovery_mgr.state = "ACTIVE"
            recovery_mgr.approvals = []
            recovery_mgr.save_status()
            recovery_mgr.log_event("Simulation Reset: System restored to ACTIVE state.")
            vault_manager.restore_data()
        else:
            recovery_mgr.state = "PROTECTED"
            recovery_mgr.save_status()
            recovery_mgr.log_event(f"Simulation Triggered: Vault set to PROTECTED mode with threat level {threat_level}.")
            
            client_ip = get_request_ip()
            score = 10.0 if threat_level == "LOW" else 60.0 if threat_level == "MEDIUM" else 90.0
            attacker_profiles[client_ip] = {
                "score": score,
                "level": threat_level,
                "reasons": [f"Simulated {threat_level} Threat"]
            }
        
        status_info = recovery_mgr.get_status_info()
        socketio.emit('vault_status', {
            "state": status_info["state"],
            "transformation_level": threat_level,
            "threat_score": score,
            "protected_requests": status_info["protected_requests"],
            "approvals": status_info["approvals"],
            "timestamp": datetime.now().isoformat()
        })
            
        return jsonify({"message": f"Simulated {threat_level} threat level applied"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/vault/approve', methods=['POST'])
def approve_vault_recovery():
    try:
        data = request.json or {}
        admin_id = data.get("admin_id", "").strip()
        if not admin_id:
            return jsonify({"error": "Admin ID is required"}), 400
            
        recovered, approvals = recovery_mgr.add_approval(admin_id)
        
        if recovered:
            attacker_profiles.clear()
            vault_manager.restore_data()
            
        status_info = recovery_mgr.get_status_info()
        socketio.emit('vault_status', {
            "state": status_info["state"],
            "transformation_level": "LOW" if recovered else "HIGH",
            "threat_score": 0.0,
            "protected_requests": status_info["protected_requests"],
            "approvals": approvals,
            "recovered": recovered,
            "timestamp": datetime.now().isoformat()
        })
        
        return jsonify({
            "message": f"Approval registered for {admin_id}",
            "approvals": approvals,
            "recovered": recovered
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/vault/recover', methods=['POST'])
def vault_recover():
    try:
        data = request.json or {}
        admin_id = data.get("admin_id", "").strip()
        recovery_mode = data.get("recovery_mode", "").strip().upper()
        
        if not admin_id:
            return jsonify({"error": "Admin ID is required"}), 400
        if recovery_mode not in ["ACTIVE", "PROTECTED", "RECOVERY MODE"]:
            return jsonify({"error": "Invalid recovery_mode"}), 400
        
        if recovery_mode == "RECOVERY MODE":
            recovery_mgr.initiate_recovery(admin_id)
        elif recovery_mode == "ACTIVE":
            recovery_mgr.state = "ACTIVE"
            recovery_mgr.approvals = []
            recovery_mgr.save_status()
            attacker_profiles.clear()
            recovery_mgr.log_event(f"System reset to ACTIVE state directly by admin {admin_id}")
            vault_manager.restore_data()
        
        status_info = recovery_mgr.get_status_info()
        socketio.emit('vault_status', {
            "state": status_info["state"],
            "recovery_mode": recovery_mode,
            "transformation_level": "LOW" if recovery_mode == "ACTIVE" else "HIGH",
            "threat_score": 0.0,
            "protected_requests": status_info["protected_requests"],
            "approvals": status_info["approvals"],
            "admin_id": admin_id,
            "timestamp": datetime.now().isoformat()
        })
        
        return jsonify({
            "message": f"Recovery mode set to {recovery_mode} by {admin_id}",
            "recovery_mode": recovery_mode,
            "state": status_info["state"]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/simulate-unauthorized-access', methods=['POST'])
def simulate_unauthorized_access():
    """Safe demo route: simulate unauthorized access and return encrypted file only."""
    data = request.get_json(silent=True) or {}
    attacker_username = (data.get('attacker_username') or '').strip()
    target_username = (data.get('target_username') or '').strip()
    target_filename = (data.get('target_filename') or 'file.bin').strip()

    if not attacker_username or not target_username:
        return jsonify({'error': 'attacker_username and target_username are required'}), 400

    # Demo-only logic: treat any request from a different user as unauthorized.
    unauthorized = attacker_username != target_username
    if unauthorized:
        encrypted_payload = vault_manager.encrypt_data(
            f"Protected file {target_filename} for {target_username}"
        )
        alert = {
            'type': 'Unauthorized File Access',
            'source_ip': request.remote_addr or 'Unknown',
            'attacker': attacker_username,
            'target': target_username,
            'filename': target_filename,
            'timestamp': datetime.now().isoformat(),
        }
        session_alerts.append(alert)
        live_stats['anomaly_count'] += 1
        live_stats['blocked_count'] += 1

        # Emit a real-time alert to connected clients
        socketio.emit('http_alert', alert)
        socketio.emit('stats_update', live_stats)
        recovery_mgr.log_event(
            f"Unauthorized access simulation blocked: attacker={attacker_username} target={target_username} file={target_filename}"
        )

        # Return encrypted content as a downloadable file
        encrypted_filename = f'{target_filename}.enc'
        return send_file(
            io.BytesIO(encrypted_payload.encode('utf-8')),
            as_attachment=True,
            download_name=encrypted_filename,
            mimetype='application/octet-stream'
        )

    return jsonify({
        'status': 'allowed',
        'message': 'Authorized access simulation',
    }), 200

@app.route('/vault/files/download-authorized/<file_id>', methods=['GET'])
def download_authorized_file(file_id):
    """Demo-only authorized access route: decrypt and return the original file bytes."""
    rec = vault_db.get_file_record(file_id)
    if not rec:
        return jsonify({'error': 'file not found'}), 404

    stored_path = os.path.join(protected_vault_bp.root_path, 'data', 'protected_files', rec['encrypted_filename'])
    if not os.path.exists(stored_path):
        return jsonify({'error': 'encrypted file missing'}), 500

    with open(stored_path, 'rb') as f:
        enc_blob = f.read()

    plaintext = decrypt_bytes(rec['nonce'], base64.b64encode(enc_blob).decode('utf-8'))
    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=rec['original_filename'],
        mimetype='application/octet-stream'
    )

@app.route('/download-report')
def download_report():
    """Generate and serve the refined professional PDF security report"""
    try:
        # Pass behavior_stats for Point 8 (Academic Reporting)
        report_path = generate_pdf_report(
            session_alerts, 
            live_stats, 
            model_info, 
            behavior_stats=behavior_stats,
            recent_packets=recent_packets
        )
        return send_file(report_path, as_attachment=True)
    except Exception as e:
        print(f"Report Error: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def test_connect():
    print('Client connected')
    emit('status', {'msg': 'Connected to Backend'})

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

@socketio.on('start_capture')
def start_capture():
    global sniffer
    if sniffer is None:
        sniffer = PacketSniffer(packet_callback)
    sniffer.start()
    emit('status', {'msg': 'Capture Started'})

@socketio.on('stop_capture')
def stop_capture():
    global sniffer
    if sniffer:
        sniffer.stop()
    emit('status', {'msg': 'Capture Stopped'})

@socketio.on('request_vault_status')
def request_vault_status():
    try:
        status_info = recovery_mgr.get_status_info()
        client_ip = request.remote_addr or 'Unknown'
        profile = attacker_profiles.get(client_ip, {"score": 0.0, "level": "LOW"})
        
        emit('vault_status', {
            "state": status_info["state"],
            "transformation_level": profile.get("level", "LOW"),
            "threat_score": profile.get("score", 0.0),
            "protected_requests": status_info["protected_requests"],
            "approvals": status_info["approvals"],
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        emit('vault_status_error', {"error": str(e)})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
