from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from packet_sniffer import PacketSniffer
import pandas as pd
import pickle
import os
import firewall_manager

import yara
import geoip2.database
from datetime import datetime
from collections import Counter
from report_generator import generate_pdf_report
from flask import send_file

import socket as _socket

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CORS(app)  # Allow all origins for HTTP routes (fixes /analyze-http CORS error)
# async_mode='threading' is REQUIRED so socketio.emit() works from background sniffer thread
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=60, ping_interval=25, async_mode='threading')

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

session_alerts = [] # To store alerts for the PDF report

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

def packet_callback(packet_data):
    global live_stats
    # ML Prediction
    packet_data['action'] = 'ALLOW' # Default action
    live_stats['total_packets'] += 1
    
    if model and 'ml_features' in packet_data:
        try:
            # ENSURE features match the retrained model (only 5 features, NO IPs)
            features = {k: v for k, v in features.items() if k in model_info['features']}
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

            packet_data['is_anomaly'] = bool(pred == 1) # 1 = Attack
            packet_data['confidence'] = round(confidence, 2)
            
            if pred == 1:
                # 3, 5, 8. Enhanced Classification, Reason, and Severity
                category, reason, severity = classify_attack(packet_data)
                packet_data['attack_type'] = category
                packet_data['reason'] = reason
                packet_data['severity'] = severity
                packet_data['is_anomaly'] = True
                
                live_stats['anomaly_count'] += 1
                
                # 6. Countermeasures Logic (Realistic Blocked Count)
                # If high confidence or high severity, simulate/actual block
                if confidence > 90.0 or severity == "High":
                    fb_success = firewall_manager.block_ip(packet_data['source'])
                    if fb_success:
                        packet_data['action'] = 'BLOCKED'
                        live_stats['blocked_count'] += 1

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

@app.route('/download-report')
def download_report():
    """Generate and serve the refined professional PDF security report"""
    try:
        # Pass behavior_stats for Point 8 (Academic Reporting)
        report_path = generate_pdf_report(
            session_alerts, 
            live_stats, 
            model_info, 
            behavior_stats=behavior_stats
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

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
