from flask import Flask
from flask_socketio import SocketIO, emit
from packet_sniffer import PacketSniffer
import pandas as pd
import pickle
import os
import firewall_manager  # Import the active defense module

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

sniffer = None
model = None
MODEL_PATH = "model.pkl"

# Load ML Model
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        print("✅ ML Model Loaded Successfully")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
else:
    print("⚠️ Warning: model.pkl not found. Running without ML.")

def packet_callback(packet_data):
    # ML Prediction
    packet_data['action'] = 'ALLOW' # Default action
    
    if model and 'ml_features' in packet_data:
        try:
            features = packet_data['ml_features']
            # Create DataFrame for prediction (must match training columns)
            input_df = pd.DataFrame([features])
            
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
                print(f"🚨 ANOMALY: {packet_data['source']} -> {packet_data['destination']} (Conf: {confidence}%)")
                
                # ACTIVE DEFENSE LOGIC
                if confidence > 99.0:
                    # BLOCK THE ATTACKER (Source IP)
                    success = firewall_manager.block_ip(packet_data['source'])
                    if success:
                        packet_data['action'] = 'BLOCKED'
                        print(f"⛔ IPS: Automatically BLOCKED traffic from {packet_data['source']}")

        except Exception as e:
            print(f"Prediction Error: {e}")
            packet_data['is_anomaly'] = False
            packet_data['confidence'] = 0.0

    socketio.emit('new_packet', packet_data)

@app.route('/')
def index():
    return "Packet Sniffer Backend Running (ML Enabled)"

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
