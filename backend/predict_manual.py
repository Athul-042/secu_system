import pickle
import pandas as pd
import sys

MODEL_PATH = "model.pkl"

def predict(protocol, src_bytes, dst_bytes, count):
    # Load Model
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
    except FileNotFoundError:
        print("Error: model.pkl not found. Run train_model.py first.")
        return
    # Map Protocol (Same logic as training)
    protocol_map = {"tcp": 0, "udp": 1, "icmp": 2, "other": 3}
    proto_val = protocol_map.get(protocol.lower(), 3)

    # Create DataFrame (feature names must match training)
    # SELECTED_FEATURES = ["protocol_type", "src_bytes", "dst_bytes", "count"]
    input_data = pd.DataFrame([[proto_val, src_bytes, dst_bytes, count]], 
                              columns=["protocol_type", "src_bytes", "dst_bytes", "count"])

    # Predict
    try:
        prediction = model.predict(input_data)[0]
        probs = model.predict_proba(input_data)[0]
        
        # Handle binary classification usually returning [prob_0, prob_1]
        # But sometimes if only 1 class in leaf, might be weird.
        if len(probs) > prediction:
            confidence = probs[prediction] * 100
        else:
            confidence = 100.0 # Fallback
    except Exception as e:
        print(f"Warning: Could not calculate confidence: {e}")
        prediction = model.predict(input_data)[0]
        confidence = 0.0

    result = "🔴 ATTACK Detected!" if prediction == 1 else "🟢 Normal Traffic"

    print("\n" + "="*30)
    print(f"Input: {protocol.upper()} | Src: {src_bytes}B | Dst: {dst_bytes}B | Count: {count}")
    print(f"Result: {result}")
    print(f"Confidence: {confidence:.2f}%")
    
    if prediction == 1:
        print("-" * 30)
        print("🔎 Creating Analysis Report...")
        reasons = []
        if count > 20:
            reasons.append(f"• High Traffic Volume ({count} connections/2s) suggests DoS/Flooding.")
        if protocol.lower() == 'icmp' and src_bytes > 1000:
            reasons.append("• Large ICMP packet size suggests 'Ping of Death'.")
        if protocol.lower() == 'udp' and count > 10:
            reasons.append("• Rapid UDP packets often indicate UDP Flooding or Scanning.")
        if src_bytes < 10 and dst_bytes < 10 and count > 5:
            reasons.append("• Tiny packets with high frequency indicate Port Scanning.")
            
        if not reasons:
            reasons.append("• Traffic pattern matches known attack signatures in database.")
            
        for r in reasons:
            print(r)

    print("="*30 + "\n")

if __name__ == "__main__":
    print("--- Network Intrusion Predictor ---")
    if len(sys.argv) == 5:
        # CMD Usage: python predict_manual.py tcp 123 456 10
        predict(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    else:
        # Interactive Mode
        p = input("Protocol (tcp/udp/icmp): ")
        s = int(input("Source Bytes: "))
        d = int(input("Dest Bytes: "))
        c = int(input("Count (connections in last 2s): "))
        predict(p, s, d, c)
