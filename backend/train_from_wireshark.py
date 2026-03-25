"""
Wireshark-Based Model Trainer — 7 Feature Version
===================================================
Features:
  1. protocol        — TCP / UDP / ICMP / HTTP / etc.
  2. packet_length   — size of packet in bytes
  3. destination_port— port the traffic is going to (80, 443, 53…)
  4. url_length      — length of the HTTP URL extracted from Info column
  5. request_count   — how many packets from same source IP (volume)
  6. source_ip       — encoded source IP address
  7. destination_ip  — encoded destination IP address

HOW TO PREPARE CSV FILES FROM WIRESHARK:
  1. Normal traffic  → browse normally for 5 min → export as data/normal_traffic.csv
  2. Attack traffic  → run attack_sim.py while capturing → export as data/attack_traffic.csv
  3. Run: python train_from_wireshark.py
"""

import pandas as pd
import numpy as np
import pickle
import os
import re
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ── Paths ──────────────────────────────────────────────────────────────────────
NORMAL_CSV = "data/normal_traffic.csv"
ATTACK_CSV = "data/attack_traffic.csv"
MODEL_PATH = "model.pkl"
FEATURES   = ["protocol", "packet_length", "destination_port",
               "url_length", "request_count", "source_ip", "destination_ip"]

# ── Encoders ───────────────────────────────────────────────────────────────────
PROTOCOL_MAP = {
    "TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3,
    "TLS": 0, "DNS": 1, "ARP": 4, "HTTPS": 0,
}

def encode_protocol(val):
    val = str(val).upper().strip()
    for k, v in PROTOCOL_MAP.items():
        if k in val:
            return v
    return 5  # OTHER

def encode_ip(ip_str):
    """Hash IP string to a consistent integer."""
    return hash(str(ip_str).strip()) % 100000

def extract_port(info_str):
    """Try to extract destination port from Info or Source/Dest columns."""
    if pd.isna(info_str):
        return 0
    info_str = str(info_str)
    # Format like: "192.168.1.1:54321 → 10.0.0.1:80"
    match = re.search(r'→\s*[\d.]+:(\d+)', info_str)
    if match:
        return int(match.group(1))
    # Or just ":80" or "port 80"
    match = re.search(r'[:\s](\d{1,5})', info_str)
    if match:
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return 0

def extract_url_length(info_str):
    """Extract URL length from HTTP GET/POST lines in the Info column."""
    if pd.isna(info_str):
        return 0
    info_str = str(info_str)
    # Match GET /path or POST /path
    match = re.search(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)', info_str, re.IGNORECASE)
    if match:
        return len(match.group(1))
    return 0

def map_columns(df):
    """Map standard Wireshark CSV column names."""
    col_map = {}
    for c in df.columns:
        lc = c.lower().strip()
        if "source" in lc or lc == "src":       col_map["source"] = c
        if "dest" in lc or lc == "dst":         col_map["dest"]   = c
        if "proto" in lc:                        col_map["proto"]  = c
        if "length" in lc or lc == "len":        col_map["length"] = c
        if "info" in lc:                         col_map["info"]   = c
    return col_map

def build_features(df, label):
    """Extract all 7 features from a Wireshark CSV DataFrame."""
    col_map = map_columns(df)
    print(f"   Columns found: {col_map}")

    out = pd.DataFrame()

    # 1. Protocol
    out["protocol"] = df[col_map["proto"]].apply(encode_protocol) if "proto" in col_map else 0

    # 2. Packet Length
    out["packet_length"] = pd.to_numeric(df[col_map["length"]], errors="coerce").fillna(0) if "length" in col_map else 0

    # 3. Destination Port (from Info column)
    out["destination_port"] = df[col_map["info"]].apply(extract_port) if "info" in col_map else 0

    # 4. URL Length  (from Info column)
    out["url_length"] = df[col_map["info"]].apply(extract_url_length) if "info" in col_map else 0

    # 5. Request Count per Source IP
    if "source" in col_map:
        count_map = df[col_map["source"]].value_counts().to_dict()
        out["request_count"] = df[col_map["source"]].map(count_map).fillna(1)
    else:
        out["request_count"] = 1

    # 6. Source IP encoded
    out["source_ip"] = df[col_map["source"]].apply(encode_ip) if "source" in col_map else 0

    # 7. Destination IP encoded
    out["destination_ip"] = df[col_map["dest"]].apply(encode_ip) if "dest" in col_map else 0

    out["label"] = label
    print(f"   ✅ {len(out)} packets processed (label={label})")
    return out

def train():
    print("\n" + "="*55)
    print("  WIRESHARK MODEL TRAINER — 7 FEATURES")
    print("="*55 + "\n")

    for path in [NORMAL_CSV, ATTACK_CSV]:
        if not os.path.exists(path):
            print(f"❌ Missing: {path}")
            print("   Capture traffic in Wireshark → Export Packet Dissections → As CSV")
            return

    print(f"📂 Loading Normal: {NORMAL_CSV}")
    normal_df = pd.read_csv(NORMAL_CSV)
    normal_df.columns = [c.strip().lower() for c in normal_df.columns]
    normal = build_features(normal_df, label=0)

    print(f"📂 Loading Attack: {ATTACK_CSV}")
    attack_df = pd.read_csv(ATTACK_CSV)
    attack_df.columns = [c.strip().lower() for c in attack_df.columns]
    attack = build_features(attack_df, label=1)

    # Combine
    df = pd.concat([normal, attack], ignore_index=True).sample(frac=1, random_state=42)
    X  = df[FEATURES]
    y  = df["label"]

    print(f"\n📊 Total: {len(df)} packets | Normal: {len(normal)} | Attack: {len(attack)}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"🤖 Training Random Forest on {len(X_train)} samples...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\n✅ Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"💾 Model saved → {MODEL_PATH}")
    print("🔄 Restart python app.py to use the new model.\n")

if __name__ == "__main__":
    train()
