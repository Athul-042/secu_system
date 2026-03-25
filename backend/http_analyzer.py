"""
Traffic Analyzer — Suspicious Behavior Detector
=================================================
Analyzes ANY Wireshark CSV export (HTTP, HTTPS, or all traffic).
Detects external IPs sending suspicious data to your machine.

Usage:
  python http_analyzer.py  data/your_capture.csv
"""

import sys
import os
import re
import pickle
import json
import ipaddress
import pandas as pd
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
MODEL_PATH     = "model.pkl"
DEFAULT_CSV    = "data/http_capture.csv"
RESULTS_JSON   = "data/http_analysis_results.json"  # saved for dashboard
SAFE_PREFIXES  = ("127.", "0.0.0.", "169.254.")

FEATURES = ["protocol", "packet_length", "destination_port",
            "url_length", "request_count", "source_ip", "destination_ip"]

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "TLS": 0,
                "DNS": 1, "ARP": 4, "HTTPS": 0}

# Thresholds for rule-based detection
LARGE_BYTES_THRESHOLD  = 3000   # single packet > 3KB = suspicious
HIGH_REQUEST_THRESHOLD = 80     # > 80 requests from same IP = suspicious
SUSPICIOUS_PORTS       = {4444, 6667, 1337, 31337, 12345, 9999}  # common malware ports
WEB_PORTS              = {80, 443, 8080, 8443}  # normal web ports


# ── Helper functions ───────────────────────────────────────────────────────────
def encode_protocol(val):
    val = str(val).upper().strip()
    for k, v in PROTOCOL_MAP.items():
        if k in val: return v
    return 5

def extract_with_tshark(pcap_path, output_csv):
    """Use TShark to extract CSV fields from PCAP"""
    if not os.path.exists(TSHARK_PATH):
        print("⚠️ TShark not found at specified path.")
        return False
    
    cmd = [
        TSHARK_PATH, "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.number", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.method", "-e", "http.request.uri", "-e", "frame.len",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]
    
    try:
        with open(output_csv, "w") as f:
            subprocess.run(cmd, stdout=f, check=True)
        return True
    except Exception as e:
        print(f"❌ TShark error: {e}")
        return False

def encode_ip(ip_str):
    return hash(str(ip_str).strip()) % 100000

def extract_port(info_str):
    if pd.isna(info_str): return 0
    s = str(info_str)
    m = re.search(r'[→>]\s*[\d.]+:(\d+)', s)
    if m: return int(m.group(1))
    m = re.search(r':(\d{1,5})\b', s)
    if m:
        p = int(m.group(1))
        if 1 <= p <= 65535: return p
    return 0

def extract_url_length(info_str):
    if pd.isna(info_str): return 0
    m = re.search(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)', str(info_str), re.IGNORECASE)
    return len(m.group(1)) if m else 0

def is_local(ip):
    """Return True only for multicast/loopback — let private IPs through for analysis."""
    s = str(ip)
    for prefix in SAFE_PREFIXES:
        if s.startswith(prefix): return True
    # Skip multicast and broadcast
    if s.startswith("224.") or s.startswith("239.") or s == "255.255.255.255":
        return True
    return False

def map_columns(df):
    col_map = {}
    for c in df.columns:
        lc = c.lower().strip()
        if "source" in lc or lc == "src":    col_map["source"] = c
        if "dest" in lc or lc == "dst":      col_map["dest"]   = c
        if "proto" in lc:                    col_map["proto"]  = c
        if "length" in lc or lc == "len":    col_map["length"] = c
        if "info" in lc:                     col_map["info"]   = c
    return col_map


# ── Feature extraction ─────────────────────────────────────────────────────────
def extract_features(df):
    cm = map_columns(df)

    feat                    = pd.DataFrame()
    feat["protocol"]        = df[cm["proto"]].apply(encode_protocol)   if "proto"  in cm else 0
    feat["packet_length"]   = pd.to_numeric(df[cm["length"]], errors="coerce").fillna(0) if "length" in cm else 0
    feat["destination_port"]= df[cm["info"]].apply(extract_port)       if "info"   in cm else 0
    feat["url_length"]      = df[cm["info"]].apply(extract_url_length)  if "info"   in cm else 0
    feat["source_ip"]       = df[cm["source"]].apply(encode_ip)        if "source" in cm else 0
    feat["destination_ip"]  = df[cm["dest"]].apply(encode_ip)          if "dest"   in cm else 0

    # request_count = total packets per source IP
    if "source" in cm:
        counts = df[cm["source"]].value_counts().to_dict()
        feat["request_count"] = df[cm["source"]].map(counts).fillna(1)
    else:
        feat["request_count"] = 1

    # Store raw values for reporting
    feat["_src"]  = df[cm["source"]].values if "source" in cm else "unknown"
    feat["_dst"]  = df[cm["dest"]].values   if "dest"   in cm else "unknown"
    feat["_bytes"]= feat["packet_length"]
    feat["_port"] = feat["destination_port"]
    feat["_url_len"] = feat["url_length"]

    return feat, cm


# ── Main analysis ──────────────────────────────────────────────────────────────
def analyze(csv_path, model=None):
    print("\n" + "═"*62)
    print("   HTTP TRAFFIC ANALYZER — Suspicious Behavior Detector")
    print("═"*62 + "\n")

    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        print(f"✅ ML Model loaded from {MODEL_PATH}")
    else:
        print("⚠️  model.pkl not found — using rule-based detection only.")

    # Load CSV
    if not os.path.exists(csv_path):
        print(f"❌ File not found: {csv_path}")
        return []

    df = pd.read_csv(csv_path)
    df.columns = [c.strip().lower() for c in df.columns]
    print(f"📂 Loaded {len(df)} packets from: {csv_path}\n")

    feat_df, cm = extract_features(df)

    alerts = []
    seen_ips = {}

    # Group by source IP for per-source analysis
    src_col = cm.get("source", None)
    if src_col is None:
        print("❌ No Source column found in CSV.")
        return []

    grouped = df.groupby(df[src_col])

    for src_ip, group in grouped:
        # Skip fully local traffic
        if is_local(src_ip):
            continue

        rows_idx = group.index
        sub_feat = feat_df.loc[rows_idx, FEATURES]

        total_bytes   = feat_df.loc[rows_idx, "_bytes"].sum()
        max_bytes     = feat_df.loc[rows_idx, "_bytes"].max()
        packet_count  = len(rows_idx)
        ports_used    = feat_df.loc[rows_idx, "_port"].unique().tolist()
        avg_url_len   = feat_df.loc[rows_idx, "_url_len"].mean()
        dst_ips       = feat_df.loc[rows_idx, "_dst"].unique().tolist()

        # ── Rule-based checks ──────────────────────────────────────────────────
        rule_flags = []
        if max_bytes > LARGE_BYTES_THRESHOLD:
            rule_flags.append(f"Large payload ({int(max_bytes):,} bytes in single packet)")
        if packet_count > HIGH_REQUEST_THRESHOLD:
            rule_flags.append(f"High request volume ({packet_count} packets)")
        suspicious_p = [p for p in ports_used if int(p) in SUSPICIOUS_PORTS]
        if suspicious_p:
            rule_flags.append(f"Suspicious ports: {suspicious_p}")
        if avg_url_len > 200:
            rule_flags.append(f"Very long URLs (avg {avg_url_len:.0f} chars — possible injection)")

        # ── ML model prediction ────────────────────────────────────────────────
        ml_result, ml_confidence = "N/A", 0.0
        ml_is_attack = False
        if model:
            try:
                pred   = model.predict(sub_feat)
                attack_ratio = pred.mean()  # fraction of packets predicted as attack
                ml_is_attack = attack_ratio >= 0.5
                if hasattr(model, "predict_proba"):
                    proba = model.predict_proba(sub_feat)
                    ml_confidence = round(float(proba[:, 1].mean()) * 100, 1)
                ml_result = f"{'Attack' if ml_is_attack else 'Normal'} ({ml_confidence}%)"
            except Exception as e:
                ml_result = f"Error: {e}"

        is_suspicious = bool(rule_flags) or ml_is_attack

        verdict = "🚨 SUSPICIOUS" if is_suspicious else "✅ Normal"
        print(f"  {verdict}  {src_ip:<20}  Packets:{packet_count:>5}  "
              f"Total:{int(total_bytes):>10,}B  ML:{ml_result}")
        if rule_flags:
            for f in rule_flags:
                print(f"   ↳ ⚠️  {f}")

        if is_suspicious:
            alert = {
                "timestamp":   datetime.now().isoformat(),
                "source_ip":   str(src_ip),
                "destinations":dst_ips[:5],
                "packet_count":packet_count,
                "total_bytes": int(total_bytes),
                "ports":       [int(p) for p in ports_used if p > 0][:10],
                "avg_url_len": round(float(avg_url_len), 1),
                "rule_flags":  rule_flags,
                "ml_result":   ml_result,
                "ml_confidence": ml_confidence,
                "severity":    "HIGH" if ml_confidence > 80 or max_bytes > 50000 else "MEDIUM"
            }
            alerts.append(alert)

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "═"*62)
    print(f"  RESULTS: {len(alerts)} suspicious source(s) detected")
    print("═"*62)

    if alerts:
        for a in alerts:
            print(f"\n  🚨 [{a['severity']}] {a['source_ip']}")
            print(f"     Packets  : {a['packet_count']}")
            print(f"     Data     : {a['total_bytes']:,} bytes")
            print(f"     ML Score : {a['ml_result']}")
            for flag in a["rule_flags"]:
                print(f"     ⚠️  {flag}")
        print("\n  ⚠️  Suspicious external sources are sending data to your machine.")
        print("     This may indicate: unauthorized data fetching, malware, or exfiltration.\n")
    else:
        print("  ✅ No suspicious external HTTP activity detected.\n")

    # Save results as JSON for the dashboard
    os.makedirs("data", exist_ok=True)
    with open(RESULTS_JSON, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"💾 Results saved to {RESULTS_JSON} (readable by dashboard)\n")

    return alerts


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV
    analyze(csv_path)
