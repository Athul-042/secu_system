import numpy as np
import pandas as pd
import pickle
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

np.random.seed(42)
MODEL_PATH = "model.pkl"
os.makedirs("data", exist_ok=True)

def clamp(val, lo, hi):
    return max(lo, min(hi, int(val)))

def generate_normal(n=3000):
    records = []
    normal_dst_ips = [hash(ip) % 100000 for ip in [
        "142.250.77.14","172.217.160.78","151.101.1.140",
        "104.18.1.22","13.227.92.10","52.85.151.1"
    ]]
    normal_src_ips = [hash(ip) % 100000 for ip in [
        "192.168.1.5","10.0.0.10","172.16.0.5"
    ]]
    for _ in range(n):
        proto    = int(np.random.choice([0,0,0,1,2], p=[0.6,0.15,0.1,0.1,0.05]))
        pkt_len  = clamp(np.random.normal(800,400), 40, 1500)
        dst_port = int(np.random.choice([80,443,443,53,8080], p=[0.3,0.4,0.1,0.15,0.05]))
        url_len  = clamp(np.random.normal(35,20), 1, 150) if proto == 0 else 0
        req_cnt  = clamp(np.random.normal(15,10), 1, 60)
        src_ip   = int(np.random.choice(normal_src_ips))
        dst_ip   = int(np.random.choice(normal_dst_ips))
        records.append([proto, pkt_len, dst_port, url_len, req_cnt, src_ip, dst_ip, 0])
    return records

def generate_attack(n=2000):
    records = []
    attack_src = [hash(ip) % 100000 for ip in [
        "185.220.101.45","91.108.4.200","45.33.32.156",
        "198.51.100.77","203.0.113.50","5.188.10.100"
    ]]
    attack_dst = [hash(ip) % 100000 for ip in [
        "192.168.1.5","10.0.0.10","10.230.181.80"
    ]]

    # UDP Flood
    for _ in range(n // 4):
        records.append([1, clamp(np.random.normal(1000,50),500,1500),
                        int(np.random.choice([80,443,53,8080])), 0,
                        clamp(np.random.normal(500,100),200,1000),
                        int(np.random.choice(attack_src)), int(np.random.choice(attack_dst)), 1])

    # Large payload / exfiltration
    for _ in range(n // 4):
        records.append([0, clamp(np.random.normal(8000,2000),5000,15000),
                        int(np.random.choice([80,4444,6667,1337])), 0,
                        clamp(np.random.normal(20,10),5,60),
                        int(np.random.choice(attack_src)), int(np.random.choice(attack_dst)), 1])

    # Malicious HTTP long URLs (SQLi/injection)
    for _ in range(n // 4):
        records.append([3, clamp(np.random.normal(600,200),100,2000),
                        80, clamp(np.random.normal(350,100),200,800),
                        clamp(np.random.normal(80,30),30,300),
                        int(np.random.choice(attack_src)), int(np.random.choice(attack_dst)), 1])

    # Port scanning (tiny packets, suspicious ports)
    for _ in range(n // 4):
        records.append([0, clamp(np.random.normal(60,10),40,120),
                        int(np.random.choice([4444,6667,1337,31337,9999,23,22,21])), 0,
                        clamp(np.random.normal(200,50),50,500),
                        int(np.random.choice(attack_src)), int(np.random.choice(attack_dst)), 1])

    return records

def train():
    # REMOVED IP features because they cause overfitting on synthetic data
    # Real-world IDS focus on behavioral features
    FEATURES = ["protocol", "packet_length", "destination_port", "url_length", "request_count"]

    print("Generating synthetic training data...")
    normal = [r[:5] + [r[-1]] for r in generate_normal(3000)] # Only first 5 + label
    attack = [r[:5] + [r[-1]] for r in generate_attack(2000)]

    all_data = normal + attack
    np.random.shuffle(all_data)

    df = pd.DataFrame(all_data, columns=FEATURES + ["label"])
    print(f"Normal: {len(normal)}  |  Attack: {len(attack)}  |  Total: {len(df)}")

    X = df[FEATURES]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"Training XGBoost on {len(X_train)} samples...")
    model = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    # Save meta-info for the report
    with open("data/model_info.pkl", "wb") as f:
        pickle.dump({"accuracy": acc, "features": FEATURES, "model_type": "XGBoost"}, f)

    print(f"\nAccuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=["Normal","Attack"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved -> {MODEL_PATH}")

    df[df.label==0].drop("label",axis=1).to_csv("data/normal_traffic.csv",index=False)
    df[df.label==1].drop("label",axis=1).to_csv("data/attack_traffic.csv",index=False)
    print("Synthetic CSVs saved to data/ for reference.")

if __name__ == "__main__":
    train()
