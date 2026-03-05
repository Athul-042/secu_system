import pandas as pd
import numpy as np
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.preprocessing import LabelEncoder

# Define paths
DATA_PATH = "data/KDDTrain+.txt"
MODEL_PATH = "model.pkl"

# Columns for NSL-KDD
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]

# Selected Features compatible with basic packet sniffing
# Added 'count' (traffic volume) which can be calculated in real-time
SELECTED_FEATURES = ["protocol_type", "src_bytes", "dst_bytes", "count"]

def train():
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: Dataset not found at {DATA_PATH}")
        print("Please download 'KDDTrain+.txt' from NSL-KDD and place it in 'backend/data/'")
        return

    print("Loading NSL-KDD dataset...")
    df = pd.read_csv(DATA_PATH, names=COLUMNS)

    print("Preprocessing...")
    # 1. Encode Protocol (Text -> Number)
    protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
    df["protocol_type"] = df["protocol_type"].map(protocol_map).fillna(3)

    # 2. Encode Label (Normal=0, Attack=1)
    df["target"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)

    # 3. Select Features & Target
    X = df[SELECTED_FEATURES]
    y = df["target"]

    # 4. Split Data (80% Train, 20% Test)
    print("Splitting data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"Training Random Forest on {len(X_train)} records...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    print("Saving model...")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    
    print(f"✅ Model saved to {MODEL_PATH}")

    print("Evaluating Model...")
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\nModel Performance (Test Set):")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    try:
        print("\nDetailed Report:")
        print(classification_report(y_test, y_pred))
    except Exception as e:
        print(f"Could not generate detailed report: {e}")

if __name__ == "__main__":
    train()
