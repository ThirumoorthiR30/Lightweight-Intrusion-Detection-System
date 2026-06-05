
from scapy.all import sniff, IP, TCP, UDP
import time
import pandas as pd
import joblib


model = joblib.load("ids_model.pkl")
scaler = joblib.load("scaler.pkl")
columns = joblib.load("columns.pkl")


flow_data = {
    "start_time": time.time(),
    "src_bytes": 0,
    "dst_bytes": 0,
    "count": 0,
    "srv_count": 0,
    "protocol_type": "tcp"
}


def packet_handler(packet):
    global flow_data

    if IP in packet:
        flow_data["count"] += 1

        if TCP in packet:
            flow_data["protocol_type"] = "tcp"
            flow_data["src_bytes"] += len(packet)
        elif UDP in packet:
            flow_data["protocol_type"] = "udp"
            flow_data["src_bytes"] += len(packet)


def analyze_flow():
    duration = time.time() - flow_data["start_time"]

    data = {
        "duration": duration,
        "protocol_type": flow_data["protocol_type"],
        "src_bytes": flow_data["src_bytes"],
        "dst_bytes": flow_data["dst_bytes"],
        "count": flow_data["count"],
        "srv_count": flow_data["count"],
        "wrong_fragment": 0,
        "urgent": 0,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_srv_count": flow_data["count"]
    }

    df = pd.DataFrame([data])

    # One-hot encoding + alignment
    df = pd.get_dummies(df)
    df = df.reindex(columns=columns, fill_value=0)

    df_scaled = scaler.transform(df)

    prediction = model.predict(df_scaled)[0]
    print("Prediction =", prediction)
    if prediction != 0:
        print(f"🚨 ATTACK DETECTED: {prediction}")
    else:
        print("✅ Normal Traffic")

    # Reset window
    flow_data["start_time"] = time.time()
    flow_data["count"] = 0
    flow_data["src_bytes"] = 0


import threading

def live_monitor():
    sniff(prn=packet_handler, store=False)

threading.Thread(target=live_monitor, daemon=True).start()

while True:
    time.sleep(5)
    analyze_flow()
