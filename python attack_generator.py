from scapy.all import IP, TCP, UDP, send
import random
import time

TARGET_IP = "127.0.0.1"   # change if needed (local system)
TARGET_PORT = 80

# -----------------------------
# NORMAL TRAFFIC
# -----------------------------
def normal_traffic():
    pkt = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="PA")/("GET / HTTP/1.1\r\n")
    send(pkt, verbose=False)
    print("✅ Normal traffic sent")

# -----------------------------
# DoS-LIKE TRAFFIC (burst packets)
# -----------------------------
def dos_attack():
    for _ in range(20):
        pkt = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="S")
        send(pkt, verbose=False)
    print("🚨 DoS-like traffic sent")

# -----------------------------
# PROBE / PORT SCAN
# -----------------------------
def probe_attack():
    for port in range(20, 30):
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
    print("🚨 Probe/Scan traffic sent")

# -----------------------------
# HIGH BYTE SUSPICIOUS TRAFFIC
# -----------------------------
def high_byte_attack():
    payload = "X" * random.randint(2000, 5000)
    pkt = IP(dst=TARGET_IP)/UDP(dport=TARGET_PORT)/payload
    send(pkt, verbose=False)
    print("🚨 High-byte suspicious traffic sent")

# -----------------------------
# MIXED TRAFFIC GENERATOR
# -----------------------------
def mixed_traffic():
    actions = [normal_traffic, dos_attack, probe_attack, high_byte_attack]

    while True:
        action = random.choice(actions)
        action()
        time.sleep(random.uniform(0.5, 2))  # random interval


if __name__ == "__main__":
    print("🔁 Sending mixed traffic (Normal + Attacks)...")
    mixed_traffic()
