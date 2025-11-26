import random
from scapy.all import sniff, IP, TCP, UDP, Ether, Raw

# Generate consistent fake identity each run
FAKE_LOCAL_IP = f"192.168.{random.randint(10,250)}.{random.randint(10,250)}"
FAKE_MAC = "AA:BB:CC:" + ":".join([f"{random.randint(0,255):02X}" for _ in range(3)])

def spoof_ip(real_ip):
    parts = real_ip.split(".")
    return f"10.{parts[1]}.{parts[2]}.{random.randint(10,250)}"

def spoof_port(real_port):
    return random.randint(1000, 65000)

def spoof_payload(payload):
    if not payload:
        return "<no payload>"
    return " ".join([hex(random.randint(0,255)) for _ in range(10)])

def handle_packet(packet):
    print("\n=== SAFE CAPTURED PACKET ===")

    # MAC spoof
    if Ether in packet:
        print(f"Source MAC: {FAKE_MAC}")
        print(f"Destination MAC: {FAKE_MAC}")

    # IP spoof
    if IP in packet:
        fake_src = spoof_ip(packet[IP].src)
        fake_dst = spoof_ip(packet[IP].dst)
        print(f"Source IP: {fake_src}")
        print(f"Destination IP: {fake_dst}")
        print(f"Protocol: {packet[IP].proto}")

    # TCP spoof
    if TCP in packet:
        print("Protocol: TCP")
        print(f"Source Port: {spoof_port(packet[TCP].sport)}")
        print(f"Destination Port: {spoof_port(packet[TCP].dport)}")

    # UDP spoof
    if UDP in packet:
        print("Protocol: UDP")
        print(f"Source Port: {spoof_port(packet[UDP].sport)}")
        print(f"Destination Port: {spoof_port(packet[UDP].dport)}")

    # Payload spoof
    if Raw in packet:
        payload = bytes(packet[Raw].load)
        print(f"Payload (spoofed): {spoof_payload(payload)}")
    else:
        print("Payload: <none>")

print("SAFE Packet Sniffer Started (Sensitive Data Spoofed)")
print("Press Ctrl + C to stop...\n")

sniff(prn=handle_packet, store=False)
