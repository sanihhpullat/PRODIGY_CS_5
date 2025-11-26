## Project: Safe Packet Sniffer (Python)

### Description
Developed a real-time network packet sniffer using Python and Scapy. The tool captures live network packets, analyzes them, and displays information such as source IP, destination IP, MAC addresses, protocol, ports, and payload data.  
To ensure safety and avoid exposing my real network information, all sensitive fields (IP, MAC, ports, payload) are automatically spoofed before being displayed. This allows the tool to demonstrate full packet-sniffing functionality without leaking any actual personal or device data.

### Why Spoofing Was Used
Because packet sniffers normally reveal real network details (my actual IP, MAC address, packet payloads, etc.), this project includes a built-in spoofing system that replaces:
- Real IP → Fake 10.x.x.x IP  
- Real MAC → Fake AA:BB:CC:xx:xx:xx  
- Real Ports → Random safe ports  
- Real Payload → Generated random hex values  

### Requirements
This project requires the following:
- Python
- Scapy library (`pip install scapy`)
- Npcap installed on Windows  
  (Scapy needs Npcap for low-level packet capture. Installed with WinPcap compatibility mode.)

### Features
- Real-time packet capture  
- Spoofed output for safety  
- Displays protocol, IPs, ports, MACs, and payload  
- Works on Windows with Npcap  
- Ethical and safe for educational use

### How to Use
1. Install Python and Scapy:
   ```bash
   pip install scapy
   ```
2. Install **Npcap** (Windows) with **WinPcap compatibility mode** enabled.  
3. Save the script as **sanih_packet_sniffer.py**  
4. Open Command Prompt inside the folder where the script is saved.  
5. Run the tool:
   ```bash
   python sanih_packet_sniffer.py
   ```
6. The program will begin capturing packets and printing **fully spoofed** safe output.  
7. Press **Ctrl + C** to stop the sniffer.

### Sample Output (Spoofed)
=== SAFE CAPTURED PACKET ===  
Source MAC: AA:BB:CC:A3:AE:89  
Destination MAC: AA:BB:CC:A3:AE:89  
Source IP: 10.67.189.112  
Destination IP: 10.168.8.141  
Protocol: 1  
Payload (spoofed): 0xd8 0xc6 0xb7 0x3a 0xe5 0x49 0xdd 0x4f 0x09 0x46  

### Purpose
Created as part of my cybersecurity internship to practice network analysis, packet inspection, Python scripting, and safe handling of sensitive network data.
