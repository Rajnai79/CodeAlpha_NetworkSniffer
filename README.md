# CodeAlpha — Basic Network Sniffer

> **Cyber Security Internship — Task 1**  
> **Author:** Nai Raj | **ID:** CA/SE3/16577  
> **Domain:** Cyber Security | **Org:** CodeAlpha

---

## 📌 Project Overview

This project is developed as part of the **CodeAlpha Cyber Security Internship**.

The objective is to build a **Python-based network packet sniffer** that captures and analyzes live network traffic in real time. The tool helps understand how data flows across networks and how different protocols behave at the packet level.

---

## 🚀 Features

| Feature | Description |
|---|---|
| ✅ Live Packet Capture | Captures packets from network interface in real time |
| ✅ IP Layer Analysis | Displays source & destination IP addresses |
| ✅ Protocol Detection | Identifies TCP, UDP, ICMP, ARP packets |
| ✅ Port & Service Info | Shows port numbers with common service names (HTTP, HTTPS, DNS, SSH…) |
| ✅ DNS Query Detection | Extracts DNS hostnames from UDP packets |
| ✅ Payload Inspection | Decodes and displays readable packet payload |
| ✅ ARP Analysis | Detects ARP requests and replies with MAC addresses |
| ✅ ICMP Details | Shows ICMP type (Echo Request, Echo Reply, etc.) |
| ✅ TCP Flags | Displays TCP connection flags (SYN, ACK, FIN…) |
| ✅ Colored Terminal | Color-coded output for easy reading |
| ✅ Packet Filter | Optional BPF filter support (tcp, udp, icmp, port 80…) |
| ✅ Packet Counter | Shows count and summary on exit |

---

## 🛠 Technologies Used

- **Language:** Python 3
- **Library:** Scapy
- **OS:** Windows / Linux / Kali Linux

---

## 📂 Project Structure

```
CodeAlpha_NetworkSniffer/
│
├── main.py            ← Main sniffer program
├── requirements.txt   ← Python dependencies
├── README.md          ← Project documentation
└── screenshots/       ← Output screenshots
```

---

## ⚙️ Installation

### Step 1 — Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer.git
```

### Step 2 — Navigate to Project Folder
```bash
cd CodeAlpha_NetworkSniffer
```

### Step 3 — Install Required Library
```bash
pip install -r requirements.txt
```

---

## ▶️ How To Run

### Windows
Run **Command Prompt or VS Code as Administrator**, then:
```bash
python main.py
```

### Linux / Kali Linux
```bash
sudo python3 main.py
```

### With Protocol Filter (Optional)
```bash
# Capture only TCP packets
sudo python3 main.py tcp

# Capture only UDP packets
sudo python3 main.py udp

# Capture only ICMP (ping) packets
sudo python3 main.py icmp

# Capture HTTP traffic only
sudo python3 main.py "tcp port 80"
```

---

## 🧠 How It Works

```
Network Interface
       │
       ▼
  Scapy sniff()
       │
       ▼
  process_packet()
       │
       ├─── IP Layer?  ──► Extract src IP, dst IP, length, TTL
       │         │
       │         ├── TCP? ──► Ports, Flags, Service Name
       │         ├── UDP? ──► Ports, DNS Query
       │         └── ICMP?──► Type, Code
       │
       ├─── ARP Layer? ──► Op, Sender IP, Target IP, MAC
       │
       └─── Raw Layer? ──► Decode & Display Payload
```

---

## 📸 Example Output

```
╔══════════════════════════════════════════════════════════╗
║         CODEALPHA — BASIC NETWORK SNIFFER                ║
║         Cyber Security Internship — Task 1               ║
╠══════════════════════════════════════════════════════════╣
║  Author  : Nai Raj                                       ║
║  ID      : CA/SE3/16577                                  ║
╚══════════════════════════════════════════════════════════╝

  [*] Starting packet capture... Press CTRL+C to stop.

─────────────────────────────────────────────────────────────
[#1]  2026-05-25 11:20:15  │  TCP
─────────────────────────────────────────────────────────────
  Source IP      :  192.168.1.5
  Destination IP :  142.250.183.78
  Packet Length  :  74 bytes     TTL: 64
  Source Port    :  51422
  Dest Port      :  443 (HTTPS)
  TCP Flags      :  S

─────────────────────────────────────────────────────────────
[#2]  2026-05-25 11:20:15  │  UDP
─────────────────────────────────────────────────────────────
  Source IP      :  192.168.1.5
  Destination IP :  8.8.8.8
  Packet Length  :  60 bytes     TTL: 64
  Source Port    :  54321
  Dest Port      :  53 (DNS)
  DNS Query      :  www.google.com
```

---

## 📡 Protocols Covered

| Protocol | Layer | Info Extracted |
|---|---|---|
| TCP | Transport | Source/Dest Port, Flags, Service |
| UDP | Transport | Source/Dest Port, DNS Queries |
| ICMP | Network | Type, Code (Echo/Unreachable) |
| ARP | Data Link | Operation, IPs, MAC Address |
| DNS | Application | Queried Hostname |
| IP | Network | Src/Dst IP, TTL, Length |

---

## 🔐 Learning Outcomes

Through this project, I learned:

- Fundamentals of **packet sniffing** and network analysis
- How **TCP/IP protocols** work at the packet level
- Understanding **TCP flags** (SYN, ACK, FIN, RST)
- How **DNS resolution** works over UDP
- Difference between **TCP and UDP** communication
- How **ARP** maps IP addresses to MAC addresses
- Using **Scapy** library for raw packet processing
- Importance of **administrator/root privileges** for socket access
- Basics of **BPF (Berkeley Packet Filter)** for traffic filtering
- Real-world **cybersecurity monitoring** fundamentals

---

## 🎯 Internship Task Details

**TASK 1: Basic Network Sniffer**
- Build a Python program to capture network traffic packets
- Analyze packet structure and contents
- Understand network data flow and protocols
- Use libraries like Scapy or Socket
- Display source/destination IPs, protocols, and payloads

---

## ⚠️ Important Note

> This project is created strictly for **educational purposes** and **ethical cybersecurity learning** as part of the CodeAlpha Internship.  
> **Do NOT use packet sniffing tools on unauthorized networks.** Always obtain proper permission before capturing network traffic.

---

## 👨‍💻 Author

**Nai Raj**  
Cyber Security Intern — CodeAlpha  
Student ID: CA/SE3/16577

---

## 🔗 Connect With Me

- **GitHub:** https://github.com/YOUR_USERNAME
- **LinkedIn:** https://linkedin.com/in/YOUR_LINKEDIN
