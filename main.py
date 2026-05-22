#!/usr/bin/env python3
"""
============================================================
  CodeAlpha Cyber Security Internship
  Task 1: Basic Network Sniffer
  Author: Nai Raj | CA/SE3/16577
============================================================
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR
from datetime import datetime
import sys
import os

# ─────────────────────────────────────────────
#  COLORS FOR TERMINAL OUTPUT
# ─────────────────────────────────────────────

class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ─────────────────────────────────────────────
#  PACKET COUNTER
# ─────────────────────────────────────────────

packet_count = 0

# ─────────────────────────────────────────────
#  PROTOCOL DETECTION
# ─────────────────────────────────────────────

def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP", Color.GREEN
    elif packet.haslayer(UDP):
        return "UDP", Color.YELLOW
    elif packet.haslayer(ICMP):
        return "ICMP", Color.CYAN
    elif packet.haslayer(ARP):
        return "ARP", Color.BLUE
    else:
        return "OTHER", Color.WHITE


# ─────────────────────────────────────────────
#  GET SERVICE NAME FROM PORT
# ─────────────────────────────────────────────

def get_service(port):
    services = {
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        53:   "DNS",
        67:   "DHCP",
        80:   "HTTP",
        110:  "POP3",
        143:  "IMAP",
        443:  "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    return services.get(port, "")


# ─────────────────────────────────────────────
#  PROCESS EACH CAPTURED PACKET
# ─────────────────────────────────────────────

def process_packet(packet):
    global packet_count
    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    protocol, proto_color = get_protocol_name(packet)

    print(f"\n{Color.BOLD}{'─' * 65}{Color.RESET}")
    print(
        f"{Color.BOLD}[#{packet_count}]{Color.RESET}  "
        f"{Color.CYAN}{timestamp}{Color.RESET}  │  "
        f"{proto_color}{Color.BOLD}{protocol}{Color.RESET}"
    )
    print(f"{'─' * 65}")

    # ── IP Layer ──────────────────────────────
    if packet.haslayer(IP):
        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        ttl     = packet[IP].ttl
        pkt_len = len(packet)

        print(f"  {Color.WHITE}Source IP      :{Color.RESET}  {Color.GREEN}{src_ip}{Color.RESET}")
        print(f"  {Color.WHITE}Destination IP :{Color.RESET}  {Color.RED}{dst_ip}{Color.RESET}")
        print(f"  {Color.WHITE}Packet Length  :{Color.RESET}  {pkt_len} bytes   "
              f"  {Color.WHITE}TTL:{Color.RESET} {ttl}")

        # ── TCP Details ──────────────────────
        if packet.haslayer(TCP):
            sport   = packet[TCP].sport
            dport   = packet[TCP].dport
            flags   = packet[TCP].flags
            s_svc   = get_service(sport)
            d_svc   = get_service(dport)

            s_label = f"{sport} ({s_svc})" if s_svc else str(sport)
            d_label = f"{dport} ({d_svc})" if d_svc else str(dport)

            print(f"  {Color.WHITE}Source Port    :{Color.RESET}  {s_label}")
            print(f"  {Color.WHITE}Dest Port      :{Color.RESET}  {d_label}")
            print(f"  {Color.WHITE}TCP Flags      :{Color.RESET}  {flags}")

        # ── UDP Details ──────────────────────
        elif packet.haslayer(UDP):
            sport   = packet[UDP].sport
            dport   = packet[UDP].dport
            s_svc   = get_service(sport)
            d_svc   = get_service(dport)

            s_label = f"{sport} ({s_svc})" if s_svc else str(sport)
            d_label = f"{dport} ({d_svc})" if d_svc else str(dport)

            print(f"  {Color.WHITE}Source Port    :{Color.RESET}  {s_label}")
            print(f"  {Color.WHITE}Dest Port      :{Color.RESET}  {d_label}")

        # ── ICMP Details ─────────────────────
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            type_name = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable"}.get(icmp_type, str(icmp_type))
            print(f"  {Color.WHITE}ICMP Type      :{Color.RESET}  {type_name} (code {icmp_code})")

        # ── DNS Query ────────────────────────
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                dns_name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                print(f"  {Color.YELLOW}DNS Query      :{Color.RESET}  {dns_name}")
            except Exception:
                pass

        # ── Payload ──────────────────────────
        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load
                payload  = raw_data.decode("utf-8", errors="ignore").strip()

                if payload:
                    # Truncate long payloads for readability
                    display = payload[:300].replace("\n", " ").replace("\r", "")
                    print(f"  {Color.WHITE}Payload        :{Color.RESET}  {Color.CYAN}{display}{Color.RESET}")
            except Exception:
                pass

    # ── ARP Layer ─────────────────────────────
    elif packet.haslayer(ARP):
        op = "Request" if packet[ARP].op == 1 else "Reply"
        print(f"  {Color.WHITE}ARP Operation  :{Color.RESET}  {op}")
        print(f"  {Color.WHITE}Sender IP      :{Color.RESET}  {Color.GREEN}{packet[ARP].psrc}{Color.RESET}")
        print(f"  {Color.WHITE}Target IP      :{Color.RESET}  {Color.RED}{packet[ARP].pdst}{Color.RESET}")
        print(f"  {Color.WHITE}Sender MAC     :{Color.RESET}  {packet[ARP].hwsrc}")

    else:
        print(f"  {Color.YELLOW}Non-IP/ARP packet captured{Color.RESET}")


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║         CODEALPHA — BASIC NETWORK SNIFFER                ║
  ║         Cyber Security Internship — Task 1               ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Author  : Nai Raj                                       ║
  ║  ID      : CA/SE3/16577                                  ║
  ║  Tool    : Python + Scapy                                ║
  ╚══════════════════════════════════════════════════════════╝
{Color.RESET}"""
    print(banner)


# ─────────────────────────────────────────────
#  SUMMARY ON EXIT
# ─────────────────────────────────────────────

def print_summary():
    print(f"\n{Color.BOLD}{'═' * 65}{Color.RESET}")
    print(f"  {Color.GREEN}[✓] Sniffing stopped.{Color.RESET}")
    print(f"  {Color.WHITE}Total Packets Captured : {Color.BOLD}{Color.CYAN}{packet_count}{Color.RESET}")
    print(f"{Color.BOLD}{'═' * 65}{Color.RESET}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()

    # Optional: filter argument (e.g. "tcp", "udp", "icmp")
    filter_arg = None
    if len(sys.argv) > 1:
        filter_arg = sys.argv[1]
        print(f"  {Color.YELLOW}[*] Filter applied : {filter_arg}{Color.RESET}")

    print(f"  {Color.GREEN}[*] Starting packet capture... Press CTRL+C to stop.{Color.RESET}\n")

    try:
        sniff(
            prn=process_packet,
            filter=filter_arg,
            store=False
        )

    except KeyboardInterrupt:
        print_summary()

    except PermissionError:
        print(f"\n  {Color.RED}[ERROR] Permission denied.{Color.RESET}")
        print(f"  {Color.YELLOW}→ Windows: Run terminal as Administrator{Color.RESET}")
        print(f"  {Color.YELLOW}→ Linux  : Use  sudo python3 main.py{Color.RESET}\n")
        sys.exit(1)

    except Exception as e:
        print(f"\n  {Color.RED}[ERROR] {e}{Color.RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
