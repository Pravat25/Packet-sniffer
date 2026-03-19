from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0

# Filters
filter_protocol = input("Filter by protocol (tcp/udp/icmp/all): ").lower()
filter_port = input("Filter by port (or press Enter for all): ")

if filter_port.isdigit():
    filter_port = int(filter_port)
else:
    filter_port = None


def packet_callback(packet):
    global packet_count

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    protocol = None
    sport = None
    dport = None

    if packet.haslayer(TCP):
        protocol = "tcp"
        sport = packet[TCP].sport
        dport = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "udp"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "icmp"

    # Apply filters
    if filter_protocol != "all" and protocol != filter_protocol:
        return

    if filter_port:
        if sport != filter_port and dport != filter_port:
            return

    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if protocol in ["tcp", "udp"]:
        log = f"[{packet_count}] {timestamp} {protocol.upper()} {src}:{sport} -> {dst}:{dport}"
    else:
        log = f"[{packet_count}] {timestamp} {protocol.upper()} {src} -> {dst}"

    print(log)

    # Save to file
    with open("packet_log.txt", "a") as f:
        f.write(log + "\n")


print("\nStarting advanced packet sniffer with logging...\n")

sniff(prn=packet_callback, count=50)
