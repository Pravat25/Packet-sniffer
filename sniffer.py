from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_count = 0

# Get user input for filtering
filter_protocol = input("Filter by protocol (tcp/udp/icmp/all): ").lower()
filter_port = input("Filter by port (or press Enter for all): ")

if filter_port:
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

    # Detect protocol
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

    # Apply protocol filter
    if filter_protocol != "all" and protocol != filter_protocol:
        return

    # Apply port filter
    if filter_port:
        if sport != filter_port and dport != filter_port:
            return

    packet_count += 1

    # Print result
    if protocol in ["tcp", "udp"]:
        print(f"[{packet_count}] {protocol.upper()} {src}:{sport} -> {dst}:{dport}")
    else:
        print(f"[{packet_count}] {protocol.upper()} {src} -> {dst}")


print("\nStarting filtered packet sniffer...\n")

sniff(prn=packet_callback, count=50)
