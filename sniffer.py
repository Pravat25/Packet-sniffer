from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{packet_count}] {protocol} {src}:{sport} -> {dst}:{dport}")

        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{packet_count}] {protocol} {src}:{sport} -> {dst}:{dport}")

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            print(f"[{packet_count}] {protocol} {src} -> {dst}")

        else:
            print(f"[{packet_count}] Other {src} -> {dst}")


print("Starting advanced packet sniffer...\n")

sniff(prn=packet_callback, count=20)
