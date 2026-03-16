from scapy.all import sniff

def packet_callback(packet):

    if packet.haslayer("IP"):

        src = packet["IP"].src
        dst = packet["IP"].dst

        print(f"Packet: {src} -> {dst}")

print("Starting packet sniffer...\n")

sniff(prn=packet_callback, count=10)
