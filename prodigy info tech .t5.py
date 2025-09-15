from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Identify protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto)

        print(f"\n[Packet Captured]")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        
        if packet.haslayer(TCP):
            print("TCP Segment:")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("UDP Segment:")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("ICMP Packet")
        
        # Show payload if present
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")

def main():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, count=10)

if _name_ == "_main_":
    main()
