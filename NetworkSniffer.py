from scapy.all import sniff, Ether, ARP, IP, TCP, UDP, ICMP

def packet_callback(packet):
    log_entry = ""

    if packet.haslayer(Ether):
        log_entry += "Ethernet Frame:\n"
        log_entry += "  Source MAC: {}\n".format(packet[Ether].src)
        log_entry += "  Destination MAC: {}\n".format(packet[Ether].dst)

    if packet.haslayer(ARP):
        log_entry += "ARP Packet:\n"
        log_entry += "  {}\n".format(packet.summary())

    if packet.haslayer(IP):
        log_entry += "IP Packet:\n"
        log_entry += "  Source IP: {}\n".format(packet[IP].src)
        log_entry += "  Destination IP: {}\n".format(packet[IP].dst)

        if packet.haslayer(TCP):
            log_entry += "TCP Segment:\n"
            log_entry += "  Source Port: {}\n".format(packet[TCP].sport)
            log_entry += "  Destination Port: {}\n".format(packet[TCP].dport)

        if packet.haslayer(UDP):
            log_entry += "UDP Datagram:\n"
            log_entry += "  Source Port: {}\n".format(packet[UDP].sport)
            log_entry += "  Destination Port: {}\n".format(packet[UDP].dport)

        if packet.haslayer(ICMP):
            log_entry += "ICMP Packet:\n"
            if packet[ICMP].type == 0:
                log_entry += "  ICMP Echo Reply\n"
            elif packet[ICMP].type == 8:
                log_entry += "  ICMP Echo Request\n"
            else:
                log_entry += "  ICMP Type: {}\n".format(packet[ICMP].type)
                log_entry += "  ICMP Code: {}\n".format(packet[ICMP].code)

    log_entry += "\n"

    with open("packet_log.txt", "a") as f:
        f.write(log_entry)

    print(log_entry)

# Sniffing network traffic
sniff(prn=packet_callback, count=10)  # Adjust count as needed