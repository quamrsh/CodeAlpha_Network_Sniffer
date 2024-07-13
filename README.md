Certainly! Here's a README file for your simple network sniffer using Python and Scapy:

# Simple Network Sniffer

This Python script implements a simple network sniffer using Scapy to capture and log various network packets, including Ethernet frames, ARP packets, IP packets (TCP, UDP, ICMP), and their respective details.

## Features

- **Ethernet Frame Handling**: Logs source and destination MAC addresses.
- **ARP Packet Handling**: Logs ARP packet details.
- **IP Packet Handling**: Logs source and destination IP addresses.
  - **TCP Segment Handling**: Logs source and destination port numbers for TCP packets.
  - **UDP Datagram Handling**: Logs source and destination port numbers for UDP packets.
  - **ICMP Packet Handling**: Logs ICMP packet types, including Echo Reply and Echo Request.

## Prerequisites

- Python 3
- Scapy library

## Installation

1. **Install Python**: If you don't have Python installed, download and install it from the [official website](https://www.python.org/downloads/).

2. **Install Scapy**: Use pip to install Scapy.
    ```bash
    pip install scapy
    ```

## Usage

1. **Download the Code**: Save the provided script as `networksniffer.py`.

2. **Run the Script**: Execute the script to start capturing network packets.
    ```bash
    python networksniffer.py
    ```

3. **View Captured Packets**: Captured packet details are logged in the `packetlog.txt` file in the same directory as the script.

## Code Explanation

### Imports

```python
from scapy.all import sniff, Ether, ARP, IP, TCP, UDP, ICMP
```

- Imports necessary Scapy modules and classes for packet handling.

### Packet Callback Function

```python
def packet_callback(packet):
    log_entry = ""

    if packet.haslayer(Ether):
        log_entry += "Ethernet Frame: Source MAC: {}\nDestination MAC: {}\n".format(packet[Ether].src, packet[Ether].dst)

    if packet.haslayer(ARP):
        log_entry += "ARP Packet: {}\n".format(packet.summary())

    if packet.haslayer(IP):
        log_entry += "IP Packet: Source IP: {}\nDestination IP: {}\n".format(packet[IP].src, packet[IP].dst)

        if packet.haslayer(TCP):
            log_entry += "TCP Segment: Source Port: {}\nDestination Port: {}\n".format(packet[TCP].sport, packet[TCP].dport)

        if packet.haslayer(UDP):
            log_entry += "UDP Datagram: Source Port: {}\nDestination Port: {}\n".format(packet[UDP].sport, packet[UDP].dport)

        if packet.haslayer(ICMP):
            if packet[ICMP].type == 0:
                log_entry += "ICMP Echo Reply\n"
            elif packet[ICMP].type == 8:
                log_entry += "ICMP Echo Request\n"
            else:
                log_entry += "ICMP Packet: Type: {}\nCode: {}\n".format(packet[ICMP].type, packet[ICMP].code)

    with open("packetlog.txt", "a") as f:
        f.write(log_entry)
```

- **packet_callback**: Function that handles incoming packets, extracts relevant information, and logs it into `packetlog.txt`.

### Sniffing Network Traffic

```python
sniff(prn=packet_callback, count=50)  # Adjust count as needed
```

- Starts the packet sniffing process using Scapy's `sniff` function with `packet_callback` as the callback function. Adjust `count` parameter to specify how many packets to capture.

## Customization

- Modify the script to include additional packet types or customize logging formats as per your requirements.

## Logging

- Captured packet details are appended to `packetlog.txt` file in the current working directory.

## Disclaimer

This script is for educational purposes only and should be used responsibly and legally. Capturing network traffic without authorization is often against the law and can have serious consequences.

---

Feel free to enhance the script or adapt it for specific use cases.
