# Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Cybersecurity](https://img.shields.io/badge/Tool-Packet%20Sniffer-red)
![Status](https://img.shields.io/badge/Status-Active-success)

## Overview

Packet Sniffer is a Python-based cybersecurity tool that captures and analyzes network traffic in real time.

It provides detailed insights into network packets, including source and destination IP addresses, protocols, and ports.  
This project demonstrates fundamental **network traffic analysis**, which is a core concept in cybersecurity and widely used in **network monitoring, intrusion detection, and incident response**.

---

## Features

- Capture live network packets
- Display source and destination IP addresses
- Detect protocols (TCP, UDP, ICMP)
- Show source and destination ports
- Packet counter for monitoring traffic

---

## Advanced Features

- Filter packets by protocol (TCP, UDP, ICMP)
- Filter traffic by specific ports (e.g., 80, 443)
- Real-time packet monitoring
- Timestamped packet logging
- Save captured data to a log file (`packet_log.txt`)

---

## Technologies Used

- Python
- Scapy library

---

## Project Structure


packet-sniffer
│
├── sniffer.py
├── requirements.txt
├── packet_log.txt (generated after running)
└── README.md


---

## Installation

Clone the repository:


git clone https://github.com/Pravat25/packet-sniffer.git


Navigate into the folder:


cd packet-sniffer


Install dependencies:


pip install -r requirements.txt


---

## How to Run

Run the script:


python sniffer.py


Enter filter options when prompted:


Filter by protocol (tcp/udp/icmp/all): tcp
Filter by port (or press Enter for all): 80


---

## Example Output


[1] 2026-03-19 12:30:01 TCP 192.168.1.5:52345 -> 142.250.182.14:443
[2] 2026-03-19 12:30:02 UDP 192.168.1.5:5353 -> 224.0.0.251:5353


---

## Logging Feature

Captured packets are automatically saved to:


packet_log.txt


Each log entry includes:

- Packet number
- Timestamp
- Protocol
- Source and destination IP/port

---

## Learning Purpose

This project was built to practice:

- Network packet analysis
- Protocol inspection (TCP, UDP, ICMP)
- Cybersecurity monitoring concepts
- Python scripting with Scapy

---

## Disclaimer

This tool is created for **educational purposes only** and should not be used for unauthorized network monitoring.
