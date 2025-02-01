# CN_Assignment1
CS-331, Computer Network Assignment 1
---

## Introduction
This assignment focuses on capturing network packets and analyzing them using C++ Python. The project runs on Kali Linux, and a live boot method is used to run Kali Linux without installation. Additionally, Wireshark is utilized for packet inspection, and `tcpreplay` is used for replaying captured packets.

## Tools and Technologies Used
- **C++ (sniff.cpp)**: Captures packets from a live network interface and extracts relevant information.
- **Python (sniffer.py, matplotlib)**: Generates a histogram of packet sizes for analysis.
- **Kali Linux**: A penetration testing OS used for packet analysis.
- **tcpreplay**: A command-line tool for replaying `.pcap` files.
- **Wireshark**: A GUI-based network protocol analyzer.
- **Rufus**: Used for creating a bootable USB to live boot Kali Linux.

## Setup and Installation

### 1. Installing Kali Linux on a USB (Live Boot Method)
- Download the Kali Linux ISO
- Use **Rufus** to create a bootable USB:
- Boot from the USB by changing the boot order in BIOS settings.
- Select "Live Mode" to run Kali Linux without installation.

### 2. Installing Required Packages
Once Kali Linux is running, install necessary tools using:
```bash
sudo apt update
sudo apt install wireshark tcpreplay libpcap-dev
pip install matplotlib
```

## Packet Capture using C++ (sniff.cpp)
The C++ program **sniff.cpp** captures live packets from a network interface, extracts details like source/destination IPs, ports, and packet sizes, and saves packet sizes to `packet_sizes.txt`.

### Code Explanation:
- Capture live packets from the pcap file.
- Extracts source and destination IPs and ports.
- Tracks packet count, data transfer, min/max size, and flow statistics.
- Saves packet sizes in `packet_sizes.txt` for later analysis.

### Compilation and Execution:
```bash
g++ sniff.cpp -o sniff -lpcap
sudo ./sniff lo
```

## Packet Analysis using Python (sniffer.py)
Python's **matplotlib** is used to generate a histogram of packet sizes.

### Code Explanation:
- Reads packet sizes from `packet_sizes.txt`.
- Uses `matplotlib.pyplot.hist()` to create a histogram.
- Saves the histogram as `packet_histogram.png`.

### Execution:
```bash
python3 sniffer.py
```

## Using tcpreplay for Packet Replay
**tcpreplay** is used to replay packets stored in a `.pcap` file on an interface:
```bash
sudo tcpreplay -i lo --mbps=100 input.pcap
```

## Using Wireshark for Packet Inspection
- Open Wireshark and load the `.pcap` file.
- Inspect different protocols, packet sizes, and timestamps.
- Apply filters to focus on specific  (e.g., STUN or MDNS).

## Live Boot Kali Linux
This method allows running Kali Linux without installing it permanently:
- **Advantages**:
  - No changes to the host system.
  - Easy to carry and use on any computer.
- **Disadvantages**:
  - Limited persistence unless configured.

## Conclusion
This project demonstrates how to capture, analyze, and replay network packets using C++ and Python in Kali Linux. Wireshark and tcpreplay provide additional insights and control over network traffic, making this approach valuable for cybersecurity and network monitoring.
## Author
Assignment by Aayan Ansari(24120020) and Gursneh Kaur(24120028). Hope you liked it!!
