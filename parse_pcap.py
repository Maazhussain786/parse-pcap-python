"""
=========================================================
Computer Networks - Assignment 1
PCAP File Parsing and Analysis using Python (Scapy)
=========================================================

Submitted by:
- Maaz Hussain (532844) - BSCS14-B
- Muhammad Abdul Daym (507605) -BSCS14-B

Description:
------------
This Python program parses `.pcap` files (captured with Wireshark or provided test files)
and performs basic network traffic analysis. It is an alternative solution to the 
starter Java code (ParsePCAP.java) that uses jNetPcap.

Main Features:
--------------
1. Reads packets from a PCAP file.
2. Extracts TCP and UDP destination ports.
3. Builds a list of all destination ports observed in the capture.
4. Removes duplicates to get unique destination ports.
5. Counts frequency of each port (e.g., Port 443 -> 1514 packets).
6. Extracts destination IP + port pairs to identify which servers were contacted.
7. Prints results in a structured and easy-to-read format.

Why This is Useful:
-------------------
- Helps understand which services/applications are being used in the captured traffic.
- Example: 
  - Port 80 -> HTTP (web traffic)
  - Port 443 -> HTTPS (secure web traffic)
  - Port 53 -> DNS queries
  - Port 6881 -> BitTorrent traffic
- Students can analyze their own network captures and compare traffic patterns.

Student Tasks (Extended from Assignment):
-----------------------------------------
- Capture your own traffic in Wireshark and run it through this program.
- Save the results (ports, frequencies, IPs) for your report.
- Compare traffic patterns between sample PCAP (slowdownload.pcap) and your own capture.

Dependencies:
-------------
- Python 3.x
- scapy (pip install scapy)

Usage:
------
Update the filename path in the code or run the script directly:

    python parse_pcap.py
Example Output:
---------------
=== Unique Destination Ports ===
53, 67, 80, 137, 443, 5353, 6881
=== Port Frequencies ===
Port 443   -> 1514 packets
Port 80    -> 744 packets
Port 53    -> 74 packets
...
=== Top 20 Destination IPs + Ports ===
8.8.8.8:53          -> 74 packets
185.199.108.133:443 -> 333 packets
...



Github Repo : https://github.com/Maazhussain786/parse-pcap-python

=========================================================
"""


from scapy.all import rdpcap
from collections import Counter

def parse_pcap(filename, top_n=20):
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"Error: PCAP file not found -> {filename}")
        return
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return

    ports = []
    ip_ports = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            dst_ip = pkt["IP"].dst
            if pkt.haslayer("TCP"):
                ports.append(pkt["TCP"].dport)
                ip_ports.append((dst_ip, pkt["TCP"].dport))
            elif pkt.haslayer("UDP"):
                ports.append(pkt["UDP"].dport)
                ip_ports.append((dst_ip, pkt["UDP"].dport))

    if not ports:
        print("No TCP/UDP ports found in the capture.")
        return

    # Unique Ports
    unique_ports = sorted(set(ports))
    print("\n=== Unique Destination Ports ===")
    print(", ".join(map(str, unique_ports)))

    # Frequency Count
    print("\n=== Port Frequencies ===")
    for port, count in sorted(Counter(ports).items(), key=lambda x: -x[1])[:top_n]:
        print(f"Port {port:<5} -> {count} packets")

    # Destination IP + Port (Top N)
    print(f"\n=== Top {top_n} Destination IPs + Ports ===")
    for (ip, port), count in Counter(ip_ports).most_common(top_n):
        print(f"{ip}:{port} -> {count} packets")

if __name__ == "__main__":
    parse_pcap(r"D:\CN\assignment_1_solution\tests\my_own_wireshark.pcap")
