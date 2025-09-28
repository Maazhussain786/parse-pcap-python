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
