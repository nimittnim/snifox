import socket
import struct
import time
import matplotlib.pyplot as plt
from collections import defaultdict

# Global storage
packet_sizes = []
flow_data = defaultdict(int)
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
unique_pairs = set()

def process_packet(packet):
    global packet_sizes
    eth_length = 14  # Ethernet header length
    
    if len(packet) < eth_length:
        return
    
    ip_header = packet[eth_length:20+eth_length]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    
    ttl, protocol, src_ip, dst_ip = iph[5], iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])
    src_port, dst_port = 'N/A', 'N/A'
    
    if protocol == 6 or protocol == 17:  # TCP or UDP
        tcp_udp_header = packet[eth_length + iph_length:eth_length + iph_length + 4]
        src_port, dst_port = struct.unpack('!HH', tcp_udp_header)
    
    packet_size = len(packet)
    packet_sizes.append(packet_size)
    
    src_flows[src_ip] += 1
    dst_flows[dst_ip] += 1
    flow_data[(src_ip, dst_ip)] += packet_size
    unique_pairs.add((src_ip, src_port, dst_ip, dst_port))
    

def start_sniffer():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Sniffer started...")
    start_time = time.time()
    
    try:
        while time.time() - start_time < 30:  # Run for 30 seconds
            raw_packet, _ = s.recvfrom(65535)
            process_packet(raw_packet)
    except KeyboardInterrupt:
        print("Sniffer stopped manually.")
    finally:
        s.close()
    
    analyze_results()

def analyze_results():
    total_bytes = sum(packet_sizes)
    total_packets = len(packet_sizes)
    min_size = min(packet_sizes) if packet_sizes else 0
    max_size = max(packet_sizes) if packet_sizes else 0
    avg_size = total_bytes / total_packets if total_packets > 0 else 0
    
    print(f"Total Data: {total_bytes} bytes")
    print(f"Total Packets: {total_packets}")
    print(f"Min Size: {min_size}, Max Size: {max_size}, Avg Size: {avg_size:.2f}")
    
    print("\nTop Data Transfer Pairs:")
    max_transfer_pair = max(flow_data, key=flow_data.get, default=None)
    if max_transfer_pair:
        print(f"{max_transfer_pair}: {flow_data[max_transfer_pair]} bytes")
    
    print("\nPacket Size Distribution Histogram:")
    plt.hist(packet_sizes, bins=20, edgecolor='black')
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.show()
    
if __name__ == "__main__":
    start_sniffer()
