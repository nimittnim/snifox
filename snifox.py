import socket
import struct
import time
import matplotlib.pyplot as plt
from collections import defaultdict
from scapy.all import sniff, IP, IPv6, TCP, UDP
import os

class Snifox:
    def __init__(self, duration=30, mode='raw', interface='enp0s1',results_dir = 'results'):
        self.duration = duration
        self.mode = mode
        self.interface = interface
        self.packet_sizes = []
        self.flow_data = defaultdict(int)
        self.src_flows = defaultdict(int)
        self.dst_flows = defaultdict(int)
        self.unique_pairs = set()
	self.stop_sniffing = False  
	

    def process_packet_raw(self, packet):
        eth_length = 14  # Ethernet header length
        
        if len(packet) < eth_length:
            return
        
        ip_header = packet[eth_length:20+eth_length]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        
        ttl, protocol, src_ip, dst_ip = iph[5], iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])
        src_port, dst_port = 'N/A', 'N/A'
        
        if protocol == 6 or protocol == 17:  # TCP or UDP
            tcp_udp_header = packet[eth_length + iph_length:eth_length + iph_length + 4]
            src_port, dst_port = struct.unpack('!HH', tcp_udp_header)
        
        packet_size = len(packet)
        self.packet_sizes.append(packet_size)
        
        self.src_flows[src_ip] += 1
        self.dst_flows[dst_ip] += 1
        self.flow_data[(src_ip, dst_ip)] += packet_size
        self.unique_pairs.add((src_ip, src_port, dst_ip, dst_port))
    
    def process_packet_scapy(self, packet):
       
        packet_size = len(packet)
        self.packet_sizes.append(packet_size)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = packet[IPv6].nh
        else:
            return

        src_port, dst_port = 'N/A', 'N/A'
        if TCP in packet or UDP in packet:
            src_port = packet.sport
            dst_port = packet.dport

        self.src_flows[src_ip] += 1
        self.dst_flows[dst_ip] += 1
        self.flow_data[(src_ip, src_port, dst_ip, dst_port)] += packet_size
        self.unique_pairs.add((src_ip, src_port, dst_ip, dst_port))

    def start_sniffer(self):
        print("Sniffer started...")

        if self.mode == 'raw':
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            try:
                while not self.stop_sniffing:
                    raw_packet, _ = s.recvfrom(65535)
                    self.process_packet_raw(raw_packet)
            except KeyboardInterrupt:
                print("Sniffer stopped manually.")
            finally:
                s.close()
        elif self.mode == 'scapy':
            sniff(iface=self.interface, prn=self.process_packet_scapy, store=False, timeout=self.duration)

        self.analyze_results()

    def analyze_results(self):
        total_bytes = sum(self.packet_sizes)
        total_packets = len(self.packet_sizes)
        min_size = min(self.packet_sizes) if self.packet_sizes else 0
        max_size = max(self.packet_sizes) if self.packet_sizes else 0
        avg_size = total_bytes / total_packets if total_packets > 0 else 0
        
        print(f"Total Data: {total_bytes} bytes")
        print(f"Total Packets: {total_packets}")
        print(f"Min Size: {min_size}, Max Size: {max_size}, Avg Size: {avg_size:.2f}")
        
        max_transfer_pair = max(self.flow_data, key=self.flow_data.get, default=None)
        if max_transfer_pair:
            print(f"Top Data Transfer Pair: {max_transfer_pair}: {self.flow_data[max_transfer_pair]} bytes")


        # Save histogram plot
        plt.hist(self.packet_sizes, bins=20, edgecolor='black')
        plt.xlabel("Packet Size (Bytes)")
        plt.ylabel("Frequency")
        plt.title("Packet Size Distribution")
        plt.savefig(os.path.join('results', "packet_size_distribution.png"))
        plt.close()

        # Save flow data to text files

        with open(os.path.join('results', "flow_data.txt"), "w") as f:
            for key, value in self.flow_data.items():
                f.write(f"{key}: {value}\n")
        
        with open(os.path.join('results', "src_flows.txt"), "w") as f:
            for key, value in self.src_flows.items():
                f.write(f"{key}: {value}\n")
        
        with open(os.path.join('results', "dst_flows.txt"), "w") as f:
            for key, value in self.dst_flows.items():
                f.write(f"{key}: {value}\n")

    def stop(self):
        self.stop_sniffing = True

if __name__ == "__main__":
    sniffer = Snifox()
    sniffer.start_sniffer()
