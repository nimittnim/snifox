from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP
from scapy.layers.dhcp import DHCP
from scapy.layers.netbios import NBNSQueryRequest
import ipaddress
from urllib.parse import parse_qs, unquote

class Snifox_Advanced:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(self.pcap_file)
        self.phishing_ip = None
        self.username = None
        self.password = None
    
    def is_private_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def find_phishing_ip(self, target_domain="secure-bank.com"):
        for pkt in self.packets:
            if pkt.haslayer(DNSRR):
                dns = pkt[DNS]
                if dns.qr == 1:  # DNS Response
                    qname = dns.qd.qname.decode().lower() if dns.qd else ''
                    if target_domain in qname:
                        for rr in dns.an:
                            if rr.type == 1:  # A record
                                answer_ip = rr.rdata if not isinstance(rr.rdata, bytes) else rr.rdata.decode()
                                if self.is_private_ip(answer_ip):
                                    self.phishing_ip = answer_ip
                                    return self.phishing_ip
        return None

    def extract_credentials(self):
        if not self.phishing_ip:
            return None, None

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt[IP].dst == self.phishing_ip:
                if pkt.haslayer(HTTPRequest):
                    http = pkt[HTTPRequest]
                    if b'POST' in http.Method:
                        if pkt.haslayer(Raw):
                            load = pkt[Raw].load.decode('utf-8', errors='ignore')
                            body = load.split('\r\n\r\n')[-1]

                            # Try URL-encoded format
                            if 'username=' in body:
                                params = parse_qs(body)
                                self.username = unquote(params.get('username', [''])[0])
                                self.password = unquote(params.get('password', [''])[0])
                                return self.username, self.password

                            # Try JSON format
                            match = re.search(r'"username"\s*:\s*"([^"]+)"', body)
                            if match:
                                self.username = unquote(match.group(1))
                                return self.username, None
        return None, None
    
    def analyze_attacker_packets(self):
    
        attacker_info = {
            'email_address': None,
            'email_subject': None,
            'email_body': None,
            'hostname': None,
        }

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt[IP].src == self.phishing_ip:
                # Check SMTP traffic
                if pkt.haslayer(TCP) and pkt[TCP].dport == 25 and pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode()
                    if 'MAIL FROM:' in payload:
                        attacker_info['email'] = payload.split('MAIL FROM:<')[1].split('>')[0]
                    if 'Host' in payload:
                        attacker_info['hostname'] = payload.split('Host ')[1].split('\r\n')[0]
                    if 'Subject' in payload:
                        attacker_info['email_subject'] = payload.split('Subject: ')[1].split('\r\n')[0]
                    attacker_info['email_body'] = payload.split('\r\n\r\n')[1].split('\r\n.\r\n')[0]

        return attacker_info

    def analyze_pcap(self):
        self.find_phishing_ip()
        self.extract_credentials()
        result = self.analyze_attacker_packets()
        print("1. IP address of the phishing page: ", self.phishing_ip)
        print("2. username and password: of the victim are", self.username, self.password)    
        print("3. Information about the attacker:")
        print("\tName of the attacker: ", result['hostname'])
        print("\tEmail address of the attacker: ", result['email'])
        print("\tEmail subject: ", result['email_subject'])
        print("\tEmail body: ", result['email_body'])
        return 
        

if __name__ == "__main__":
    sniffer = Snifox_Advanced("6.pcap")
    sniffer.analyze_pcap()
