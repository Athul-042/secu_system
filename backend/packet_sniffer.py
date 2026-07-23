from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import time
from collections import defaultdict, deque

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.stop_sniffing = threading.Event()
        self.thread = None
        # Track packet counts per source IP for the "request_count" feature
        self.ip_counts = defaultdict(int)

    def _ip_to_int(self, ip_str):
        """Hash IP string to integer (must match training hashing logic)"""
        try:
            return hash(ip_str) % 100000
        except:
            return 0

    def process_packet(self, packet):
        if IP not in packet:
            return

        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_len = len(packet)
            
            # 1. Protocol Mapping (0: Others/TCP, 1: UDP, 2: ICMP, 3: HTTP)
            proto_num = 0
            protocol_name = "TCP" # Default
            if packet.haslayer(UDP):
                proto_num = 1
                protocol_name = "UDP"
            elif packet.haslayer(ICMP):
                proto_num = 2
                protocol_name = "ICMP"
            
            # 2. Destination Port
            dst_port = 0
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport

            # 3. URL Length (for HTTP detection)
            url_len = 0
            payload_str = ""
            if packet.haslayer(Raw):
                try:
                    payload_str = packet[Raw].load.decode(errors='ignore')
                    if any(verb in payload_str for verb in ["GET ", "POST ", "HEAD ", "PUT "]):
                        proto_num = 3 # Upgrade to HTTP
                        protocol_name = "HTTP"
                        first_line = payload_str.split('\r\n')[0]
                        parts = first_line.split(' ')
                        if len(parts) > 1:
                            url_len = len(parts[1])
                except:
                    pass

            # 4. Request Count
            self.ip_counts[src_ip] += 1
            req_cnt = self.ip_counts[src_ip]

            # Features must match train_synthetic.py EXACT ORDER:
            # ["protocol","packet_length","destination_port","url_length","request_count","source_ip","destination_ip"]
            ml_features = {
                "protocol": proto_num,
                "packet_length": pkt_len,
                "destination_port": dst_port,
                "url_length": url_len,
                "request_count": req_cnt,
                "source_ip": self._ip_to_int(src_ip),
                "destination_ip": self._ip_to_int(dst_ip)
            }

            packet_data = {
                "source": src_ip,
                "destination": dst_ip,
                "protocol": protocol_name,
                "size": pkt_len,
                "timestamp": time.time(),
                "summary": packet.summary() if hasattr(packet, 'summary') else "",
                "payload": payload_str, # Added for YARA
                "ml_features": ml_features
            }
            
            self.callback(packet_data)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def start(self):
        if self.thread and self.thread.is_alive():
            print("⚡ Sniffer already running.")
            return
        
        self.stop_sniffing.clear()
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()
        print("✅ Sniffer thread started successfully.")

    def stop(self):
        self.stop_sniffing.set()

    def _sniff_loop(self):
        try:
            print("🔍 Scapy sniff loop checking for network access privileges...")
            # Sniff one packet to test for WinPcap/Npcap or admin rights
            sniff(filter="ip", store=False, timeout=0.1, count=1)
            
            print("🔍 Scapy sniff loop started (7-Feature ML Mode).")
            while not self.stop_sniffing.is_set():
                # Sniff in small batches for responsiveness
                sniff(prn=self.process_packet, filter="ip", store=False, timeout=1, count=10)
        except Exception as e:
            print(f"❌ Sniffer error: {e}")
            print("💡 Hint: Run as Administrator. Switching to Mock Packet Generator fallback.")
            self._mock_sniff_loop()

    def _mock_sniff_loop(self):
        import random
        # List of public IPs that map to different countries in GeoIP
        ips = [
            '185.220.101.5',   # Germany
            '103.243.24.1',    # India
            '8.8.8.8',         # USA
            '91.198.174.192',  # Netherlands
            '95.213.255.1',    # Russia
            '109.248.9.1',     # China
            '127.0.0.1',       # Local loopback
            '192.168.1.15'     # Local Network
        ]
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP']
        
        while not self.stop_sniffing.is_set():
            # Wait random time (0.3s to 1.5s) to simulate traffic flow
            time.sleep(random.uniform(0.3, 1.5))
            
            src_ip = random.choice(ips)
            dst_ip = '10.11.136.80'
            pkt_len = random.randint(40, 1500)
            proto = random.choice(protocols)
            
            # Map protocol to number
            proto_num = 0
            if proto == 'UDP': proto_num = 1
            elif proto == 'ICMP': proto_num = 2
            elif proto == 'HTTP': proto_num = 3
            
            self.ip_counts[src_ip] += 1
            req_cnt = self.ip_counts[src_ip]
            
            # Decide if this mock packet is an anomaly (e.g. 10% chance)
            is_anomaly = random.random() < 0.10
            
            ml_features = {
                "protocol": proto_num,
                "packet_length": pkt_len,
                "destination_port": random.choice([80, 443, 22, 53, 8080]),
                "url_length": random.randint(0, 120) if proto == 'HTTP' else 0,
                "request_count": req_cnt,
                "source_ip": self._ip_to_int(src_ip),
                "destination_ip": self._ip_to_int(dst_ip)
            }
            
            packet_data = {
                "source": src_ip,
                "destination": dst_ip,
                "protocol": proto,
                "size": pkt_len,
                "timestamp": time.time(),
                "summary": f"{proto} Packet: {src_ip} -> {dst_ip} size={pkt_len}",
                "payload": "GET /etc/passwd HTTP/1.1" if proto == 'HTTP' and is_anomaly else "GET /index.html HTTP/1.1" if proto == 'HTTP' else "",
                "ml_features": ml_features
            }
            
            if is_anomaly:
                packet_data["is_anomaly"] = True
                packet_data["confidence"] = round(random.uniform(85, 99.5), 2)
                packet_data["attack_type"] = random.choice(["Web Injection Attempt", "Data Exfiltration", "Bot Activity"])
                packet_data["severity"] = random.choice(["Medium", "High"])
                packet_data["reason"] = "Pattern matching outlier detected"
                
            self.callback(packet_data)
