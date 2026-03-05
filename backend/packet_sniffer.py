from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from collections import defaultdict, deque

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.stop_sniffing = threading.Event()
        self.thread = None
        # Track connections for "count" feature: dst_ip -> subset of timestamps
        self.connection_history = defaultdict(deque)

    def _update_count(self, dst_ip):
        now = time.time()
        timestamps = self.connection_history[dst_ip]
        timestamps.append(now)
        
        # Remove packets older than 2 seconds
        while timestamps and timestamps[0] < now - 2:
            timestamps.popleft()
            
        return len(timestamps)

    def process_packet(self, packet):
        if IP in packet:
            try:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                length = len(packet)
                
                # Protocol Mapping for ML (TCP=0, UDP=1, ICMP=2, Other=3)
                protocol_num = 3
                protocol_name = "OTHER"
                if proto == 6:
                    protocol_name = "TCP"
                    protocol_num = 0
                elif proto == 17:
                    protocol_name = "UDP"
                    protocol_num = 1
                elif proto == 1:
                    protocol_name = "ICMP"
                    protocol_num = 2

                # Calculate "Count" (Traffic Volume to this destination)
                count = self._update_count(dst_ip)

                packet_data = {
                    "source": src_ip,
                    "destination": dst_ip,
                    "protocol": protocol_name,
                    "size": length,
                    "timestamp": time.time(),
                    "summary": packet.summary() if hasattr(packet, 'summary') else "",
                    # ML Features
                    "ml_features": {
                        "protocol_type": protocol_num,
                        "src_bytes": length, # Approximation
                        "dst_bytes": 0,      # We don't track response size in this simple sniffer
                        "count": count
                    }
                }
                
                self.callback(packet_data)
            except Exception as e:
                print(f"Error processing packet: {e}")

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        
        self.stop_sniffing.clear()
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.stop_sniffing.set()

    def _sniff_loop(self):
        try:
            while not self.stop_sniffing.is_set():
                # Filter for IP packets
                sniff(prn=self.process_packet, filter="ip", store=False, timeout=1, count=10)
        except Exception as e:
            print(f"Sniffer error: {e}")
