import threading
import time
from collections import defaultdict
from scapy.all import sniff, DNS, IP
import logging

class DNSTrafficAnalyzer:
    def __init__(self, interface="enp0s3", query_threshold_per_sec=20):
        self.interface = interface
        self.query_threshold = query_threshold_per_sec
        self.client_query_counter = defaultdict(int)
        self.lock = threading.Lock()
        self.is_running = False

    def _process_packet(self, pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # 0 คือ DNS Query
            if pkt.haslayer(IP):
                client_ip = pkt[IP].src
                with self.lock:
                    self.client_query_counter[client_ip] += 1

    def _rate_monitor(self):
        while self.is_running:
            time.sleep(1.0)
            with self.lock:
                for client, count in list(self.client_query_counter.items()):
                    if count >= self.query_threshold:
                        logging.warning(f"🚨 [Scapy Alert] ตรวจพบ DNS Flood: {client} ยิง {count} req/sec")
                self.client_query_counter.clear()

    def start(self):
        self.is_running = True
        t_monitor = threading.Thread(target=self._rate_monitor, daemon=True)
        t_monitor.start()
        
        t_sniff = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_running
            ),
            daemon=True
        )
        t_sniff.start()
        logging.info("📡 Scapy DNS Packet Analyzer เริ่มดักจับแพ็กเก็ต...")

    def stop(self):
        self.is_running = False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    analyzer = DNSTrafficAnalyzer()
    analyzer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        analyzer.stop()
