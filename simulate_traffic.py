"""
Skrypt do symulacji ruchu sieciowego za pomocą scapy.
Używany do demonstracji działania systemu detekcji.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap
import random
import logging
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrafficSimulator:
    """
    Generator symulowanego ruchu sieciowego.
    """
    
    def __init__(self):
        self.packets = []
    
    def generate_normal_http_traffic(self, count: int = 50):
        """
        Generuje normalny ruch HTTP.
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu HTTP...")
        
        for i in range(count):
            src_ip = f"192.168.1.{random.randint(10, 100)}"
            dst_ip = f"8.8.{random.randint(1, 255)}.{random.randint(1, 255)}"
            src_port = random.randint(49152, 65535)
            
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=src_port, dport=80) / \
                     Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            
            self.packets.append(packet)
    
    def generate_normal_https_traffic(self, count: int = 50):
        """
        Generuje normalny ruch HTTPS.
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu HTTPS...")
        
        for i in range(count):
            src_ip = f"192.168.1.{random.randint(10, 100)}"
            dst_ip = f"172.{random.randint(16, 31)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            src_port = random.randint(49152, 65535)
            
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=src_port, dport=443) / \
                     Raw(load=b"\x16\x03\x01\x00\x00")  # TLS handshake
            
            self.packets.append(packet)
    
    def generate_normal_dns_traffic(self, count: int = 30):
        """
        Generuje normalny ruch DNS.
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu DNS...")
        
        for i in range(count):
            src_ip = f"192.168.1.{random.randint(10, 100)}"
            dst_ip = "8.8.8.8"  # Google DNS
            src_port = random.randint(49152, 65535)
            
            packet = IP(src=src_ip, dst=dst_ip) / \
                     UDP(sport=src_port, dport=53) / \
                     Raw(load=b"\x00\x01")  # Uproszczone zapytanie DNS
            
            self.packets.append(packet)
    
    def generate_suspicious_port_scan(self, target_ip: str = "10.0.0.100", port_count: int = 50):
        """
        Generuje podejrzany ruch - skanowanie portów.
        Wywoła regułę PortScanDetectionRule.
        
        Args:
            target_ip: IP docelowe do skanowania
            port_count: Liczba portów do zeskanowania
        """
        logger.info(f"Generowanie skanowania portów na {target_ip}...")
        
        src_ip = "192.168.1.99"
        
        for port in range(1, port_count + 1):
            packet = IP(src=src_ip, dst=target_ip) / \
                     TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            
            self.packets.append(packet)
    
    def generate_suspicious_large_transfer(self, count: int = 20):
        """
        Generuje podejrzany ruch - duży transfer danych.
        Wywoła regułę LargeDataTransferRule.
        
        Args:
            count: Liczba dużych pakietów
        """
        logger.info(f"Generowanie dużego transferu danych...")
        
        src_ip = "192.168.1.50"
        dst_ip = "203.0.113.10"
        
        # Tworzenie dużych pakietów (każdy ~1400 bajtów)
        large_payload = b"X" * 1400
        
        for i in range(count):
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=random.randint(49152, 65535), dport=443) / \
                     Raw(load=large_payload)
            
            self.packets.append(packet)
    
    def generate_suspicious_port_4444(self, count: int = 10):
        """
        Generuje ruch do portu 4444 (Metasploit).
        Wywoła regułę SuspiciousPortRule i regułę Sigma.
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie ruchu do podejrzanego portu 4444...")
        
        src_ip = "192.168.1.75"
        dst_ip = "198.51.100.25"
        
        for i in range(count):
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=random.randint(49152, 65535), dport=4444) / \
                     Raw(load=b"SUSPICIOUS_PAYLOAD")
            
            self.packets.append(packet)
    
    def generate_dns_tunneling(self, count: int = 100):
        """
        Generuje ruch przypominający tunelowanie DNS.
        Wywoła regułę DNSTunnelingRule.
        
        Args:
            count: Liczba pakietów DNS
        """
        logger.info(f"Generowanie ruchu przypominającego tunelowanie DNS...")
        
        src_ip = "192.168.1.88"
        dst_ip = "8.8.8.8"
        src_port = random.randint(49152, 65535)
        
        for i in range(count):
            # Wysyłamy wiele małych zapytań DNS (symulacja tunelowania)
            packet = IP(src=src_ip, dst=dst_ip) / \
                     UDP(sport=src_port, dport=53) / \
                     Raw(load=f"query_{i}".encode())
            
            self.packets.append(packet)
    
    def generate_icmp_flood(self, count: int = 50):
        """
        Generuje ICMP flood.
        
        Args:
            count: Liczba pakietów ICMP
        """
        logger.info(f"Generowanie ICMP flood...")
        
        src_ip = "192.168.1.200"
        dst_ip = "10.0.0.1"
        
        for i in range(count):
            packet = IP(src=src_ip, dst=dst_ip) / \
                     ICMP(type=8, code=0) / \
                     Raw(load=b"X" * 56)
            
            self.packets.append(packet)
    
    def save_to_pcap(self, filename: str):
        """
        Zapisuje wygenerowane pakiety do pliku PCAP.
        
        Args:
            filename: Nazwa pliku wyjściowego
        """
        if not self.packets:
            logger.warning("Brak pakietów do zapisania")
            return
        
        wrpcap(filename, self.packets)
        logger.info(f"Zapisano {len(self.packets)} pakietów do pliku: {filename}")
    
    def clear_packets(self):
        """Czyści listę pakietów."""
        self.packets = []
        logger.info("Lista pakietów wyczyszczona")


def create_demo_pcap_with_alerts(output_file: str = "demo_traffic.pcap"):
    """
    Tworzy demonstracyjny plik PCAP z ruchem, który wywoła różne alerty.
    
    Args:
        output_file: Nazwa pliku wyjściowego
    """
    simulator = TrafficSimulator()
    
    # Normalny ruch
    simulator.generate_normal_http_traffic(count=30)
    simulator.generate_normal_https_traffic(count=40)
    simulator.generate_normal_dns_traffic(count=20)
    
    # Podejrzany ruch
    simulator.generate_suspicious_port_scan(target_ip="10.0.0.100", port_count=25)
    simulator.generate_suspicious_large_transfer(count=15)
    simulator.generate_suspicious_port_4444(count=8)
    simulator.generate_dns_tunneling(count=60)
    simulator.generate_icmp_flood(count=30)
    
    # Zapis do pliku
    simulator.save_to_pcap(output_file)
    
    logger.info(f"""
╔════════════════════════════════════════════════════════════════╗
║  Demonstracyjny plik PCAP został utworzony: {output_file:20s} ║
╠════════════════════════════════════════════════════════════════╣
║  Zawiera:                                                      ║
║  • Normalny ruch HTTP/HTTPS/DNS                                ║
║  • Skanowanie portów (wykryje PortScanDetectionRule)           ║
║  • Duży transfer (wykryje LargeDataTransferRule)               ║
║  • Port 4444 (wykryje SuspiciousPortRule + Sigma)              ║
║  • DNS tunneling (wykryje DNSTunnelingRule)                    ║
║  • ICMP flood                                                  ║
╚════════════════════════════════════════════════════════════════╝
""")


def create_normal_traffic_pcap(output_file: str = "normal_traffic.pcap"):
    """
    Tworzy plik PCAP z normalnym ruchem (bez alertów).
    
    Args:
        output_file: Nazwa pliku wyjściowego
    """
    simulator = TrafficSimulator()
    
    simulator.generate_normal_http_traffic(count=100)
    simulator.generate_normal_https_traffic(count=100)
    simulator.generate_normal_dns_traffic(count=50)
    
    simulator.save_to_pcap(output_file)
    
    logger.info(f"Utworzono plik z normalnym ruchem: {output_file}")


if __name__ == "__main__":
    import sys
    
    # Tworzenie demonstracyjnych plików PCAP
    create_demo_pcap_with_alerts("../data/demo_traffic.pcap")
    create_normal_traffic_pcap("../data/normal_traffic.pcap")
    
    print("\nPliki demonstracyjne zostały utworzone w katalogu data/")
    print("\nAby przetestować system, uruchom:")
    print("  python netanalyzer.py analyze data/demo_traffic.pcap -o ./test_output")
