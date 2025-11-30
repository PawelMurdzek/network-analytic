"""
Skrypt do symulacji ruchu sieciowego za pomocą scapy.
Używany do demonstracji działania systemu detekcji.
Zawiera realistyczne scenariusze ataków: APT, Ransomware, C2, Exfiltration.
"""

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap, Ether
import random
import logging
from typing import List
from datetime import datetime, timedelta
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# REALISTYCZNE ADRESY IP (publiczne zakresy dokumentacyjne + znane "złe" IP)
# ============================================================================

# RFC 5737 - Zakresy dokumentacyjne (bezpieczne do testów)
INTERNAL_NETWORK = "192.168.1.{}"
INTERNAL_SERVERS = ["192.168.1.1", "192.168.1.10", "192.168.1.20", "192.168.1.254"]

# Realistyczne zewnętrzne IP (zakresy testowe)
LEGITIMATE_SERVICES = {
    "google_dns": ["8.8.8.8", "8.8.4.4"],
    "cloudflare_dns": ["1.1.1.1", "1.0.0.1"],
    "microsoft": ["13.107.21.200", "204.79.197.200"],
    "amazon": ["52.94.236.248", "54.239.28.85"],
    "github": ["140.82.121.4", "140.82.121.3"],
}

# Symulowane złośliwe IP (zakresy dokumentacyjne RFC 5737)
MALICIOUS_IPS = {
    "c2_servers": ["203.0.113.66", "203.0.113.100", "203.0.113.200"],
    "tor_exit_nodes": ["198.51.100.10", "198.51.100.20", "198.51.100.30"],
    "known_botnet": ["198.51.100.50", "198.51.100.51", "198.51.100.52"],
    "ransomware_c2": ["203.0.113.13", "203.0.113.31"],
    "apt_infrastructure": ["198.51.100.99", "203.0.113.88"],
}

# Podejrzane porty
SUSPICIOUS_PORTS = {
    "metasploit": 4444,
    "cobalt_strike": 50050,
    "empire": 8443,
    "reverse_shell": [4444, 5555, 6666, 1337],
    "crypto_mining": [3333, 14444, 45700],
}


class TrafficSimulator:
    """
    Generator symulowanego ruchu sieciowego z realistycznymi scenariuszami.
    """
    
    def __init__(self):
        self.packets = []
        self.timestamp = datetime.now()
    
    def _get_random_internal_ip(self) -> str:
        """Losowy adres z sieci wewnętrznej."""
        return INTERNAL_NETWORK.format(random.randint(10, 200))
    
    def _get_random_legitimate_ip(self) -> str:
        """Losowy legalny adres zewnętrzny."""
        category = random.choice(list(LEGITIMATE_SERVICES.keys()))
        return random.choice(LEGITIMATE_SERVICES[category])
    
    def _advance_time(self, seconds: float = 0.1):
        """Przesuwa znacznik czasu."""
        self.timestamp += timedelta(seconds=seconds)
        return self.timestamp.timestamp()
    
    def generate_normal_http_traffic(self, count: int = 50):
        """
        Generuje normalny ruch HTTP do legalnych serwisów.
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu HTTP...")
        
        websites = [
            ("www.google.com", "8.8.8.8"),
            ("www.github.com", "140.82.121.4"),
            ("www.microsoft.com", "13.107.21.200"),
            ("www.amazon.com", "52.94.236.248"),
        ]
        
        for i in range(count):
            src_ip = self._get_random_internal_ip()
            site_name, dst_ip = random.choice(websites)
            src_port = random.randint(49152, 65535)
            
            # Request
            http_request = f"GET / HTTP/1.1\r\nHost: {site_name}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=src_port, dport=80, flags="PA") / \
                     Raw(load=http_request.encode())
            packet.time = self._advance_time(random.uniform(0.01, 0.5))
            self.packets.append(packet)
    
    def generate_normal_https_traffic(self, count: int = 50):
        """
        Generuje normalny ruch HTTPS (TLS).
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu HTTPS...")
        
        for i in range(count):
            src_ip = self._get_random_internal_ip()
            dst_ip = self._get_random_legitimate_ip()
            src_port = random.randint(49152, 65535)
            
            # Symulacja TLS Client Hello
            tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0xf1]) + b'\x01' + bytes(random.randint(50, 200))
            
            packet = IP(src=src_ip, dst=dst_ip) / \
                     TCP(sport=src_port, dport=443, flags="PA") / \
                     Raw(load=tls_hello)
            packet.time = self._advance_time(random.uniform(0.01, 0.3))
            self.packets.append(packet)
    
    def generate_normal_dns_traffic(self, count: int = 30):
        """
        Generuje normalny ruch DNS do publicznych resolverów.
        
        Args:
            count: Liczba pakietów do wygenerowania
        """
        logger.info(f"Generowanie {count} pakietów normalnego ruchu DNS...")
        
        domains = [
            "www.google.com", "mail.google.com", "drive.google.com",
            "github.com", "api.github.com",
            "microsoft.com", "login.microsoftonline.com",
            "aws.amazon.com", "s3.amazonaws.com"
        ]
        
        dns_servers = LEGITIMATE_SERVICES["google_dns"] + LEGITIMATE_SERVICES["cloudflare_dns"]
        
        for i in range(count):
            src_ip = self._get_random_internal_ip()
            dst_ip = random.choice(dns_servers)
            src_port = random.randint(49152, 65535)
            domain = random.choice(domains)
            
            # Uproszczone zapytanie DNS
            packet = IP(src=src_ip, dst=dst_ip) / \
                     UDP(sport=src_port, dport=53) / \
                     DNS(rd=1, qd=DNSQR(qname=domain))
            packet.time = self._advance_time(random.uniform(0.001, 0.1))
            self.packets.append(packet)
    
    def generate_suspicious_port_scan(self, target_ip: str = "192.168.1.20", port_count: int = 50):
        """
        Generuje realistyczne skanowanie portów (SYN scan).
        Wywoła regułę PortScanDetectionRule.
        
        Args:
            target_ip: IP docelowe do skanowania
            port_count: Liczba portów do zeskanowania
        """
        logger.info(f"Generowanie skanowania portów na {target_ip}...")
        
        attacker_ip = "192.168.1.99"  # Zainfekowany host wewnętrzny
        
        # Typowe porty skanowane przez nmap
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                       993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        ports_to_scan = common_ports[:port_count] if port_count <= len(common_ports) else \
                       common_ports + list(range(1, port_count - len(common_ports) + 1))
        
        for port in ports_to_scan:
            # SYN packet (typowy dla nmap -sS)
            packet = IP(src=attacker_ip, dst=target_ip) / \
                     TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            packet.time = self._advance_time(random.uniform(0.001, 0.01))  # Szybkie skanowanie
            self.packets.append(packet)
    
    def generate_suspicious_large_transfer(self, count: int = 20):
        """
        Generuje podejrzany duży transfer danych (potencjalna eksfiltracja).
        Wywoła regułę LargeDataTransferRule.
        
        Args:
            count: Liczba dużych pakietów
        """
        logger.info(f"Generowanie dużego transferu danych (eksfiltracja)...")
        
        infected_host = "192.168.1.50"
        exfil_server = MALICIOUS_IPS["c2_servers"][0]
        
        # Symulacja eksfiltracji wrażliwych danych
        sensitive_data_patterns = [
            b"password=", b"credit_card:", b"ssn:", b"api_key=",
            b"BEGIN RSA PRIVATE KEY", b"AWS_SECRET_ACCESS_KEY"
        ]
        
        for i in range(count):
            # Duży payload z "wrażliwymi" danymi
            payload = random.choice(sensitive_data_patterns) + bytes(random.randint(1000, 1400))
            
            packet = IP(src=infected_host, dst=exfil_server) / \
                     TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") / \
                     Raw(load=payload)
            packet.time = self._advance_time(random.uniform(0.1, 0.5))
            self.packets.append(packet)
    
    def generate_suspicious_port_4444(self, count: int = 10):
        """
        Generuje ruch do portu 4444 (Metasploit reverse shell).
        Wywoła regułę SuspiciousPortRule i regułę Sigma.
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie ruchu do podejrzanego portu 4444 (Metasploit)...")
        
        victim_ip = "192.168.1.75"
        c2_server = MALICIOUS_IPS["c2_servers"][1]
        
        for i in range(count):
            # Meterpreter-like payload
            payload = b"\x00\x00\x00\x00" + struct.pack(">I", random.randint(1, 1000)) + b"METERPRETER"
            
            packet = IP(src=victim_ip, dst=c2_server) / \
                     TCP(sport=random.randint(49152, 65535), dport=4444, flags="PA") / \
                     Raw(load=payload)
            packet.time = self._advance_time(random.uniform(0.5, 2.0))
            self.packets.append(packet)
    
    def generate_dns_tunneling(self, count: int = 100):
        """
        Generuje realistyczne tunelowanie DNS (dane zakodowane w zapytaniach).
        Wywoła regułę DNSTunnelingRule.
        
        Args:
            count: Liczba pakietów DNS
        """
        logger.info(f"Generowanie tunelowania DNS...")
        
        infected_host = "192.168.1.88"
        dns_server = "8.8.8.8"
        
        # Domena C2 z zakodowanymi danymi
        c2_domain = "data.evil-c2.example.com"
        
        for i in range(count):
            # Zakodowane dane w subdomenie (typowe dla DNS tunneling)
            encoded_data = ''.join(random.choices('abcdef0123456789', k=random.randint(30, 60)))
            tunnel_domain = f"{encoded_data}.{c2_domain}"
            
            packet = IP(src=infected_host, dst=dns_server) / \
                     UDP(sport=random.randint(49152, 65535), dport=53) / \
                     DNS(rd=1, qd=DNSQR(qname=tunnel_domain))
            packet.time = self._advance_time(random.uniform(0.01, 0.1))
            self.packets.append(packet)
    
    def generate_icmp_flood(self, count: int = 50):
        """
        Generuje ICMP flood (ping flood DDoS).
        
        Args:
            count: Liczba pakietów ICMP
        """
        logger.info(f"Generowanie ICMP flood...")
        
        attacker_ip = "192.168.1.200"
        target_ip = INTERNAL_SERVERS[0]
        
        for i in range(count):
            packet = IP(src=attacker_ip, dst=target_ip) / \
                     ICMP(type=8, code=0) / \
                     Raw(load=b"X" * 56)
            packet.time = self._advance_time(0.001)  # Bardzo szybko
            self.packets.append(packet)
    
    # ========================================================================
    # NOWE SCENARIUSZE ATAKÓW
    # ========================================================================
    
    def generate_cobalt_strike_beacon(self, count: int = 20):
        """
        Symuluje komunikację Cobalt Strike beacon z C2.
        Charakterystyczne: regularne połączenia, nietypowe User-Agenty.
        
        Args:
            count: Liczba pakietów beacon
        """
        logger.info(f"Generowanie ruchu Cobalt Strike beacon...")
        
        infected_host = "192.168.1.45"
        c2_server = MALICIOUS_IPS["apt_infrastructure"][0]
        
        for i in range(count):
            # Beacon heartbeat - HTTP GET z charakterystycznym patternem
            beacon_path = f"/pixel.gif?id={random.randint(100000, 999999)}"
            http_request = f"GET {beacon_path} HTTP/1.1\r\n"
            http_request += f"Host: cdn-images.{random.randint(1,99)}.com\r\n"
            http_request += "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\r\n"
            http_request += f"Cookie: SESSIONID={random.randbytes(16).hex()}\r\n\r\n"
            
            packet = IP(src=infected_host, dst=c2_server) / \
                     TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") / \
                     Raw(load=http_request.encode())
            # Regularne interwały (typowe dla beacon)
            packet.time = self._advance_time(random.uniform(55, 65))  # ~60 sekund
            self.packets.append(packet)
    
    def generate_ransomware_activity(self, count: int = 30):
        """
        Symuluje aktywność ransomware:
        - Połączenia do C2 po klucz szyfrowania
        - Duży ruch wewnętrzny (szyfrowanie udziałów SMB)
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie aktywności ransomware...")
        
        infected_host = "192.168.1.60"
        ransomware_c2 = MALICIOUS_IPS["ransomware_c2"][0]
        
        # Faza 1: Pobranie klucza z C2
        key_request = b"POST /api/getkey HTTP/1.1\r\nHost: payment.onion\r\n\r\n"
        key_request += b'{"victim_id": "' + random.randbytes(8).hex().encode() + b'"}'
        
        packet = IP(src=infected_host, dst=ransomware_c2) / \
                 TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") / \
                 Raw(load=key_request)
        packet.time = self._advance_time(0.1)
        self.packets.append(packet)
        
        # Faza 2: Skanowanie i szyfrowanie udziałów SMB
        for i in range(count - 1):
            target_server = random.choice(INTERNAL_SERVERS)
            
            # SMB traffic (port 445)
            smb_payload = b"\x00\x00\x00\x55\xffSMB" + random.randbytes(80)
            
            packet = IP(src=infected_host, dst=target_server) / \
                     TCP(sport=random.randint(49152, 65535), dport=445, flags="PA") / \
                     Raw(load=smb_payload)
            packet.time = self._advance_time(random.uniform(0.01, 0.1))
            self.packets.append(packet)
    
    def generate_lateral_movement(self, count: int = 25):
        """
        Symuluje ruch boczny (lateral movement) w sieci:
        - Próby RDP, SSH, WMI
        - Skanowanie wewnętrzne
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie ruchu bocznego (lateral movement)...")
        
        compromised_host = "192.168.1.30"
        
        # Próby połączenia z różnymi hostami wewnętrznymi
        lateral_ports = [
            (3389, "RDP"),
            (22, "SSH"),
            (135, "WMI/RPC"),
            (5985, "WinRM"),
            (445, "SMB"),
        ]
        
        for i in range(count):
            target_ip = INTERNAL_NETWORK.format(random.randint(1, 254))
            port, service = random.choice(lateral_ports)
            
            # SYN do próby połączenia
            packet = IP(src=compromised_host, dst=target_ip) / \
                     TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            packet.time = self._advance_time(random.uniform(0.1, 1.0))
            self.packets.append(packet)
    
    def generate_crypto_mining(self, count: int = 40):
        """
        Symuluje ruch cryptominera:
        - Połączenia do puli mining
        - Charakterystyczne porty i payloady
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie ruchu cryptomining...")
        
        miner_host = "192.168.1.120"
        mining_pool = MALICIOUS_IPS["known_botnet"][0]
        mining_port = random.choice(SUSPICIOUS_PORTS["crypto_mining"])
        
        for i in range(count):
            # Stratum mining protocol
            if i == 0:
                # Subscribe
                payload = b'{"id": 1, "method": "mining.subscribe", "params": []}\n'
            elif i == 1:
                # Authorize
                payload = b'{"id": 2, "method": "mining.authorize", "params": ["wallet.worker", "x"]}\n'
            else:
                # Submit share
                nonce = random.randbytes(4).hex()
                payload = f'{{"id": {i}, "method": "mining.submit", "params": ["wallet.worker", "job_id", "{nonce}"]}}\n'.encode()
            
            packet = IP(src=miner_host, dst=mining_pool) / \
                     TCP(sport=random.randint(49152, 65535), dport=mining_port, flags="PA") / \
                     Raw(load=payload)
            packet.time = self._advance_time(random.uniform(1, 5))
            self.packets.append(packet)
    
    def generate_tor_traffic(self, count: int = 15):
        """
        Symuluje ruch przez sieć Tor (połączenia z exit nodes).
        
        Args:
            count: Liczba pakietów
        """
        logger.info(f"Generowanie ruchu Tor...")
        
        internal_host = "192.168.1.180"
        
        for i in range(count):
            tor_node = random.choice(MALICIOUS_IPS["tor_exit_nodes"])
            tor_port = random.choice([9001, 9030, 9050, 9150])
            
            # TLS-like payload
            packet = IP(src=internal_host, dst=tor_node) / \
                     TCP(sport=random.randint(49152, 65535), dport=tor_port, flags="PA") / \
                     Raw(load=b"\x16\x03\x01" + random.randbytes(100))
            packet.time = self._advance_time(random.uniform(0.5, 2.0))
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
        self.timestamp = datetime.now()
        logger.info("Lista pakietów wyczyszczona")
    
    def get_packet_summary(self) -> dict:
        """Zwraca podsumowanie wygenerowanych pakietów."""
        summary = {
            "total_packets": len(self.packets),
            "protocols": {},
            "src_ips": set(),
            "dst_ips": set(),
        }
        
        for pkt in self.packets:
            if IP in pkt:
                summary["src_ips"].add(pkt[IP].src)
                summary["dst_ips"].add(pkt[IP].dst)
                
                if TCP in pkt:
                    summary["protocols"]["TCP"] = summary["protocols"].get("TCP", 0) + 1
                elif UDP in pkt:
                    summary["protocols"]["UDP"] = summary["protocols"].get("UDP", 0) + 1
                elif ICMP in pkt:
                    summary["protocols"]["ICMP"] = summary["protocols"].get("ICMP", 0) + 1
        
        summary["src_ips"] = len(summary["src_ips"])
        summary["dst_ips"] = len(summary["dst_ips"])
        
        return summary


def create_demo_pcap_with_alerts(output_file: str = "demo_traffic.pcap"):
    """
    Tworzy demonstracyjny plik PCAP z ruchem wywołującym różne alerty.
    Zawiera realistyczne scenariusze ataków.
    
    Args:
        output_file: Nazwa pliku wyjściowego
    """
    simulator = TrafficSimulator()
    
    # ===== Normalny ruch (baseline) =====
    simulator.generate_normal_http_traffic(count=50)
    simulator.generate_normal_https_traffic(count=60)
    simulator.generate_normal_dns_traffic(count=40)
    
    # ===== Scenariusze ataków =====
    
    # 1. Rekonesans - skanowanie portów
    simulator.generate_suspicious_port_scan(target_ip="192.168.1.20", port_count=30)
    
    # 2. Initial Access - podejrzane porty (Metasploit)
    simulator.generate_suspicious_port_4444(count=10)
    
    # 3. C2 Communication - Cobalt Strike beacon
    simulator.generate_cobalt_strike_beacon(count=15)
    
    # 4. Lateral Movement
    simulator.generate_lateral_movement(count=20)
    
    # 5. Data Exfiltration
    simulator.generate_suspicious_large_transfer(count=20)
    simulator.generate_dns_tunneling(count=80)
    
    # 6. Ransomware Activity
    simulator.generate_ransomware_activity(count=25)
    
    # 7. Crypto Mining
    simulator.generate_crypto_mining(count=30)
    
    # 8. Tor Traffic
    simulator.generate_tor_traffic(count=10)
    
    # 9. DoS
    simulator.generate_icmp_flood(count=40)
    
    # Zapis do pliku
    simulator.save_to_pcap(output_file)
    
    summary = simulator.get_packet_summary()
    
    logger.info(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  DEMONSTRACYJNY PLIK PCAP UTWORZONY                                      ║
║  Plik: {output_file:<60} ║
╠══════════════════════════════════════════════════════════════════════════╣
║  STATYSTYKI:                                                             ║
║  • Pakiety: {summary['total_packets']:<10} • Src IPs: {summary['src_ips']:<10} • Dst IPs: {summary['dst_ips']:<10}   ║
╠══════════════════════════════════════════════════════════════════════════╣
║  SCENARIUSZE ATAKOW (MITRE ATT&CK):                                      ║
║  ├─ T1046 Network Service Scanning (port scan)                          ║
║  ├─ T1571 Non-Standard Port (Metasploit 4444)                           ║
║  ├─ T1071 Application Layer Protocol (Cobalt Strike)                    ║
║  ├─ T1021 Remote Services (lateral movement)                            ║
║  ├─ T1048 Exfiltration Over Alternative Protocol (DNS tunneling)        ║
║  ├─ T1486 Data Encrypted for Impact (ransomware)                        ║
║  ├─ T1496 Resource Hijacking (crypto mining)                            ║
║  └─ T1090 Proxy (Tor traffic)                                           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  [OK] NORMALNE USLUGI:                                                   ║
║  • HTTP/HTTPS do Google, GitHub, Microsoft, Amazon                      ║
║  • DNS do 8.8.8.8, 1.1.1.1                                               ║
╚══════════════════════════════════════════════════════════════════════════╝
""")


def create_normal_traffic_pcap(output_file: str = "normal_traffic.pcap"):
    """
    Tworzy plik PCAP z normalnym ruchem (bez alertów).
    
    Args:
        output_file: Nazwa pliku wyjściowego
    """
    simulator = TrafficSimulator()
    
    simulator.generate_normal_http_traffic(count=150)
    simulator.generate_normal_https_traffic(count=150)
    simulator.generate_normal_dns_traffic(count=80)
    
    simulator.save_to_pcap(output_file)
    
    logger.info(f"[OK] Utworzono plik z normalnym ruchem: {output_file}")


def create_apt_scenario_pcap(output_file: str = "apt_attack.pcap"):
    """
    Tworzy plik PCAP symulujący pełny scenariusz ataku APT.
    Fazy: Rekonesans → Initial Access → C2 → Lateral Movement → Exfiltration
    
    Args:
        output_file: Nazwa pliku wyjściowego
    """
    simulator = TrafficSimulator()
    
    logger.info("Generowanie scenariusza APT...")
    
    # Faza 0: Normalny ruch w tle
    simulator.generate_normal_https_traffic(count=30)
    simulator.generate_normal_dns_traffic(count=20)
    
    # Faza 1: Rekonesans (skanowanie)
    logger.info("  [1/5] Rekonesans...")
    simulator.generate_suspicious_port_scan(port_count=50)
    
    # Faza 2: Initial Access (exploit + reverse shell)
    logger.info("  [2/5] Initial Access...")
    simulator.generate_suspicious_port_4444(count=5)
    
    # Więcej normalnego ruchu
    simulator.generate_normal_https_traffic(count=20)
    
    # Faza 3: C2 Communication
    logger.info("  [3/5] C2 Communication...")
    simulator.generate_cobalt_strike_beacon(count=20)
    
    # Faza 4: Lateral Movement
    logger.info("  [4/5] Lateral Movement...")
    simulator.generate_lateral_movement(count=30)
    
    # Faza 5: Data Exfiltration
    logger.info("  [5/5] Data Exfiltration...")
    simulator.generate_suspicious_large_transfer(count=30)
    simulator.generate_dns_tunneling(count=100)
    
    simulator.save_to_pcap(output_file)
    
    logger.info(f"[OK] Scenariusz APT zapisany: {output_file}")


if __name__ == "__main__":
    import sys
    import os
    
    # Upewnij się że katalog data istnieje
    os.makedirs("data", exist_ok=True)
    
    # Tworzenie demonstracyjnych plików PCAP
    create_demo_pcap_with_alerts("data/demo_traffic.pcap")
    create_normal_traffic_pcap("data/normal_traffic.pcap")
    create_apt_scenario_pcap("data/apt_attack.pcap")
    
    print("\n" + "="*70)
    print("  PLIKI DEMONSTRACYJNE UTWORZONE W KATALOGU data/")
    print("="*70)
    print("""
  Dostepne pliki:
  |- demo_traffic.pcap    - Mieszanka normalnego ruchu i atakow
  |- normal_traffic.pcap  - Tylko normalny ruch (baseline)
  |- apt_attack.pcap      - Pelny scenariusz ataku APT

  Aby przetestowac system, uruchom:
     python netanalyzer.py analyze data/demo_traffic.pcap -o ./output
    """)
