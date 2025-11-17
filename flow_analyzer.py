"""
Moduł do analizy ruchu sieciowego na poziomie flow z wykorzystaniem Scapy.
Alternatywa dla NFStream na Windows.
"""

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlowAnalyzer:
    """
    Klasa do analizy przepływów sieciowych z plików PCAP używając Scapy.
    """
    
    def __init__(self, pcap_file: str):
        """
        Inicjalizacja analizatora flow.
        
        Args:
            pcap_file: Ścieżka do pliku PCAP
        """
        self.pcap_file = pcap_file
        self.flows_df = None
        
    def load_flows(self) -> pd.DataFrame:
        """
        Wczytanie przepływów z pliku PCAP przy użyciu Scapy.
        
        Returns:
            DataFrame z przepływami sieciowymi
        """
        logger.info(f"Wczytywanie przepływów z pliku: {self.pcap_file}")
        
        try:
            # Wczytanie pakietów
            packets = rdpcap(self.pcap_file)
            logger.info(f"Wczytano {len(packets)} pakietów")
            
            # Grupowanie pakietów w przepływy (5-tuple)
            flows_dict = defaultdict(lambda: {
                'src_ip': None,
                'dst_ip': None,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 0,
                'bidirectional_packets': 0,
                'bidirectional_bytes': 0,
                'src2dst_packets': 0,
                'src2dst_bytes': 0,
                'dst2src_packets': 0,
                'dst2src_bytes': 0,
                'bidirectional_duration_ms': 0,
                'src2dst_duration_ms': 0,
                'dst2src_duration_ms': 0,
                'application_name': 'Unknown',
                'application_category_name': 'Unknown',
                'first_time': None,
                'last_time': None,
            })
            
            # Przetwarzanie pakietów
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    protocol = pkt[IP].proto
                    
                    src_port = 0
                    dst_port = 0
                    
                    # Wyciągnięcie portów
                    if TCP in pkt:
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        protocol = 6  # TCP
                    elif UDP in pkt:
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        protocol = 17  # UDP
                    
                    # Klucz przepływu (5-tuple)
                    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                    reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)
                    
                    # Sprawdzenie czy to nowy przepływ czy powrotny
                    if flow_key in flows_dict:
                        key = flow_key
                        direction = 'forward'
                    elif reverse_key in flows_dict:
                        key = reverse_key
                        direction = 'reverse'
                    else:
                        key = flow_key
                        direction = 'forward'
                        flows_dict[key]['src_ip'] = src_ip
                        flows_dict[key]['dst_ip'] = dst_ip
                        flows_dict[key]['src_port'] = src_port
                        flows_dict[key]['dst_port'] = dst_port
                        flows_dict[key]['protocol'] = protocol
                        flows_dict[key]['first_time'] = pkt.time
                    
                    # Aktualizacja statystyk przepływu
                    pkt_len = len(pkt)
                    flows_dict[key]['bidirectional_packets'] += 1
                    flows_dict[key]['bidirectional_bytes'] += pkt_len
                    flows_dict[key]['last_time'] = pkt.time
                    
                    if direction == 'forward':
                        flows_dict[key]['src2dst_packets'] += 1
                        flows_dict[key]['src2dst_bytes'] += pkt_len
                    else:
                        flows_dict[key]['dst2src_packets'] += 1
                        flows_dict[key]['dst2src_bytes'] += pkt_len
                    
                    # Prosta detekcja aplikacji na podstawie portu
                    if flows_dict[key]['application_name'] == 'Unknown':
                        flows_dict[key]['application_name'] = self._guess_application(dst_port)
                        flows_dict[key]['application_category_name'] = self._guess_category(dst_port)
            
            # Obliczenie czasu trwania
            for flow in flows_dict.values():
                if flow['first_time'] and flow['last_time']:
                    duration_ms = (flow['last_time'] - flow['first_time']) * 1000
                    flow['bidirectional_duration_ms'] = duration_ms
                    flow['src2dst_duration_ms'] = duration_ms
                    flow['dst2src_duration_ms'] = duration_ms
            
            # Konwersja do DataFrame
            flows = []
            for flow_data in flows_dict.values():
                # Usunięcie pomocniczych pól
                flow_data.pop('first_time', None)
                flow_data.pop('last_time', None)
                flows.append(flow_data)
            
            self.flows_df = pd.DataFrame(flows)
            logger.info(f"Utworzono {len(self.flows_df)} przepływów")
            
            return self.flows_df
            
        except Exception as e:
            logger.error(f"Błąd podczas wczytywania przepływów: {e}")
            raise
    
    def _guess_application(self, port: int) -> str:
        """Prosta detekcja aplikacji na podstawie portu"""
        port_map = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3389: 'RDP',
            445: 'SMB',
            135: 'RPC',
            139: 'NetBIOS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            4444: 'Metasploit',
        }
        return port_map.get(port, 'Unknown')
    
    def _guess_category(self, port: int) -> str:
        """Kategoryzacja aplikacji"""
        web_ports = {80, 443, 8080, 8443}
        db_ports = {3306, 5432, 6379, 1433, 5984}
        
        if port in web_ports:
            return 'Web'
        elif port in db_ports:
            return 'Database'
        elif port == 53:
            return 'Network'
        elif port in {22, 23, 3389}:
            return 'RemoteAccess'
        else:
            return 'Unknown'
    
    def get_flow_statistics(self) -> Dict:
        """
        Generowanie statystyk przepływów sieciowych.
        
        Returns:
            Słownik ze statystykami
        """
        if self.flows_df is None:
            raise ValueError("Najpierw wczytaj przepływy używając load_flows()")
        
        stats = {
            'total_flows': len(self.flows_df),
            'unique_src_ips': self.flows_df['src_ip'].nunique(),
            'unique_dst_ips': self.flows_df['dst_ip'].nunique(),
            'total_packets': int(self.flows_df['bidirectional_packets'].sum()),
            'total_bytes': int(self.flows_df['bidirectional_bytes'].sum()),
            'avg_packets_per_flow': float(self.flows_df['bidirectional_packets'].mean()),
            'avg_bytes_per_flow': float(self.flows_df['bidirectional_bytes'].mean()),
            'protocols': self.flows_df['protocol'].value_counts().to_dict(),
            'top_applications': self.flows_df['application_name'].value_counts().head(10).to_dict(),
        }
        
        # Statystyki komunikacji między hostami
        host_communication = self.flows_df.groupby(['src_ip', 'dst_ip']).agg({
            'bidirectional_packets': 'sum',
            'bidirectional_bytes': 'sum',
            'protocol': 'count'
        }).reset_index()
        
        host_communication.columns = ['src_ip', 'dst_ip', 'total_packets', 'total_bytes', 'flow_count']
        host_communication = host_communication.sort_values('total_packets', ascending=False)
        
        stats['top_host_pairs'] = host_communication.head(10).to_dict('records')
        
        return stats
    
    def get_flows_dataframe(self) -> pd.DataFrame:
        """
        Zwraca DataFrame z przepływami.
        
        Returns:
            DataFrame z przepływami
        """
        if self.flows_df is None:
            raise ValueError("Najpierw wczytaj przepływy używając load_flows()")
        
        return self.flows_df
    
    def filter_flows(self, **kwargs) -> pd.DataFrame:
        """
        Filtrowanie przepływów według podanych kryteriów.
        
        Args:
            **kwargs: Kryteria filtrowania (np. src_ip='192.168.1.1', protocol=6)
            
        Returns:
            Przefiltrowany DataFrame
        """
        if self.flows_df is None:
            raise ValueError("Najpierw wczytaj przepływy używając load_flows()")
        
        filtered = self.flows_df.copy()
        
        for key, value in kwargs.items():
            if key in filtered.columns:
                filtered = filtered[filtered[key] == value]
        
        return filtered


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Użycie: python flow_analyzer_scapy.py <ścieżka_do_pliku_pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Inicjalizacja analizatora
    analyzer = FlowAnalyzer(pcap_file)
    
    # Wczytanie przepływów
    flows = analyzer.load_flows()
    
    # Wyświetlenie statystyk
    stats = analyzer.get_flow_statistics()
    
    print("\n=== STATYSTYKI PRZEPŁYWÓW ===")
    print(f"Całkowita liczba przepływów: {stats['total_flows']}")
    print(f"Unikalne IP źródłowe: {stats['unique_src_ips']}")
    print(f"Unikalne IP docelowe: {stats['unique_dst_ips']}")
    print(f"Całkowita liczba pakietów: {stats['total_packets']}")
    print(f"Całkowita liczba bajtów: {stats['total_bytes']}")
    print(f"\nŚrednia liczba pakietów na przepływ: {stats['avg_packets_per_flow']:.2f}")
    print(f"Średnia liczba bajtów na przepływ: {stats['avg_bytes_per_flow']:.2f}")
    
    print("\n=== TOP 10 KOMUNIKACJI MIĘDZY HOSTAMI ===")
    for idx, pair in enumerate(stats['top_host_pairs'], 1):
        print(f"{idx}. {pair['src_ip']} -> {pair['dst_ip']}: "
              f"{pair['total_packets']} pakietów, {pair['total_bytes']} bajtów, "
              f"{pair['flow_count']} przepływów")
