"""
Moduł do analizy ruchu sieciowego na poziomie flow z wykorzystaniem NFStream.
Wymagania: A.1, A.2
"""

import pandas as pd
from nfstream import NFStreamer, NFPlugin
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlowAnalyzer:
    """
    Klasa do analizy przepływów sieciowych z plików PCAP.
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
        Wczytanie przepływów z pliku PCAP przy użyciu NFStream.
        
        Returns:
            DataFrame z przepływami sieciowymi
        """
        logger.info(f"Wczytywanie przepływów z pliku: {self.pcap_file}")
        
        try:
            # Inicjalizacja NFStreamer
            streamer = NFStreamer(source=self.pcap_file, 
                                 statistical_analysis=True,
                                 n_dissections=20)
            
            # Konwersja do DataFrame
            flows = []
            for flow in streamer:
                flows.append({
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'bidirectional_packets': flow.bidirectional_packets,
                    'bidirectional_bytes': flow.bidirectional_bytes,
                    'src2dst_packets': flow.src2dst_packets,
                    'src2dst_bytes': flow.src2dst_bytes,
                    'dst2src_packets': flow.dst2src_packets,
                    'dst2src_bytes': flow.dst2src_bytes,
                    'bidirectional_duration_ms': flow.bidirectional_duration_ms,
                    'src2dst_duration_ms': flow.src2dst_duration_ms,
                    'dst2src_duration_ms': flow.dst2src_duration_ms,
                    'application_name': flow.application_name,
                    'application_category_name': flow.application_category_name,
                })
            
            self.flows_df = pd.DataFrame(flows)
            logger.info(f"Wczytano {len(self.flows_df)} przepływów")
            
            return self.flows_df
            
        except Exception as e:
            logger.error(f"Błąd podczas wczytywania przepływów: {e}")
            raise
    
    def get_flow_statistics(self) -> Dict:
        """
        Generowanie statystyk przepływów sieciowych.
        Wymaganie A.2
        
        Returns:
            Słownik ze statystykami
        """
        if self.flows_df is None:
            raise ValueError("Najpierw wczytaj przepływy używając load_flows()")
        
        stats = {
            'total_flows': len(self.flows_df),
            'unique_src_ips': self.flows_df['src_ip'].nunique(),
            'unique_dst_ips': self.flows_df['dst_ip'].nunique(),
            'total_packets': self.flows_df['bidirectional_packets'].sum(),
            'total_bytes': self.flows_df['bidirectional_bytes'].sum(),
            'avg_packets_per_flow': self.flows_df['bidirectional_packets'].mean(),
            'avg_bytes_per_flow': self.flows_df['bidirectional_bytes'].mean(),
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
    # Przykład użycia
    import sys
    
    if len(sys.argv) < 2:
        print("Użycie: python flow_analyzer.py <ścieżka_do_pliku_pcap>")
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
