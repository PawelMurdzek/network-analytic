"""
Detection as a Code - Reguły detekcyjne dla analizy ruchu sieciowego.
Wymaganie: D.1
"""

import pandas as pd
from typing import Dict, List, Tuple, Callable
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DetectionRule:
    """
    Klasa bazowa dla reguł detekcyjnych.
    """
    
    def __init__(self, name: str, description: str, severity: str):
        """
        Args:
            name: Nazwa reguły
            description: Opis reguły
            severity: Poziom zagrożenia (low, medium, high, critical)
        """
        self.name = name
        self.description = description
        self.severity = severity
    
    def detect(self, flow: pd.Series) -> Tuple[bool, str]:
        """
        Funkcja detekcyjna - musi być nadpisana w klasach pochodnych.
        
        Args:
            flow: Seria pandas reprezentująca pojedynczy przepływ
            
        Returns:
            Tuple (czy_wykryto, wiadomość)
        """
        raise NotImplementedError("Metoda detect() musi być zaimplementowana")


class LargeDataTransferRule(DetectionRule):
    """
    Wykrywa podejrzanie duże transfery danych.
    """
    
    def __init__(self, threshold_bytes: int = 10_000_000):
        super().__init__(
            name="Large Data Transfer",
            description=f"Wykrywa transfery większe niż {threshold_bytes} bajtów",
            severity="medium"
        )
        self.threshold_bytes = threshold_bytes
    
    def detect(self, flow: pd.Series) -> Tuple[bool, str]:
        if flow['bidirectional_bytes'] > self.threshold_bytes:
            return True, (
                f"Wykryto duży transfer danych: {flow['src_ip']}:{flow['src_port']} -> "
                f"{flow['dst_ip']}:{flow['dst_port']}, "
                f"{flow['bidirectional_bytes']} bajtów"
            )
        return False, ""


class PortScanDetectionRule(DetectionRule):
    """
    Wykrywa potencjalne skanowanie portów (jeden host łączy się z wieloma portami).
    Ta reguła działa na zgrupowanych danych.
    """
    
    def __init__(self, threshold_ports: int = 10):
        super().__init__(
            name="Port Scan Detection",
            description=f"Wykrywa połączenia z więcej niż {threshold_ports} różnymi portami",
            severity="high"
        )
        self.threshold_ports = threshold_ports
    
    def detect_on_dataframe(self, flows_df: pd.DataFrame) -> List[Dict]:
        """
        Detekcja na całym DataFrame.
        
        Returns:
            Lista alertów
        """
        alerts = []
        
        # Grupowanie po IP źródłowym i zliczanie unikalnych portów docelowych
        port_counts = flows_df.groupby('src_ip')['dst_port'].nunique()
        
        for src_ip, port_count in port_counts.items():
            if port_count > self.threshold_ports:
                alerts.append({
                    'rule': self.name,
                    'severity': self.severity,
                    'message': f"Możliwe skanowanie portów z {src_ip}: {port_count} różnych portów docelowych",
                    'src_ip': src_ip,
                    'port_count': port_count
                })
        
        return alerts


class SuspiciousPortRule(DetectionRule):
    """
    Wykrywa połączenia do podejrzanych portów (np. nietypowe porty, często używane przez malware).
    """
    
    def __init__(self):
        super().__init__(
            name="Suspicious Port Connection",
            description="Wykrywa połączenia do podejrzanych portów",
            severity="medium"
        )
        # Lista podejrzanych portów (przykładowe)
        self.suspicious_ports = [
            4444,  # Metasploit default
            5555,  # Android Debug Bridge (może być wykorzystywane przez malware)
            6667,  # IRC (często używane przez botnety)
            31337, # Back Orifice
            12345, # NetBus
            1337,  # Leetspeak port (często używany przez exploity)
        ]
    
    def detect(self, flow: pd.Series) -> Tuple[bool, str]:
        if flow['dst_port'] in self.suspicious_ports:
            return True, (
                f"Połączenie do podejrzanego portu: {flow['src_ip']} -> "
                f"{flow['dst_ip']}:{flow['dst_port']}"
            )
        return False, ""


class DNSTunnelingRule(DetectionRule):
    """
    Wykrywa potencjalne tunelowanie DNS (nienormalnie długie zapytania DNS).
    """
    
    def __init__(self, packet_threshold: int = 50):
        super().__init__(
            name="DNS Tunneling Detection",
            description=f"Wykrywa przepływy DNS z więcej niż {packet_threshold} pakietami",
            severity="high"
        )
        self.packet_threshold = packet_threshold
    
    def detect(self, flow: pd.Series) -> Tuple[bool, str]:
        # Port 53 = DNS
        if flow['dst_port'] == 53 and flow['bidirectional_packets'] > self.packet_threshold:
            return True, (
                f"Możliwe tunelowanie DNS: {flow['src_ip']} -> {flow['dst_ip']}, "
                f"{flow['bidirectional_packets']} pakietów"
            )
        return False, ""


class LongDurationConnectionRule(DetectionRule):
    """
    Wykrywa podejrzanie długie połączenia (np. C2 beaconing).
    """
    
    def __init__(self, duration_threshold_ms: int = 3600000):  # 1 godzina
        super().__init__(
            name="Long Duration Connection",
            description=f"Wykrywa połączenia trwające dłużej niż {duration_threshold_ms}ms",
            severity="medium"
        )
        self.duration_threshold_ms = duration_threshold_ms
    
    def detect(self, flow: pd.Series) -> Tuple[bool, str]:
        if flow['bidirectional_duration_ms'] > self.duration_threshold_ms:
            return True, (
                f"Długotrwałe połączenie: {flow['src_ip']}:{flow['src_port']} -> "
                f"{flow['dst_ip']}:{flow['dst_port']}, "
                f"{flow['bidirectional_duration_ms']}ms"
            )
        return False, ""


class DetectionEngine:
    """
    Silnik detekcyjny zarządzający regułami i wykonujący detekcję.
    """
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        self.alerts: List[Dict] = []
    
    def add_rule(self, rule: DetectionRule):
        """
        Dodaje regułę do silnika.
        
        Args:
            rule: Reguła detekcyjna
        """
        self.rules.append(rule)
        logger.info(f"Dodano regułę: {rule.name}")
    
    def run_detection(self, flows_df: pd.DataFrame) -> List[Dict]:
        """
        Uruchamia detekcję na przepływach.
        
        Args:
            flows_df: DataFrame z przepływami
            
        Returns:
            Lista alertów
        """
        self.alerts = []
        
        logger.info(f"Uruchamianie detekcji z {len(self.rules)} regułami...")
        
        for rule in self.rules:
            # Sprawdzenie czy reguła ma metodę detect_on_dataframe (dla reguł agregujących)
            if hasattr(rule, 'detect_on_dataframe'):
                alerts = rule.detect_on_dataframe(flows_df)
                self.alerts.extend(alerts)
            else:
                # Standardowa detekcja na każdym przepływie
                for idx, flow in flows_df.iterrows():
                    detected, message = rule.detect(flow)
                    if detected:
                        self.alerts.append({
                            'rule': rule.name,
                            'severity': rule.severity,
                            'message': message,
                            'src_ip': flow['src_ip'],
                            'dst_ip': flow['dst_ip'],
                            'src_port': flow['src_port'],
                            'dst_port': flow['dst_port'],
                        })
        
        logger.info(f"Wygenerowano {len(self.alerts)} alertów")
        
        return self.alerts
    
    def get_alerts_dataframe(self) -> pd.DataFrame:
        """
        Zwraca alerty jako DataFrame.
        
        Returns:
            DataFrame z alertami
        """
        return pd.DataFrame(self.alerts)
    
    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        """
        Filtruje alerty według poziomu zagrożenia.
        
        Args:
            severity: Poziom zagrożenia (low, medium, high, critical)
            
        Returns:
            Lista alertów o podanym poziomie zagrożenia
        """
        return [alert for alert in self.alerts if alert['severity'] == severity]


def create_default_detection_engine() -> DetectionEngine:
    """
    Tworzy silnik detekcyjny z domyślnymi regułami.
    
    Returns:
        Skonfigurowany DetectionEngine
    """
    engine = DetectionEngine()
    
    # Dodanie standardowych reguł
    engine.add_rule(LargeDataTransferRule(threshold_bytes=10_000_000))
    engine.add_rule(PortScanDetectionRule(threshold_ports=10))
    engine.add_rule(SuspiciousPortRule())
    engine.add_rule(DNSTunnelingRule(packet_threshold=50))
    engine.add_rule(LongDurationConnectionRule(duration_threshold_ms=3600000))
    
    return engine


if __name__ == "__main__":
    # Przykład użycia
    import sys
    sys.path.append('..')
    from flow_analyzer import FlowAnalyzer
    
    if len(sys.argv) < 2:
        print("Użycie: python detection_rules.py <ścieżka_do_pliku_pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Wczytanie przepływów
    analyzer = FlowAnalyzer(pcap_file)
    flows = analyzer.load_flows()
    
    # Utworzenie silnika detekcyjnego
    engine = create_default_detection_engine()
    
    # Uruchomienie detekcji
    alerts = engine.run_detection(flows)
    
    # Wyświetlenie alertów
    print("\n=== ALERTY BEZPIECZEŃSTWA ===")
    if alerts:
        for idx, alert in enumerate(alerts, 1):
            print(f"\n{idx}. [{alert['severity'].upper()}] {alert['rule']}")
            print(f"   {alert['message']}")
    else:
        print("Nie wykryto zagrożeń")
