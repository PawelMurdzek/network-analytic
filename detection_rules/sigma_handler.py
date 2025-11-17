"""
Moduł do obsługi reguł Sigma w systemie detekcji.
Wymaganie: D.2
"""

import yaml
import pandas as pd
from typing import Dict, List, Any, Optional
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SigmaRule:
    """
    Klasa reprezentująca regułę Sigma.
    """
    
    def __init__(self, rule_file: str):
        """
        Args:
            rule_file: Ścieżka do pliku YAML z regułą Sigma
        """
        self.rule_file = rule_file
        self.rule_data = None
        self.load_rule()
    
    def load_rule(self):
        """
        Wczytuje regułę Sigma z pliku YAML.
        """
        try:
            with open(self.rule_file, 'r', encoding='utf-8') as f:
                self.rule_data = yaml.safe_load(f)
            logger.info(f"Wczytano regułę Sigma: {self.get_title()}")
        except Exception as e:
            logger.error(f"Błąd podczas wczytywania reguły {self.rule_file}: {e}")
            raise
    
    def get_title(self) -> str:
        """Zwraca tytuł reguły."""
        return self.rule_data.get('title', 'Unknown')
    
    def get_description(self) -> str:
        """Zwraca opis reguły."""
        return self.rule_data.get('description', '')
    
    def get_level(self) -> str:
        """Zwraca poziom zagrożenia."""
        return self.rule_data.get('level', 'medium')
    
    def get_detection_logic(self) -> Dict:
        """Zwraca logikę detekcji."""
        return self.rule_data.get('detection', {})
    
    def match(self, flow: pd.Series) -> bool:
        """
        Sprawdza czy przepływ pasuje do reguły.
        Uproszczona implementacja - w rzeczywistej aplikacji należałoby użyć PySigma.
        
        Args:
            flow: Seria pandas reprezentująca przepływ
            
        Returns:
            True jeśli przepływ pasuje do reguły
        """
        detection = self.get_detection_logic()
        
        # Uproszczona logika - sprawdzanie podstawowych warunków
        # W prawdziwej implementacji należy użyć PySigma do pełnej konwersji
        
        if 'selection' in detection:
            selection = detection['selection']
            return self._check_selection(flow, selection)
        
        return False
    
    def _check_selection(self, flow: pd.Series, selection: Dict) -> bool:
        """
        Sprawdza warunki selekcji.
        
        Args:
            flow: Seria pandas reprezentująca przepływ
            selection: Słownik z warunkami selekcji
            
        Returns:
            True jeśli wszystkie warunki są spełnione
        """
        for key, value in selection.items():
            # Mapowanie pól Sigma na pola flow
            flow_key = self._map_sigma_field(key)
            
            if flow_key not in flow.index:
                continue
            
            if isinstance(value, list):
                if flow[flow_key] not in value:
                    return False
            else:
                if flow[flow_key] != value:
                    return False
        
        return True
    
    def _map_sigma_field(self, sigma_field: str) -> str:
        """
        Mapuje pola Sigma na pola w DataFrame z przepływami.
        
        Args:
            sigma_field: Nazwa pola w Sigma
            
        Returns:
            Nazwa pola w DataFrame
        """
        # Podstawowe mapowanie - można rozszerzyć
        mapping = {
            'DestinationPort': 'dst_port',
            'SourcePort': 'src_port',
            'DestinationIp': 'dst_ip',
            'SourceIp': 'src_ip',
            'Protocol': 'protocol',
        }
        
        return mapping.get(sigma_field, sigma_field.lower())


class SigmaRuleEngine:
    """
    Silnik do przetwarzania reguł Sigma.
    """
    
    def __init__(self):
        self.rules: List[SigmaRule] = []
        self.alerts: List[Dict] = []
    
    def load_rules_from_directory(self, rules_dir: str):
        """
        Wczytuje wszystkie reguły Sigma z katalogu.
        
        Args:
            rules_dir: Ścieżka do katalogu z regułami
        """
        if not os.path.exists(rules_dir):
            logger.warning(f"Katalog z regułami nie istnieje: {rules_dir}")
            return
        
        for filename in os.listdir(rules_dir):
            if filename.endswith(('.yml', '.yaml')):
                rule_path = os.path.join(rules_dir, filename)
                try:
                    rule = SigmaRule(rule_path)
                    self.rules.append(rule)
                except Exception as e:
                    logger.error(f"Nie można wczytać reguły {filename}: {e}")
        
        logger.info(f"Wczytano {len(self.rules)} reguł Sigma")
    
    def add_rule(self, rule: SigmaRule):
        """
        Dodaje regułę do silnika.
        
        Args:
            rule: Reguła Sigma
        """
        self.rules.append(rule)
    
    def run_detection(self, flows_df: pd.DataFrame) -> List[Dict]:
        """
        Uruchamia detekcję na przepływach.
        
        Args:
            flows_df: DataFrame z przepływami
            
        Returns:
            Lista alertów
        """
        self.alerts = []
        
        logger.info(f"Uruchamianie detekcji Sigma z {len(self.rules)} regułami...")
        
        for rule in self.rules:
            for idx, flow in flows_df.iterrows():
                if rule.match(flow):
                    self.alerts.append({
                        'rule': rule.get_title(),
                        'severity': rule.get_level(),
                        'message': f"{rule.get_description()}",
                        'src_ip': flow['src_ip'],
                        'dst_ip': flow['dst_ip'],
                        'src_port': flow['src_port'],
                        'dst_port': flow['dst_port'],
                    })
        
        logger.info(f"Wygenerowano {len(self.alerts)} alertów Sigma")
        
        return self.alerts
    
    def get_alerts_dataframe(self) -> pd.DataFrame:
        """
        Zwraca alerty jako DataFrame.
        
        Returns:
            DataFrame z alertami
        """
        return pd.DataFrame(self.alerts)


def create_example_sigma_rule(output_path: str):
    """
    Tworzy przykładową regułę Sigma do testów.
    
    Args:
        output_path: Ścieżka do zapisu reguły
    """
    example_rule = {
        'title': 'Suspicious Port 4444 Connection',
        'id': '12345678-1234-1234-1234-123456789012',
        'description': 'Detects connections to port 4444 which is commonly used by Metasploit',
        'author': 'Security Team',
        'date': '2024/01/01',
        'level': 'high',
        'logsource': {
            'category': 'network',
            'product': 'flow'
        },
        'detection': {
            'selection': {
                'DestinationPort': 4444
            },
            'condition': 'selection'
        },
        'falsepositives': [
            'Legitimate applications using port 4444'
        ],
        'tags': [
            'attack.command_and_control',
            'attack.t1071'
        ]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(example_rule, f, default_flow_style=False, allow_unicode=True)
    
    logger.info(f"Utworzono przykładową regułę Sigma: {output_path}")


if __name__ == "__main__":
    # Przykład użycia
    import sys
    
    # Utworzenie przykładowej reguły
    example_rule_path = "../detection_rules/example_sigma_rule.yml"
    create_example_sigma_rule(example_rule_path)
    
    # Test wczytywania reguły
    rule = SigmaRule(example_rule_path)
    print(f"\nWczytano regułę: {rule.get_title()}")
    print(f"Opis: {rule.get_description()}")
    print(f"Poziom: {rule.get_level()}")
