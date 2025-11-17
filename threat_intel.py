"""
Moduł do wzbogacania danych o informacje z Threat Intelligence.
Wymaganie: E.1
"""

import pandas as pd
import requests
import logging
from typing import Dict, Optional
import time
from functools import lru_cache

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligenceEnricher:
    """
    Klasa do wzbogacania danych o informacje z Threat Intelligence.
    """
    
    def __init__(self, rate_limit_delay: float = 0.5):
        """
        Args:
            rate_limit_delay: Opóźnienie między zapytaniami API (w sekundach)
        """
        self.rate_limit_delay = rate_limit_delay
        self.cache = {}
    
    @lru_cache(maxsize=1000)
    def get_ip_geolocation(self, ip: str) -> Optional[Dict]:
        """
        Pobiera informacje o geolokalizacji IP z api ip-api.com.
        
        Args:
            ip: Adres IP
            
        Returns:
            Słownik z danymi geolokalizacyjnymi lub None
        """
        try:
            # Dodanie opóźnienia aby nie przekroczyć limitu API
            time.sleep(self.rate_limit_delay)
            
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'timezone': data.get('timezone'),
                    }
            
            return None
            
        except Exception as e:
            logger.warning(f"Błąd podczas pobierania geolokalizacji dla {ip}: {e}")
            return None
    
    @lru_cache(maxsize=1000)
    def check_ip_reputation_abuseipdb(self, ip: str, api_key: Optional[str] = None) -> Optional[Dict]:
        """
        Sprawdza reputację IP w AbuseIPDB (wymaga klucza API).
        
        Args:
            ip: Adres IP
            api_key: Klucz API do AbuseIPDB
            
        Returns:
            Słownik z informacjami o reputacji lub None
        """
        if not api_key:
            logger.warning("Brak klucza API dla AbuseIPDB")
            return None
        
        try:
            time.sleep(self.rate_limit_delay)
            
            headers = {
                'Key': api_key,
                'Accept': 'application/json',
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    return {
                        'abuse_confidence_score': data['data'].get('abuseConfidenceScore'),
                        'is_whitelisted': data['data'].get('isWhitelisted'),
                        'total_reports': data['data'].get('totalReports'),
                        'usage_type': data['data'].get('usageType'),
                        'domain': data['data'].get('domain'),
                    }
            
            return None
            
        except Exception as e:
            logger.warning(f"Błąd podczas sprawdzania reputacji dla {ip}: {e}")
            return None
    
    def check_ip_reputation_virustotal(self, ip: str, api_key: Optional[str] = None) -> Optional[Dict]:
        """
        Sprawdza reputację IP w VirusTotal (wymaga klucza API).
        
        Args:
            ip: Adres IP
            api_key: Klucz API do VirusTotal
            
        Returns:
            Słownik z informacjami o reputacji lub None
        """
        if not api_key:
            logger.warning("Brak klucza API dla VirusTotal")
            return None
        
        try:
            time.sleep(self.rate_limit_delay)
            
            headers = {
                'x-apikey': api_key,
            }
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    attributes = data['data'].get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    return {
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'reputation': attributes.get('reputation', 0),
                        'asn': attributes.get('asn'),
                        'as_owner': attributes.get('as_owner'),
                    }
            
            return None
            
        except Exception as e:
            logger.warning(f"Błąd podczas sprawdzania VirusTotal dla {ip}: {e}")
            return None
    
    def enrich_flows(
        self, 
        flows_df: pd.DataFrame,
        enrich_src: bool = True,
        enrich_dst: bool = True,
        abuseipdb_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Wzbogaca przepływy o dane Threat Intelligence.
        
        Args:
            flows_df: DataFrame z przepływami
            enrich_src: Czy wzbogacać IP źródłowe
            enrich_dst: Czy wzbogacać IP docelowe
            abuseipdb_api_key: Klucz API dla AbuseIPDB (opcjonalnie)
            virustotal_api_key: Klucz API dla VirusTotal (opcjonalnie)
            
        Returns:
            Wzbogacony DataFrame
        """
        enriched_df = flows_df.copy()
        
        logger.info("Rozpoczęcie wzbogacania danych...")
        
        # Unikalne IP do wzbogacenia
        ips_to_enrich = set()
        
        if enrich_src:
            ips_to_enrich.update(flows_df['src_ip'].unique())
        
        if enrich_dst:
            ips_to_enrich.update(flows_df['dst_ip'].unique())
        
        # Usunięcie lokalnych i prywatnych IP
        ips_to_enrich = [
            ip for ip in ips_to_enrich 
            if not self._is_private_ip(ip)
        ]
        
        logger.info(f"Wzbogacanie {len(ips_to_enrich)} unikalnych IP...")
        
        # Wzbogacanie każdego IP
        ip_enrichment_data = {}
        
        for idx, ip in enumerate(ips_to_enrich, 1):
            if idx % 10 == 0:
                logger.info(f"Przetworzono {idx}/{len(ips_to_enrich)} IP...")
            
            enrichment = {}
            
            # Geolokalizacja
            geo_data = self.get_ip_geolocation(ip)
            if geo_data:
                enrichment.update({
                    f'country': geo_data.get('country'),
                    f'city': geo_data.get('city'),
                    f'latitude': geo_data.get('latitude'),
                    f'longitude': geo_data.get('longitude'),
                    f'isp': geo_data.get('isp'),
                })
            
            # Reputacja z AbuseIPDB (jeśli dostępny klucz API)
            if abuseipdb_api_key:
                abuse_data = self.check_ip_reputation_abuseipdb(ip, abuseipdb_api_key)
                if abuse_data:
                    enrichment.update({
                        f'abuse_score': abuse_data.get('abuse_confidence_score'),
                        f'total_reports': abuse_data.get('total_reports'),
                    })
            
            # Reputacja z VirusTotal (jeśli dostępny klucz API)
            if virustotal_api_key:
                vt_data = self.check_ip_reputation_virustotal(ip, virustotal_api_key)
                if vt_data:
                    enrichment.update({
                        f'vt_malicious': vt_data.get('malicious'),
                        f'vt_suspicious': vt_data.get('suspicious'),
                    })
            
            ip_enrichment_data[ip] = enrichment
        
        # Dodanie wzbogaconych danych do DataFrame
        if enrich_src:
            enriched_df = self._add_enrichment_columns(
                enriched_df, ip_enrichment_data, 'src_ip', 'src_'
            )
        
        if enrich_dst:
            enriched_df = self._add_enrichment_columns(
                enriched_df, ip_enrichment_data, 'dst_ip', 'dst_'
            )
        
        logger.info("Wzbogacanie zakończone")
        
        return enriched_df
    
    def _add_enrichment_columns(
        self, 
        df: pd.DataFrame, 
        enrichment_data: Dict, 
        ip_column: str,
        prefix: str
    ) -> pd.DataFrame:
        """
        Dodaje kolumny z danymi wzbogacenia do DataFrame.
        
        Args:
            df: DataFrame
            enrichment_data: Dane wzbogacenia
            ip_column: Nazwa kolumny z IP
            prefix: Prefix dla nowych kolumn
            
        Returns:
            DataFrame z dodanymi kolumnami
        """
        for key in ['country', 'city', 'latitude', 'longitude', 'isp', 
                    'abuse_score', 'total_reports', 'vt_malicious', 'vt_suspicious']:
            column_name = f'{prefix}{key}'
            df[column_name] = df[ip_column].apply(
                lambda ip: enrichment_data.get(ip, {}).get(key, None)
            )
        
        return df
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Sprawdza czy IP jest prywatne lub lokalne.
        
        Args:
            ip: Adres IP
            
        Returns:
            True jeśli IP jest prywatne
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Prywatne zakresy IP
            if first_octet == 10:
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            if first_octet == 192 and second_octet == 168:
                return True
            if first_octet == 127:  # localhost
                return True
            
            return False
            
        except:
            return True


if __name__ == "__main__":
    # Przykład użycia
    import sys
    sys.path.append('..')
    from flow_analyzer import FlowAnalyzer
    
    if len(sys.argv) < 2:
        print("Użycie: python threat_intel.py <ścieżka_do_pliku_pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Wczytanie przepływów
    analyzer = FlowAnalyzer(pcap_file)
    flows = analyzer.load_flows()
    
    # Wzbogacenie danych
    enricher = ThreatIntelligenceEnricher()
    enriched_flows = enricher.enrich_flows(flows, enrich_src=False, enrich_dst=True)
    
    # Wyświetlenie przykładowych danych
    print("\n=== PRZYKŁADOWE WZBOGACONE DANE ===")
    cols_to_show = ['dst_ip', 'dst_country', 'dst_city', 'dst_isp']
    available_cols = [col for col in cols_to_show if col in enriched_flows.columns]
    
    if available_cols:
        print(enriched_flows[available_cols].head(10))
