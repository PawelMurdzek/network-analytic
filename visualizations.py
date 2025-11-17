"""
Moduł do wizualizacji danych i alertów.
Wymagania: V.1, V.2
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Optional
import logging
import os

# Opcjonalnie - dla map geograficznych
try:
    import folium
    from folium.plugins import HeatMap
    FOLIUM_AVAILABLE = True
except ImportError:
    FOLIUM_AVAILABLE = False
    logging.warning("Biblioteka folium niedostępna - mapy geograficzne nie będą działać")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ustawienia stylu wykresów
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)


class NetworkVisualizer:
    """
    Klasa do tworzenia wizualizacji danych sieciowych i alertów.
    """
    
    def __init__(self, output_dir: str = "./visualizations"):
        """
        Args:
            output_dir: Katalog do zapisywania wizualizacji
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def plot_alerts_timeline(
        self, 
        alerts_df: pd.DataFrame,
        time_column: str = 'timestamp',
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres liczby wykrytych zagrożeń w czasie.
        Wymaganie: V.1
        
        Args:
            alerts_df: DataFrame z alertami
            time_column: Nazwa kolumny z czasem
            save_path: Ścieżka do zapisu (opcjonalnie)
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(14, 6))
        
        if time_column in alerts_df.columns:
            # Jeśli mamy kolumnę czasu
            alerts_df[time_column] = pd.to_datetime(alerts_df[time_column])
            alerts_by_time = alerts_df.groupby(
                alerts_df[time_column].dt.floor('H')
            ).size()
            
            plt.plot(alerts_by_time.index, alerts_by_time.values, 
                    marker='o', linewidth=2, markersize=6)
            plt.xlabel('Czas', fontsize=12)
            plt.xticks(rotation=45)
        else:
            # Wykres słupkowy liczby alertów według typu
            if 'severity' in alerts_df.columns:
                severity_counts = alerts_df['severity'].value_counts()
                colors = {'low': 'green', 'medium': 'orange', 
                         'high': 'red', 'critical': 'darkred'}
                
                bar_colors = [colors.get(sev, 'gray') for sev in severity_counts.index]
                
                plt.bar(severity_counts.index, severity_counts.values, 
                       color=bar_colors, alpha=0.7, edgecolor='black')
                plt.xlabel('Poziom zagrożenia', fontsize=12)
            else:
                # Prosty wykres liczby alertów
                rule_counts = alerts_df['rule'].value_counts().head(10)
                plt.barh(rule_counts.index, rule_counts.values, color='coral')
                plt.xlabel('Liczba alertów', fontsize=12)
                plt.ylabel('Reguła', fontsize=12)
        
        plt.title('Wykryte zagrożenia', fontsize=14, fontweight='bold')
        plt.ylabel('Liczba alertów', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'alerts_timeline.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path
    
    def plot_severity_distribution(
        self,
        alerts_df: pd.DataFrame,
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres rozkładu alertów według poziomu zagrożenia.
        
        Args:
            alerts_df: DataFrame z alertami
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(10, 6))
        
        if 'severity' in alerts_df.columns:
            severity_counts = alerts_df['severity'].value_counts()
            
            colors = {'low': '#90EE90', 'medium': '#FFA500', 
                     'high': '#FF6B6B', 'critical': '#8B0000'}
            pie_colors = [colors.get(sev, 'gray') for sev in severity_counts.index]
            
            plt.pie(severity_counts.values, labels=severity_counts.index,
                   autopct='%1.1f%%', startangle=90, colors=pie_colors,
                   textprops={'fontsize': 12})
            
            plt.title('Rozkład alertów według poziomu zagrożenia', 
                     fontsize=14, fontweight='bold')
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'severity_distribution.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path
    
    def plot_confusion_matrix(
        self,
        confusion_matrix: List[List[int]],
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres macierzy konfuzji dla modelu ML.
        
        Args:
            confusion_matrix: Macierz konfuzji
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(8, 6))
        
        sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Normal', 'Suspicious'],
                   yticklabels=['Normal', 'Suspicious'],
                   cbar_kws={'label': 'Liczba przypadków'})
        
        plt.title('Macierz konfuzji - Model ML', fontsize=14, fontweight='bold')
        plt.xlabel('Predykcja', fontsize=12)
        plt.ylabel('Rzeczywista wartość', fontsize=12)
        plt.tight_layout()
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'confusion_matrix.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path
    
    def plot_top_ips(
        self,
        flows_df: pd.DataFrame,
        ip_column: str = 'dst_ip',
        top_n: int = 10,
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres top N adresów IP.
        
        Args:
            flows_df: DataFrame z przepływami
            ip_column: Nazwa kolumny z IP
            top_n: Liczba top IP do pokazania
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(12, 6))
        
        ip_counts = flows_df[ip_column].value_counts().head(top_n)
        
        plt.barh(range(len(ip_counts)), ip_counts.values, color='steelblue')
        plt.yticks(range(len(ip_counts)), ip_counts.index)
        plt.xlabel('Liczba przepływów', fontsize=12)
        plt.ylabel('Adres IP', fontsize=12)
        plt.title(f'Top {top_n} najczęściej występujących adresów IP', 
                 fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3, axis='x')
        plt.tight_layout()
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, f'top_{ip_column}.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path
    
    def plot_protocol_distribution(
        self,
        flows_df: pd.DataFrame,
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres rozkładu protokołów.
        
        Args:
            flows_df: DataFrame z przepływami
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(10, 6))
        
        protocol_counts = flows_df['protocol'].value_counts()
        
        # Mapowanie numerów protokołów na nazwy
        protocol_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        labels = [f"{protocol_names.get(p, f'Protocol {p}')} ({p})" 
                 for p in protocol_counts.index]
        
        plt.pie(protocol_counts.values, labels=labels,
               autopct='%1.1f%%', startangle=90,
               colors=sns.color_palette('Set3'))
        
        plt.title('Rozkład protokołów w ruchu sieciowym', 
                 fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'protocol_distribution.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path
    
    def create_geo_map(
        self,
        flows_df: pd.DataFrame,
        latitude_column: str = 'dst_latitude',
        longitude_column: str = 'dst_longitude',
        save_path: Optional[str] = None
    ) -> Optional[str]:
        """
        Tworzy mapę geograficzną z lokalizacją podejrzanych IP.
        Wymaganie: V.2 (nice-to-have)
        
        Args:
            flows_df: DataFrame z przepływami (wzbogacone o geolokalizację)
            latitude_column: Nazwa kolumny z szerokością geograficzną
            longitude_column: Nazwa kolumny z długością geograficzną
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku HTML lub None
        """
        if not FOLIUM_AVAILABLE:
            logger.warning("Biblioteka folium niedostępna - pomijanie tworzenia mapy")
            return None
        
        # Filtrowanie danych z geolokalizacją
        geo_data = flows_df[
            (flows_df[latitude_column].notna()) & 
            (flows_df[longitude_column].notna())
        ]
        
        if geo_data.empty:
            logger.warning("Brak danych z geolokalizacją")
            return None
        
        # Utworzenie mapy (centrowanej na średnich współrzędnych)
        center_lat = geo_data[latitude_column].mean()
        center_lon = geo_data[longitude_column].mean()
        
        m = folium.Map(location=[center_lat, center_lon], zoom_start=2)
        
        # Dodanie markerów dla każdej unikalnej lokalizacji
        location_counts = geo_data.groupby(
            [latitude_column, longitude_column]
        ).size().reset_index(name='count')
        
        for _, row in location_counts.iterrows():
            folium.CircleMarker(
                location=[row[latitude_column], row[longitude_column]],
                radius=min(row['count'] / 2, 15),
                popup=f"Liczba przepływów: {row['count']}",
                color='red',
                fill=True,
                fillColor='red',
                fillOpacity=0.6
            ).add_to(m)
        
        # Dodanie heat mapy
        heat_data = [
            [row[latitude_column], row[longitude_column]] 
            for _, row in geo_data.iterrows()
        ]
        HeatMap(heat_data, radius=15).add_to(m)
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'geo_map.html')
        
        m.save(save_path)
        
        logger.info(f"Mapa geograficzna zapisana: {save_path}")
        return save_path
    
    def plot_feature_importance(
        self,
        importance_df: pd.DataFrame,
        save_path: Optional[str] = None
    ) -> str:
        """
        Wykres ważności cech dla modelu ML.
        
        Args:
            importance_df: DataFrame z ważnością cech
            save_path: Ścieżka do zapisu
            
        Returns:
            Ścieżka do zapisanego pliku
        """
        plt.figure(figsize=(10, 6))
        
        top_features = importance_df.head(10)
        
        plt.barh(range(len(top_features)), top_features['importance'].values, 
                color='teal', alpha=0.7)
        plt.yticks(range(len(top_features)), top_features['feature'].values)
        plt.xlabel('Ważność cechy', fontsize=12)
        plt.ylabel('Cecha', fontsize=12)
        plt.title('Top 10 najważniejszych cech w modelu ML', 
                 fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3, axis='x')
        plt.tight_layout()
        
        if save_path is None:
            save_path = os.path.join(self.output_dir, 'feature_importance.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Wykres zapisany: {save_path}")
        return save_path


if __name__ == "__main__":
    # Przykład użycia
    logger.info("Moduł wizualizacji gotowy do użycia")
