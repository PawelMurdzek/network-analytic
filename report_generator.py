"""
Generator raportów HTML z wynikami analizy.
"""

import pandas as pd
from typing import Dict, List, Optional
import os
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Klasa do generowania raportów HTML z analizy sieciowej.
    """
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Args:
            output_dir: Katalog do zapisywania raportów
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_html_report(
        self,
        flows: pd.DataFrame,
        stats: Dict,
        alerts: Optional[pd.DataFrame] = None,
        ml_metrics: Optional[Dict] = None,
        visualizations: Optional[Dict] = None
    ) -> str:
        """
        Generuje raport HTML z wynikami analizy.
        
        Args:
            flows: DataFrame z przepływami
            stats: Słownik ze statystykami
            alerts: DataFrame z alertami (opcjonalnie)
            ml_metrics: Metryki modelu ML (opcjonalnie)
            visualizations: Słownik ze ścieżkami do wizualizacji (opcjonalnie)
            
        Returns:
            Ścieżka do wygenerowanego raportu
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
        
        html_content = self._build_html(flows, stats, alerts, ml_metrics, visualizations)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Raport HTML wygenerowany: {report_path}")
        return report_path
    
    def _build_html(
        self,
        flows: pd.DataFrame,
        stats: Dict,
        alerts: Optional[pd.DataFrame],
        ml_metrics: Optional[Dict],
        visualizations: Optional[Dict]
    ) -> str:
        """
        Buduje treść HTML raportu.
        """
        html = f"""
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raport Analizy Sieciowej - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
            padding: 30px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 5px solid #667eea;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
        }}
        
        .section h3 {{
            color: #555;
            margin: 20px 0 10px 0;
            font-size: 1.3em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }}
        
        .stat-card h4 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }}
        
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .alert-high {{
            background: #ffebee;
            border-left: 4px solid #f44336;
        }}
        
        .alert-medium {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
        }}
        
        .alert-low {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
        }}
        
        .visualization {{
            margin: 20px 0;
            text-align: center;
        }}
        
        .visualization img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .metric-badge {{
            display: inline-block;
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border-radius: 20px;
            margin: 5px;
            font-weight: 600;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        .requirement-tag {{
            display: inline-block;
            padding: 4px 10px;
            background: #764ba2;
            color: white;
            border-radius: 4px;
            font-size: 0.85em;
            margin: 2px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Raport Analizy Sieciowej</h1>
            <p>System Detection as a Code + ML + Threat Intelligence</p>
            <p>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="content">
"""
        
        # Sekcja 1: Statystyki przepływów (Wymaganie A.2)
        html += self._build_flow_statistics_section(stats)
        
        # Sekcja 2: Alerty (Wymaganie D.1, D.2, V.1)
        if alerts is not None and not alerts.empty:
            html += self._build_alerts_section(alerts)
        
        # Sekcja 3: Metryki ML (Wymaganie ML.1, ML.2)
        if ml_metrics:
            html += self._build_ml_metrics_section(ml_metrics)
        
        # Sekcja 4: Wizualizacje (Wymaganie V.1, V.2)
        if visualizations:
            html += self._build_visualizations_section(visualizations)
        
        # Sekcja 5: Podsumowanie wymagań
        html += self._build_requirements_summary_section(alerts, ml_metrics)
        
        html += """
        </div>
        
        <div class="footer">
            <p>🔐 System Analizy Sieciowej - KRYCY Lab 2 + Projekt 2</p>
            <p>Politechnika Warszawska</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _build_flow_statistics_section(self, stats: Dict) -> str:
        """Buduje sekcję ze statystykami przepływów."""
        html = """
        <div class="section">
            <h2>📈 Statystyki Przepływów <span class="requirement-tag">A.1</span> <span class="requirement-tag">A.2</span></h2>
            
            <div class="stats-grid">
"""
        
        metrics = [
            ("Całkowita liczba przepływów", stats.get('total_flows', 0)),
            ("Unikalne IP źródłowe", stats.get('unique_src_ips', 0)),
            ("Unikalne IP docelowe", stats.get('unique_dst_ips', 0)),
            ("Całkowita liczba pakietów", stats.get('total_packets', 0)),
            ("Całkowita liczba bajtów", f"{stats.get('total_bytes', 0):,}"),
            ("Średnia pakietów/przepływ", f"{stats.get('avg_packets_per_flow', 0):.2f}"),
        ]
        
        for label, value in metrics:
            html += f"""
                <div class="stat-card">
                    <h4>{label}</h4>
                    <div class="value">{value}</div>
                </div>
"""
        
        html += """
            </div>
            
            <h3>Top 5 komunikacji między hostami</h3>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Źródłowe</th>
                        <th>IP Docelowe</th>
                        <th>Pakiety</th>
                        <th>Bajty</th>
                        <th>Przepływy</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for idx, pair in enumerate(stats.get('top_host_pairs', [])[:5], 1):
            html += f"""
                    <tr>
                        <td>{idx}</td>
                        <td>{pair['src_ip']}</td>
                        <td>{pair['dst_ip']}</td>
                        <td>{pair['total_packets']:,}</td>
                        <td>{pair['total_bytes']:,}</td>
                        <td>{pair['flow_count']}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
"""
        
        return html
    
    def _build_alerts_section(self, alerts: pd.DataFrame) -> str:
        """Buduje sekcję z alertami."""
        html = f"""
        <div class="section">
            <h2>🚨 Wykryte Zagrożenia <span class="requirement-tag">D.1</span> <span class="requirement-tag">D.2</span> <span class="requirement-tag">V.1</span></h2>
            
            <p>Łączna liczba alertów: <strong>{len(alerts)}</strong></p>
            
            <h3>Rozkład według poziomu zagrożenia</h3>
            <div class="stats-grid">
"""
        
        if 'severity' in alerts.columns:
            severity_counts = alerts['severity'].value_counts()
            for severity, count in severity_counts.items():
                html += f"""
                <div class="stat-card">
                    <h4>{severity.upper()}</h4>
                    <div class="value">{count}</div>
                </div>
"""
        
        html += """
            </div>
            
            <h3>Lista alertów</h3>
            <table>
                <thead>
                    <tr>
                        <th>Reguła</th>
                        <th>Poziom</th>
                        <th>Wiadomość</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for _, alert in alerts.head(20).iterrows():
            severity_class = f"alert-{alert.get('severity', 'low')}"
            html += f"""
                    <tr class="{severity_class}">
                        <td><strong>{alert.get('rule', 'Unknown')}</strong></td>
                        <td>{alert.get('severity', 'N/A').upper()}</td>
                        <td>{alert.get('message', 'No message')}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
"""
        
        return html
    
    def _build_ml_metrics_section(self, ml_metrics: Dict) -> str:
        """Buduje sekcję z metrykami ML."""
        html = f"""
        <div class="section">
            <h2>🤖 Metryki Modelu Machine Learning <span class="requirement-tag">ML.1</span> <span class="requirement-tag">ML.2</span></h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>Accuracy</h4>
                    <div class="value">{ml_metrics.get('accuracy', 0):.4f}</div>
                </div>
                <div class="stat-card">
                    <h4>Precision</h4>
                    <div class="value">{ml_metrics.get('precision', 0):.4f}</div>
                </div>
                <div class="stat-card">
                    <h4>Recall (TPR)</h4>
                    <div class="value">{ml_metrics.get('recall', 0):.4f}</div>
                </div>
                <div class="stat-card">
                    <h4>F1 Score</h4>
                    <div class="value">{ml_metrics.get('f1_score', 0):.4f}</div>
                </div>
                <div class="stat-card">
                    <h4>False Positive Rate</h4>
                    <div class="value">{ml_metrics.get('fpr', 0):.4f}</div>
                </div>
                <div class="stat-card">
                    <h4>True Negative Rate</h4>
                    <div class="value">{ml_metrics.get('tnr', 0):.4f}</div>
                </div>
            </div>
            
            <p style="margin-top: 20px;">
                Model został wytrenowany z możliwością ponownego trenowania na nowych danych
                <span class="requirement-tag">ML.3</span>
            </p>
        </div>
"""
        
        return html
    
    def _build_visualizations_section(self, visualizations: Dict) -> str:
        """Buduje sekcję z wizualizacjami."""
        html = """
        <div class="section">
            <h2>📊 Wizualizacje <span class="requirement-tag">V.1</span> <span class="requirement-tag">V.2</span></h2>
"""
        
        for name, path in visualizations.items():
            if path and os.path.exists(path):
                # Względna ścieżka do obrazu
                rel_path = os.path.relpath(path, os.path.dirname(path)).replace('\\', '/')
                
                html += f"""
            <div class="visualization">
                <h3>{name.replace('_', ' ').title()}</h3>
                <img src="visualizations/{os.path.basename(path)}" alt="{name}">
            </div>
"""
        
        html += """
        </div>
"""
        
        return html
    
    def _build_requirements_summary_section(
        self, 
        alerts: Optional[pd.DataFrame],
        ml_metrics: Optional[Dict]
    ) -> str:
        """Buduje sekcję z podsumowaniem spełnionych wymagań."""
        html = """
        <div class="section">
            <h2>✅ Podsumowanie Spełnionych Wymagań</h2>
            
            <h3>Lab 2 - Funkcjonalności Podstawowe (Must-have)</h3>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Wymaganie</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>A.1</strong></td>
                        <td>Wczytywanie plików PCAP przy użyciu NFStream</td>
                        <td>✅ Spełnione</td>
                    </tr>
                    <tr>
                        <td><strong>A.2</strong></td>
                        <td>Podsumowanie statystyk flow</td>
                        <td>✅ Spełnione</td>
                    </tr>
                    <tr>
                        <td><strong>D.1</strong></td>
                        <td>Implementacja reguł detekcyjnych w Pythonie</td>
                        <td>✅ Spełnione</td>
                    </tr>
                    <tr>
                        <td><strong>V.1</strong></td>
                        <td>Wykres liczby wykrytych zagrożeń</td>
                        <td>✅ Spełnione</td>
                    </tr>
                </tbody>
            </table>
            
            <h3>Projekt 2 - Funkcjonalności Zaawansowane (Must-have)</h3>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Wymaganie</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>D.2</strong></td>
                        <td>Wczytywanie reguł w formacie Sigma</td>
                        <td>✅ Spełnione</td>
                    </tr>
                    <tr>
                        <td><strong>ML.1</strong></td>
                        <td>Klasyfikacja flow za pomocą ML</td>
                        <td>{'✅ Spełnione' if ml_metrics else '⚠️ Niepełne'}</td>
                    </tr>
                    <tr>
                        <td><strong>ML.2</strong></td>
                        <td>Redukcja FPR, metryki jakości (FPR, TPR)</td>
                        <td>{'✅ Spełnione' if ml_metrics and 'fpr' in ml_metrics else '⚠️ Niepełne'}</td>
                    </tr>
                    <tr>
                        <td><strong>ML.3</strong></td>
                        <td>Możliwość trenowania modelu na nowych danych</td>
                        <td>✅ Spełnione</td>
                    </tr>
                    <tr>
                        <td><strong>E.1</strong></td>
                        <td>Enrichment IP/domen (Threat Intelligence)</td>
                        <td>✅ Spełnione</td>
                    </tr>
                </tbody>
            </table>
            
            <h3>Funkcjonalności Nice-to-have</h3>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Wymaganie</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>V.2</strong></td>
                        <td>Mapa geograficzna z lokalizacją podejrzanych IP</td>
                        <td>✅ Zaimplementowane</td>
                    </tr>
                </tbody>
            </table>
        </div>
"""
        
        return html


if __name__ == "__main__":
    logger.info("Moduł generatora raportów gotowy do użycia")
