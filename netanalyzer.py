"""
Główny interfejs CLI do systemu analizy sieciowej.
"""

import click
import os
import sys
import logging
from pathlib import Path

# Dodanie ścieżki projektu
sys.path.insert(0, str(Path(__file__).parent))

from flow_analyzer import FlowAnalyzer
from detection_rules.detection_rules import create_default_detection_engine, DetectionEngine
from detection_rules.sigma_handler import SigmaRuleEngine
from models.ml_classifier import NetworkMLClassifier
from threat_intel import ThreatIntelligenceEnricher
from visualizations import NetworkVisualizer
from report_generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    System analizy sieciowej - Detection as a Code + ML + Threat Intelligence
    
    Narzędzie do analizy ruchu sieciowego z plików PCAP.
    """
    pass


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', default='./reports', help='Katalog wyjściowy dla raportów')
@click.option('--detect/--no-detect', default=True, help='Uruchom detekcję zagrożeń')
@click.option('--ml/--no-ml', default=True, help='Uruchom klasyfikację ML')
@click.option('--enrich/--no-enrich', default=False, help='Wzbogać dane o Threat Intelligence')
@click.option('--visualize/--no-visualize', default=True, help='Generuj wizualizacje')
@click.option('--report/--no-report', default=True, help='Generuj raport HTML')
@click.option('--sigma-rules', type=click.Path(), help='Katalog z regułami Sigma')
def analyze(pcap_file, output, detect, ml, enrich, visualize, report, sigma_rules):
    """
    Analizuj plik PCAP i wygeneruj raport.
    
    Przykład użycia:
    
        netanalyzer analyze sample.pcap -o ./output
        
        netanalyzer analyze sample.pcap --enrich --sigma-rules ./rules/
    """
    click.echo(f"\n{'='*60}")
    click.echo(f"  System Analizy Sieciowej - Analiza PCAP")
    click.echo(f"{'='*60}\n")
    
    # Utworzenie katalogu wyjściowego
    os.makedirs(output, exist_ok=True)
    
    try:
        # 1. Wczytanie przepływów
        click.echo(f"[1/6] Wczytywanie przepływów z pliku: {pcap_file}")
        analyzer = FlowAnalyzer(pcap_file)
        flows = analyzer.load_flows()
        stats = analyzer.get_flow_statistics()
        
        click.echo(f"[OK] Wczytano {stats['total_flows']} przeplywow")
        
        # 2. Detekcja zagrożeń
        alerts_df = None
        if detect:
            click.echo("\n[2/6] Uruchamianie detekcji zagrożeń...")
            
            # Reguły pythonowe
            engine = create_default_detection_engine()
            alerts = engine.run_detection(flows)
            
            # Reguły Sigma (jeśli podano)
            if sigma_rules and os.path.exists(sigma_rules):
                click.echo(f"  Wczytywanie reguł Sigma z: {sigma_rules}")
                sigma_engine = SigmaRuleEngine()
                sigma_engine.load_rules_from_directory(sigma_rules)
                sigma_alerts = sigma_engine.run_detection(flows)
                alerts.extend(sigma_alerts)
            
            alerts_df = engine.get_alerts_dataframe()
            click.echo(f"[OK] Wykryto {len(alerts)} alertow")
        else:
            click.echo("\n[2/6] Pomijanie detekcji zagrożeń")
        
        # 3. Klasyfikacja ML
        ml_metrics = None
        ml_predictions = None
        if ml:
            click.echo("\n[3/6] Uruchamianie klasyfikacji ML...")
            classifier = NetworkMLClassifier()
            ml_metrics = classifier.train(flows, tune_hyperparameters=False)
            ml_predictions, ml_probabilities = classifier.predict(flows)
            
            # Zapis modelu
            model_path = os.path.join(output, 'network_classifier.pkl')
            classifier.save_model(model_path)
            
            click.echo(f"[OK] Model wytrenowany - Accuracy: {ml_metrics['accuracy']:.4f}, FPR: {ml_metrics['fpr']:.4f}")
        else:
            click.echo("\n[3/6] Pomijanie klasyfikacji ML")
        
        # 4. Enrichment
        enriched_flows = flows
        if enrich:
            click.echo("\n[4/6] Wzbogacanie danych o Threat Intelligence...")
            enricher = ThreatIntelligenceEnricher(rate_limit_delay=0.2)
            enriched_flows = enricher.enrich_flows(
                flows.head(20),  # Ograniczenie do 20 pierwszych dla przykładu
                enrich_src=False, 
                enrich_dst=True
            )
            click.echo(f"[OK] Wzbogacono dane")
        else:
            click.echo("\n[4/6] Pomijanie wzbogacania danych")
        
        # 5. Wizualizacje
        viz_paths = {}
        if visualize:
            click.echo("\n[5/6] Generowanie wizualizacji...")
            viz_dir = os.path.join(output, 'visualizations')
            visualizer = NetworkVisualizer(output_dir=viz_dir)
            
            # Wykres protokołów
            viz_paths['protocols'] = visualizer.plot_protocol_distribution(enriched_flows)
            
            # Wykres top IP
            viz_paths['top_ips'] = visualizer.plot_top_ips(enriched_flows, 'dst_ip')
            
            # Wykresy alertów
            if alerts_df is not None and not alerts_df.empty:
                viz_paths['alerts'] = visualizer.plot_alerts_timeline(alerts_df)
                viz_paths['severity'] = visualizer.plot_severity_distribution(alerts_df)
            
            # Macierz konfuzji ML
            if ml_metrics and 'confusion_matrix' in ml_metrics:
                viz_paths['confusion'] = visualizer.plot_confusion_matrix(
                    ml_metrics['confusion_matrix']
                )
            
            # Mapa geograficzna (jeśli dane wzbogacone)
            if enrich and 'dst_latitude' in enriched_flows.columns:
                geo_path = visualizer.create_geo_map(enriched_flows)
                if geo_path:
                    viz_paths['geo_map'] = geo_path
            
            click.echo(f"[OK] Wygenerowano {len(viz_paths)} wizualizacji")
        else:
            click.echo("\n[5/6] Pomijanie wizualizacji")
        
        # 6. Raport
        if report:
            click.echo("\n[6/6] Generowanie raportu HTML...")
            report_gen = ReportGenerator(output_dir=output)
            report_path = report_gen.generate_html_report(
                flows=enriched_flows,
                stats=stats,
                alerts=alerts_df,
                ml_metrics=ml_metrics,
                visualizations=viz_paths
            )
            click.echo(f"[OK] Raport zapisany: {report_path}")
        else:
            click.echo("\n[6/6] Pomijanie generowania raportu")
        
        # Podsumowanie
        click.echo(f"\n{'='*60}")
        click.echo("  ANALIZA ZAKOŃCZONA")
        click.echo(f"{'='*60}")
        click.echo(f"\nWyniki zapisane w: {output}")
        
    except Exception as e:
        logger.error(f"Błąd podczas analizy: {e}", exc_info=True)
        click.echo(f"\nBłąd: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
def stats(pcap_file):
    """
    Wyświetl statystyki przepływów z pliku PCAP.
    
    Przykład użycia:
    
        netanalyzer stats sample.pcap
    """
    click.echo(f"\nAnaliza statystyk dla: {pcap_file}\n")
    
    try:
        analyzer = FlowAnalyzer(pcap_file)
        flows = analyzer.load_flows()
        stats = analyzer.get_flow_statistics()
        
        click.echo("=== STATYSTYKI PRZEPŁYWÓW ===\n")
        click.echo(f"Całkowita liczba przepływów: {stats['total_flows']}")
        click.echo(f"Unikalne IP źródłowe: {stats['unique_src_ips']}")
        click.echo(f"Unikalne IP docelowe: {stats['unique_dst_ips']}")
        click.echo(f"Całkowita liczba pakietów: {stats['total_packets']}")
        click.echo(f"Całkowita liczba bajtów: {stats['total_bytes']}")
        click.echo(f"\nŚrednia liczba pakietów/przepływ: {stats['avg_packets_per_flow']:.2f}")
        click.echo(f"Średnia liczba bajtów/przepływ: {stats['avg_bytes_per_flow']:.2f}")
        
        click.echo("\n=== TOP 5 KOMUNIKACJI MIĘDZY HOSTAMI ===\n")
        for idx, pair in enumerate(stats['top_host_pairs'][:5], 1):
            click.echo(
                f"{idx}. {pair['src_ip']} -> {pair['dst_ip']}: "
                f"{pair['total_packets']} pakietów, {pair['flow_count']} przepływów"
            )
        
    except Exception as e:
        click.echo(f"Błąd: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('training_data', type=click.Path(exists=True))
@click.option('--output', '-o', default='./models/network_classifier.pkl', 
              help='Ścieżka do zapisu modelu')
@click.option('--tune/--no-tune', default=True, help='Wykonaj tuning hiperparametrów')
def train_model(training_data, output, tune):
    """
    Wytrenuj nowy model ML na danych treningowych.
    
    Przykład użycia:
    
        netanalyzer train-model training.pcap -o model.pkl --tune
    """
    click.echo(f"\nTrenowanie modelu na danych: {training_data}\n")
    
    try:
        # Wczytanie danych
        analyzer = FlowAnalyzer(training_data)
        flows = analyzer.load_flows()
        
        # Trenowanie modelu
        classifier = NetworkMLClassifier()
        metrics = classifier.train(flows, tune_hyperparameters=tune)
        
        # Zapis modelu
        os.makedirs(os.path.dirname(output), exist_ok=True)
        classifier.save_model(output)
        
        click.echo("=== METRYKI MODELU ===\n")
        click.echo(f"Accuracy: {metrics['accuracy']:.4f}")
        click.echo(f"Precision: {metrics['precision']:.4f}")
        click.echo(f"Recall (TPR): {metrics['recall']:.4f}")
        click.echo(f"F1 Score: {metrics['f1_score']:.4f}")
        click.echo(f"False Positive Rate (FPR): {metrics['fpr']:.4f}")
        
        click.echo(f"\n[OK] Model zapisany: {output}")
        
    except Exception as e:
        click.echo(f"Błąd: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('output_file', type=click.Path())
@click.option('--count', '-c', default=100, help='Liczba pakietów do wygenerowania')
@click.option('--malicious/--normal', default=False, help='Generuj złośliwy ruch')
def generate_traffic(output_file, count, malicious):
    """
    Generuj syntetyczny ruch sieciowy do testów.
    
    Przykład użycia:
    
        netanalyzer generate-traffic test.pcap --count 500 --malicious
    """
    click.echo(f"\nGenerowanie {count} pakietów...")
    click.echo(f"Typ ruchu: {'złośliwy' if malicious else 'normalny'}")
    click.echo(f"Plik wyjściowy: {output_file}\n")
    
    click.echo("⚠ Ta funkcja wymaga implementacji z użyciem scapy")
    click.echo("Przykładowy skrypt znajduje się w: simulate_traffic.py")


if __name__ == '__main__':
    cli()
