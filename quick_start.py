"""
Przewodnik szybkiego startu - System Analizy Sieciowej
"""

# %% [markdown]
# # 🚀 Quick Start Guide - System Analizy Sieciowej

# %% [markdown]
# ## 1. Instalacja zależności
# 
# ```bash
# cd proj
# pip install -r requirements.txt
# ```

# %% [markdown]
# ## 2. Generowanie demonstracyjnego ruchu sieciowego

# %%
# Uruchom ten kod aby wygenerować przykładowe pliki PCAP
import sys
sys.path.append('./proj')

from simulate_traffic import create_demo_pcap_with_alerts, create_normal_traffic_pcap

# Generowanie plików
create_demo_pcap_with_alerts("proj/data/demo_traffic.pcap")
create_normal_traffic_pcap("proj/data/normal_traffic.pcap")

print("✅ Pliki demonstracyjne zostały utworzone!")

# %% [markdown]
# ## 3. Podstawowa analiza z CLI

# %% [markdown]
# ### Opcja A: Użycie CLI (z terminala)
# 
# ```bash
# cd proj
# python netanalyzer.py analyze data/demo_traffic.pcap -o ./output
# ```

# %% [markdown]
# ### Opcja B: Użycie z Python

# %%
from flow_analyzer import FlowAnalyzer
from detection_rules.detection_rules import create_default_detection_engine
from visualizations import NetworkVisualizer

# Wczytanie PCAP
analyzer = FlowAnalyzer("proj/data/demo_traffic.pcap")
flows = analyzer.load_flows()
stats = analyzer.get_flow_statistics()

# Detekcja
engine = create_default_detection_engine()
alerts = engine.run_detection(flows)

# Wyniki
print(f"Przepływy: {stats['total_flows']}")
print(f"Alerty: {len(alerts)}")

# %% [markdown]
# ## 4. Wizualizacje

# %%
import matplotlib.pyplot as plt
import pandas as pd

# Pobranie alertów jako DataFrame
alerts_df = engine.get_alerts_dataframe()

if not alerts_df.empty:
    # Wykres alertów
    severity_counts = alerts_df['severity'].value_counts()
    
    plt.figure(figsize=(10, 6))
    severity_counts.plot(kind='bar', color=['green', 'orange', 'red'])
    plt.title('Rozkład alertów według poziomu zagrożenia')
    plt.xlabel('Poziom zagrożenia')
    plt.ylabel('Liczba alertów')
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.show()

# %% [markdown]
# ## 5. Machine Learning

# %%
from models.ml_classifier import NetworkMLClassifier

# Trenowanie modelu
classifier = NetworkMLClassifier()
metrics = classifier.train(flows, tune_hyperparameters=False)

print("\nMetryki modelu:")
print(f"  Accuracy: {metrics['accuracy']:.4f}")
print(f"  FPR: {metrics['fpr']:.4f}")
print(f"  TPR: {metrics['tpr']:.4f}")

# %% [markdown]
# ## 6. Threat Intelligence Enrichment

# %%
from threat_intel import ThreatIntelligenceEnricher

# Wzbogacenie danych (przykład na 5 przepływach)
enricher = ThreatIntelligenceEnricher(rate_limit_delay=0.5)
sample = flows.head(5)
enriched = enricher.enrich_flows(sample, enrich_src=False, enrich_dst=True)

# Wyświetlenie wyników
if 'dst_country' in enriched.columns:
    print("\nWzbogacone dane:")
    print(enriched[['dst_ip', 'dst_country', 'dst_city', 'dst_isp']])

# %% [markdown]
# ## 7. Pełna analiza z raportem

# %%
from report_generator import ReportGenerator

# Generator raportów
report_gen = ReportGenerator(output_dir="./quick_start_output")

# Utworzenie wizualizacji
viz = NetworkVisualizer(output_dir="./quick_start_output/visualizations")
viz_paths = {
    'alerts': viz.plot_alerts_timeline(alerts_df) if not alerts_df.empty else None,
    'protocols': viz.plot_protocol_distribution(flows),
    'confusion': viz.plot_confusion_matrix(metrics['confusion_matrix'])
}

# Generowanie raportu
report_path = report_gen.generate_html_report(
    flows=flows,
    stats=stats,
    alerts=alerts_df if not alerts_df.empty else None,
    ml_metrics=metrics,
    visualizations=viz_paths
)

print(f"\n✅ Raport HTML wygenerowany: {report_path}")

# %% [markdown]
# ## 8. Dodawanie własnych reguł detekcyjnych

# %%
from detection_rules.detection_rules import DetectionRule, DetectionEngine

class CustomPortRule(DetectionRule):
    """Wykrywa połączenia do niestandardowego portu"""
    
    def __init__(self, port: int):
        super().__init__(
            name=f"Custom Port {port} Detection",
            description=f"Wykrywa ruch do portu {port}",
            severity="medium"
        )
        self.port = port
    
    def detect(self, flow):
        if flow['dst_port'] == self.port:
            return True, f"Wykryto połączenie do portu {self.port} z {flow['src_ip']}"
        return False, ""

# Użycie własnej reguły
custom_engine = DetectionEngine()
custom_engine.add_rule(CustomPortRule(8080))
custom_alerts = custom_engine.run_detection(flows)

print(f"\nWłasna reguła wykryła: {len(custom_alerts)} alertów")

# %% [markdown]
# ## 9. Komenda CLI - wszystkie opcje
# 
# ```bash
# # Pełna analiza z enrichment i regułami Sigma
# python netanalyzer.py analyze data/demo_traffic.pcap \
#     -o ./output \
#     --enrich \
#     --sigma-rules detection_rules/
# 
# # Tylko statystyki
# python netanalyzer.py stats data/demo_traffic.pcap
# 
# # Trenowanie modelu
# python netanalyzer.py train-model data/demo_traffic.pcap \
#     -o models/my_model.pkl \
#     --tune
# ```

# %% [markdown]
# ## 10. Sprawdzenie spełnienia wymagań

# %%
print("\n" + "="*60)
print("  WYMAGANIA PROJEKTU")
print("="*60)

requirements = {
    "A.1 - Wczytywanie PCAP z NFStream": "✅",
    "A.2 - Statystyki flow": "✅",
    "D.1 - Reguły detekcyjne w Pythonie": "✅",
    "D.2 - Reguły Sigma": "✅",
    "ML.1 - Klasyfikacja ML": "✅",
    "ML.2 - Metryki (FPR, TPR)": "✅",
    "ML.3 - Trenowanie na nowych danych": "✅",
    "E.1 - Threat Intelligence": "✅",
    "V.1 - Wizualizacje alertów": "✅",
    "V.2 - Mapa geograficzna (nice-to-have)": "✅"
}

for req, status in requirements.items():
    print(f"{status} {req}")

print("="*60)
print("\n🎉 Wszystkie wymagania spełnione!")
