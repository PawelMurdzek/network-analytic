"""
Przykładowy notebook demonstracyjny - Podstawy analityki dla projektu.
Ten notebook pokazuje przykłady użycia systemu analizy sieciowej.
"""

# %% [markdown]
# # System Analizy Sieciowej - Demonstracja
# 
# Ten notebook pokazuje jak używać systemu analizy sieciowej do wykrywania zagrożeń.

# %% [markdown]
# ## Krok 1 - Import modułów

# %%
import pandas as pd
import matplotlib.pyplot as plt
import sys
sys.path.append('./proj')

from flow_analyzer import FlowAnalyzer
from detection_rules.detection_rules import create_default_detection_engine
from detection_rules.sigma_handler import SigmaRuleEngine
from models.ml_classifier import NetworkMLClassifier
from threat_intel import ThreatIntelligenceEnricher
from visualizations import NetworkVisualizer

# %% [markdown]
# ## Krok 2 - Wczytanie pliku PCAP
# 
# **Wymaganie A.1** - Wczytywanie plików PCAP przy użyciu NFStream

# %%
# Wczytanie przepływów z pliku PCAP
pcap_file = "proj/data/demo_traffic.pcap"
analyzer = FlowAnalyzer(pcap_file)
flows_df = analyzer.load_flows()

# Wyświetlenie pierwszych 5 przepływów
flows_df.head()

# %% [markdown]
# ## Krok 3 - Statystyki przepływów
# 
# **Wymaganie A.2** - Podsumowanie statystyk flow

# %%
# Pobranie statystyk
stats = analyzer.get_flow_statistics()

print("=== STATYSTYKI PRZEPŁYWÓW ===")
print(f"Całkowita liczba przepływów: {stats['total_flows']}")
print(f"Unikalne IP źródłowe: {stats['unique_src_ips']}")
print(f"Unikalne IP docelowe: {stats['unique_dst_ips']}")
print(f"Całkowita liczba pakietów: {stats['total_packets']}")
print(f"Całkowita liczba bajtów: {stats['total_bytes']}")

# %% [markdown]
# ### Wizualizacja top komunikacji między hostami

# %%
# Konwersja do DataFrame
top_pairs = pd.DataFrame(stats['top_host_pairs'][:10])

# Wykres słupkowy
plt.figure(figsize=(12, 6))
labels = [f"{row['src_ip']} → {row['dst_ip']}" for _, row in top_pairs.iterrows()]
plt.barh(labels, top_pairs['total_packets'], color='steelblue')
plt.xlabel('Liczba pakietów')
plt.title('Top 10 komunikacji między hostami')
plt.tight_layout()
plt.show()

# %% [markdown]
# ## Krok 4 - Detection as a Code
# 
# **Wymaganie D.1** - Implementacja reguł detekcyjnych w Pythonie

# %%
# Utworzenie silnika detekcyjnego
detection_engine = create_default_detection_engine()

# Uruchomienie detekcji
alerts = detection_engine.run_detection(flows_df)

# Wyświetlenie alertów
alerts_df = detection_engine.get_alerts_dataframe()
print(f"\n=== WYKRYTO {len(alerts_df)} ALERTÓW ===\n")
alerts_df.head(10)

# %% [markdown]
# ### Wizualizacja alertów według poziomu zagrożenia
# 
# **Wymaganie V.1** - Wykres liczby wykrytych zagrożeń

# %%
if not alerts_df.empty:
    severity_counts = alerts_df['severity'].value_counts()
    
    # Kolory dla różnych poziomów zagrożenia
    colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'darkred'}
    bar_colors = [colors.get(sev, 'gray') for sev in severity_counts.index]
    
    plt.figure(figsize=(10, 6))
    plt.bar(severity_counts.index, severity_counts.values, color=bar_colors, alpha=0.7, edgecolor='black')
    plt.title('Histogram alertów według poziomu zagrożenia')
    plt.xlabel('Poziom zagrożenia')
    plt.ylabel('Liczba alertów')
    plt.xticks(rotation=0)
    plt.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    plt.show()

# %% [markdown]
# ## Krok 5 - Reguły Sigma
# 
# **Wymaganie D.2** - Wczytywanie reguł w formacie Sigma

# %%
# Wczytanie reguł Sigma
sigma_engine = SigmaRuleEngine()
sigma_engine.load_rules_from_directory("proj/detection_rules/")

# Uruchomienie detekcji Sigma
sigma_alerts = sigma_engine.run_detection(flows_df)
sigma_alerts_df = sigma_engine.get_alerts_dataframe()

print(f"=== ALERTY SIGMA: {len(sigma_alerts_df)} ===\n")
if not sigma_alerts_df.empty:
    sigma_alerts_df.head()

# %% [markdown]
# ## Krok 6 - Machine Learning
# 
# **Wymagania ML.1, ML.2** - Klasyfikacja flow i metryki jakości

# %%
# Utworzenie i trenowanie modelu ML
classifier = NetworkMLClassifier()
ml_metrics = classifier.train(flows_df, tune_hyperparameters=False)

print("\n=== METRYKI MODELU ML ===")
print(f"Accuracy: {ml_metrics['accuracy']:.4f}")
print(f"Precision: {ml_metrics['precision']:.4f}")
print(f"Recall (TPR): {ml_metrics['recall']:.4f}")
print(f"F1 Score: {ml_metrics['f1_score']:.4f}")
print(f"False Positive Rate (FPR): {ml_metrics['fpr']:.4f}")
print(f"True Negative Rate (TNR): {ml_metrics['tnr']:.4f}")

# %% [markdown]
# ### Wizualizacja macierzy konfuzji
# 
# **Wymaganie ML.2** - Metryki jakości (FPR, TPR, macierz konfuzji)

# %%
import numpy as np
import seaborn as sns

# Macierz konfuzji
cm = np.array(ml_metrics['confusion_matrix'])

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
           xticklabels=['Normal', 'Suspicious'],
           yticklabels=['Normal', 'Suspicious'])
plt.title('Macierz konfuzji - Model ML')
plt.xlabel('Predykcja')
plt.ylabel('Rzeczywista wartość')
plt.tight_layout()
plt.show()

# Obliczenie metryk z macierzy
tn, fp, fn, tp = cm.ravel()
print(f"\nTrue Negatives: {tn}")
print(f"False Positives: {fp}")
print(f"False Negatives: {fn}")
print(f"True Positives: {tp}")
print(f"\nTPR (Recall): {ml_metrics['tpr']:.4f}")
print(f"FPR: {ml_metrics['fpr']:.4f}")

# %% [markdown]
# ## Krok 7 - Threat Intelligence Enrichment
# 
# **Wymaganie E.1** - Wzbogacanie danych o IP

# %%
# Wzbogacenie danych (tylko dla przykładu - pierwsze 10 przepływów)
enricher = ThreatIntelligenceEnricher(rate_limit_delay=0.3)
sample_flows = flows_df.head(10)
enriched_flows = enricher.enrich_flows(sample_flows, enrich_src=False, enrich_dst=True)

print("\n=== WZBOGACONE DANE ===\n")
# Wyświetlenie kolumn z enrichmentem
enrichment_cols = ['dst_ip', 'dst_country', 'dst_city', 'dst_isp']
available_cols = [col for col in enrichment_cols if col in enriched_flows.columns]
if available_cols:
    enriched_flows[available_cols]

# %% [markdown]
# ### Wizualizacja alertów według kraju pochodzenia
# 
# Podobnie jak w oryginalnym notebook'u - agregacja i wykres

# %%
if 'dst_country' in enriched_flows.columns:
    # Agregacja danych - liczba przepływów według kraju
    country_counts = enriched_flows['dst_country'].value_counts()
    
    # Wykres słupkowy liczby przepływów według kraju
    plt.figure(figsize=(10, 6))
    country_counts.plot(kind='bar', color='coral')
    plt.title('Częstotliwość występowania przepływów w zależności od kraju docelowego')
    plt.xlabel('Kraj')
    plt.ylabel('Liczba przepływów')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# %% [markdown]
# ## Krok 8 - Dodatkowe wizualizacje
# 
# **Wymaganie V.1** - Różne wizualizacje

# %%
# Wizualizacja rozkładu protokołów
protocol_counts = flows_df['protocol'].value_counts()
protocol_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
labels = [f"{protocol_names.get(p, f'Protocol {p}')}" for p in protocol_counts.index]

plt.figure(figsize=(10, 6))
plt.pie(protocol_counts.values, labels=labels, autopct='%1.1f%%', startangle=90)
plt.title('Rozkład protokołów w ruchu sieciowym')
plt.tight_layout()
plt.show()

# %% [markdown]
# ### Top porty docelowe

# %%
top_ports = flows_df['dst_port'].value_counts().head(10)

plt.figure(figsize=(10, 6))
plt.barh(range(len(top_ports)), top_ports.values, color='teal')
plt.yticks(range(len(top_ports)), top_ports.index)
plt.xlabel('Liczba przepływów')
plt.ylabel('Port docelowy')
plt.title('Top 10 najczęściej używanych portów docelowych')
plt.grid(True, alpha=0.3, axis='x')
plt.tight_layout()
plt.show()

# %% [markdown]
# ## Krok 9 - Mapa geograficzna (Nice-to-have)
# 
# **Wymaganie V.2** - Mapa geograficzna z lokalizacją IP

# %%
try:
    import folium
    from folium.plugins import HeatMap
    
    if 'dst_latitude' in enriched_flows.columns and 'dst_longitude' in enriched_flows.columns:
        # Filtrowanie danych z geolokalizacją
        geo_data = enriched_flows[
            (enriched_flows['dst_latitude'].notna()) & 
            (enriched_flows['dst_longitude'].notna())
        ]
        
        if not geo_data.empty:
            # Utworzenie mapy
            center_lat = geo_data['dst_latitude'].mean()
            center_lon = geo_data['dst_longitude'].mean()
            
            m = folium.Map(location=[center_lat, center_lon], zoom_start=2)
            
            # Dodanie markerów
            for _, row in geo_data.iterrows():
                folium.CircleMarker(
                    location=[row['dst_latitude'], row['dst_longitude']],
                    radius=5,
                    popup=f"{row['dst_ip']} - {row['dst_country']}",
                    color='red',
                    fill=True,
                    fillColor='red',
                    fillOpacity=0.6
                ).add_to(m)
            
            # Zapisanie mapy
            m.save('geo_map.html')
            print("Mapa geograficzna zapisana jako geo_map.html")
        else:
            print("Brak danych geolokalizacyjnych do wizualizacji")
    else:
        print("Brak kolumn z geolokalizacją")
        
except ImportError:
    print("Biblioteka folium niedostępna - pomijanie mapy geograficznej")

# %% [markdown]
# ## Krok 10 - Predykcja na nowych danych
# 
# **Wymaganie ML.3** - Możliwość użycia modelu na nowych danych

# %%
# Predykcja na przepływach
predictions, probabilities = classifier.predict(flows_df)

# Dodanie predykcji do DataFrame
flows_with_predictions = flows_df.copy()
flows_with_predictions['ml_prediction'] = predictions
flows_with_predictions['ml_probability'] = probabilities

# Wyświetlenie podejrzanych przepływów (prediction = 1)
suspicious_flows = flows_with_predictions[flows_with_predictions['ml_prediction'] == 1]
print(f"\n=== MODEL ML WYKRYŁ {len(suspicious_flows)} PODEJRZANYCH PRZEPŁYWÓW ===\n")

if not suspicious_flows.empty:
    suspicious_flows[['src_ip', 'dst_ip', 'dst_port', 'ml_probability']].head(10)

# %% [markdown]
# ## Krok 11 - Analiza według typu aplikacji

# %%
if 'application_name' in flows_df.columns:
    app_counts = flows_df['application_name'].value_counts().head(10)
    
    plt.figure(figsize=(12, 6))
    plt.barh(range(len(app_counts)), app_counts.values, color='purple', alpha=0.7)
    plt.yticks(range(len(app_counts)), app_counts.index)
    plt.xlabel('Liczba przepływów')
    plt.ylabel('Aplikacja')
    plt.title('Top 10 aplikacji w ruchu sieciowym')
    plt.grid(True, alpha=0.3, axis='x')
    plt.tight_layout()
    plt.show()

# %% [markdown]
# ## Podsumowanie
# 
# Ten notebook zademonstrował wszystkie wymagania projektu:
# 
# ### Lab 2 - Must-have:
# - **A.1** - Wczytywanie PCAP z NFStream
# - **A.2** - Statystyki przepływów
# - **D.1** - Reguły detekcyjne w Pythonie
# - **V.1** - Wizualizacje alertów
# 
# ### Projekt 2 - Must-have:
# - **D.2** - Reguły Sigma
# - **ML.1** - Klasyfikacja ML
# - **ML.2** - Metryki (FPR, TPR, macierz konfuzji)
# - **ML.3** - Predykcja na nowych danych
# - **E.1** - Threat Intelligence enrichment
# 
# ### Nice-to-have:
# - **V.2** - Mapa geograficzna

# %%
print("\n" + "="*60)
print("  ANALIZA ZAKOŃCZONA - WSZYSTKIE WYMAGANIA SPEŁNIONE")
print("="*60)
