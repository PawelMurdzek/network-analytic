# System Analizy Sieciowej
**Detection as a Code + Machine Learning + Threat Intelligence**

> Prototypowy system analizy sieciowej (PoC) - KRYCY Lab 2 + Projekt 2  
> Politechnika Warszawska

---

## Opis projektu

System analizy sieciowej wykorzystujący:
- **Analizę przepływów (flow)** z plików PCAP za pomocą NFStream
- **Detection as a Code** - reguły detekcyjne w Pythonie
- **Reguły Sigma** - wsparcie dla standardowych reguł bezpieczeństwa
- **Machine Learning** - klasyfikacja ruchu sieciowego
- **Threat Intelligence** - wzbogacanie danych o geolokalizację i reputację IP
- **Wizualizacje** - wykresy i mapy geograficzne
- **Raporty HTML** - szczegółowe raporty z analizy

---

## Spelnione wymagania

### Lab 2 - Funkcjonalności podstawowe (Must-have)

| ID | Wymaganie | Status |
|---|---|---|
| **A.1** | Wczytywanie plików PCAP przy użyciu NFStream |
| **A.2** | Wyświetlanie podsumowania statystyk flow |
| **D.1** | Implementacja reguł detekcyjnych w Pythonie |
| **V.1** | Wykres liczby wykrytych zagrożeń |

### Projekt 2 - Funkcjonalności zaawansowane (Must-have)

| ID | Wymaganie | Status |
|---|---|---|
| **D.2** | Wczytywanie reguł Sigma |
| **ML.1** | Klasyfikacja flow za pomocą ML |
| **ML.2** | Redukcja FPR, metryki jakości (TPR, FPR, macierz konfuzji) |
| **ML.3** | Możliwość trenowania modelu na nowych danych |
| **E.1** | Enrichment IP/domen (geolokalizacja, reputacja) |

### Funkcjonalności Nice-to-have

| ID | Wymaganie | Status |
|---|---|---|
| **V.2** | Mapa geograficzna z lokalizacją podejrzanych IP |

---

## Struktura projektu

```

├── data/                          # Pliki PCAP do analizy
├── detection_rules/               # Reguly detekcyjne
│   ├── detection_rules.py         # Reguly Detection as a Code (D.1)
│   ├── sigma_handler.py           # Obsluga regul Sigma (D.2)
│   ├── example_sigma_rule.yml     # Przykladowa regula Sigma
│   └── sigma_rules/               # Katalog z regulami Sigma
│       ├── README.md              # Dokumentacja regul Sigma
│       ├── port_scan_detection.yml
│       ├── cobalt_strike_beacon.yml
│       ├── metasploit_reverse_shell.yml
│       ├── dns_tunneling.yml
│       ├── smb_lateral_movement.yml
│       ├── rdp_brute_force.yml
│       ├── crypto_mining.yml
│       ├── tor_traffic.yml
│       ├── data_exfiltration.yml
│       └── ssh_brute_force.yml
├── models/                        # Modele ML
│   └── ml_classifier.py           # Klasyfikator ML (ML.1, ML.2, ML.3)
├── reports/                       # Wygenerowane raporty
├── visualizations/                # Wizualizacje
├── flow_analyzer.py               # Analiza flow z NFStream (A.1, A.2)
├── threat_intel.py                # Threat Intelligence enrichment (E.1)
├── visualizations.py              # Generator wizualizacji (V.1, V.2)
├── report_generator.py            # Generator raportow HTML
├── latex_report_generator.py      # Generator raportow LaTeX/PDF
├── netanalyzer.py                 # Glowny interfejs CLI
└── simulate_traffic.py            # Generator symulowanego ruchu
```

---

## Reguly Sigma

System obsluguje reguly detekcyjne w formacie Sigma - otwartym standardzie
niezaleznym od platformy SIEM. Reguly znajduja sie w katalogu
`detection_rules/sigma_rules/`.

### Dostepne reguly

| Regula | Opis | Poziom | MITRE ATT&CK |
|--------|------|--------|--------------|
| Port Scan | Wykrywanie skanowania portow | Medium | T1046 |
| Cobalt Strike | Beacony Cobalt Strike C2 | Critical | T1071.001 |
| Metasploit | Reverse shell na port 4444 | Critical | T1059 |
| DNS Tunneling | Tunelowanie danych przez DNS | Medium | T1071.004 |
| SMB Lateral | Ruch boczny przez SMB/445 | High | T1021.002 |
| RDP Brute Force | Ataki brute force na RDP | High | T1110 |
| Crypto Mining | Komunikacja z mining pools | High | T1496 |
| Tor Traffic | Ruch przez siec Tor | Medium | T1090.003 |
| Data Exfiltration | Duze transfery danych | Low | T1048 |
| SSH Brute Force | Ataki brute force na SSH | Medium | T1110.001 |

### Dodawanie wlasnych regul

Szczegolowa instrukcja znajduje sie w `detection_rules/sigma_rules/README.md`.

Przyklad reguly:

```yaml
title: Moja Regula
id: unique-uuid-here
description: Opis wykrywanego zagrozenia
logsource:
  category: network
  product: flow
detection:
  selection:
    DestinationPort: 12345
  condition: selection
level: high
tags:
  - attack.command_and_control
```

---

## Instalacja

### Wymagania
- Python 3.8+
- Windows/Linux/macOS

### Instalacja zależności

```powershell
# Podstawowe biblioteki
pip install pandas numpy matplotlib seaborn

# Analiza sieciowa
pip install nfstream scapy

# Machine Learning
pip install scikit-learn joblib

# Threat Intelligence
pip install requests

# Wizualizacje (opcjonalnie - mapy)
pip install folium

# CLI
pip install click

# Reguły Sigma
pip install pyyaml
```

Lub wszystkie naraz:

```powershell
pip install pandas numpy matplotlib seaborn nfstream scapy scikit-learn joblib requests folium click pyyaml
```

---

## Użycie

### 1. Generowanie demonstracyjnego ruchu sieciowego

```powershell
cd proj
python simulate_traffic.py
```

To utworzy dwa pliki PCAP w katalogu `data/`:
- `demo_traffic.pcap` - ruch z alertami (skanowanie portów, suspicious ports, itp.)
- `normal_traffic.pcap` - normalny ruch

### 2. Analiza pliku PCAP

#### Podstawowa analiza

```powershell
python netanalyzer.py analyze data/demo_traffic.pcap
```

#### Pełna analiza z wszystkimi funkcjami

```powershell
python netanalyzer.py analyze data/demo_traffic.pcap -o ./output --enrich --sigma-rules detection_rules/
```

#### Wyświetlenie statystyk

```powershell
python netanalyzer.py stats data/demo_traffic.pcap
```

#### Trenowanie modelu ML

```powershell
python netanalyzer.py train-model data/demo_traffic.pcap -o models/custom_model.pkl
```

### 3. Parametry analizy

```
--output, -o          Katalog wyjściowy dla raportów (domyślnie: ./reports)
--detect/--no-detect  Uruchom detekcję zagrożeń (domyślnie: włączone)
--ml/--no-ml          Uruchom klasyfikację ML (domyślnie: włączone)
--enrich/--no-enrich  Wzbogać dane o Threat Intelligence (domyślnie: wyłączone*)
--visualize           Generuj wizualizacje (domyślnie: włączone)
--report              Generuj raport HTML (domyślnie: włączone)
--sigma-rules         Katalog z regułami Sigma (opcjonalnie)
```

*Uwaga: Enrichment może być czasochłonny ze względu na limity API

---

## Funkcjonalności

### Analiza Flow (A.1, A.2)
- Wczytywanie plików PCAP za pomocą NFStream
- Statystyki przepływów: liczba pakietów, bajtów, protokoły
- Top komunikacje między hostami

### Detection as a Code (D.1)

Zaimplementowane reguły w Pythonie:
- **LargeDataTransferRule** - wykrywa duże transfery danych
- **PortScanDetectionRule** - wykrywa skanowanie portów
- **SuspiciousPortRule** - wykrywa połączenia do podejrzanych portów (4444, 5555, 6667, etc.)
- **DNSTunnelingRule** - wykrywa potencjalne tunelowanie DNS
- **LongDurationConnectionRule** - wykrywa długotrwałe połączenia

### Reguły Sigma (D.2)
- Wczytywanie reguł w formacie YAML
- Przykładowa reguła: detekcja portu 4444 (Metasploit)

### Machine Learning (ML.1, ML.2, ML.3)
- **Klasyfikacja**: Random Forest Classifier
- **Metryki**: Accuracy, Precision, Recall, F1-Score, TPR, FPR, TNR
- **Macierz konfuzji**: Wizualizacja wyników
- **Tuning hiperparametrów**: GridSearchCV
- **Retrenowanie**: Możliwość trenowania na nowych danych przez CLI

### Threat Intelligence (E.1)
- **Geolokalizacja IP**: ip-api.com (kraj, miasto, ISP, współrzędne)
- **Reputacja IP**: AbuseIPDB, VirusTotal (wymaga kluczy API)

### Wizualizacje (V.1, V.2)
- Wykres alertów według czasu/typu
- Rozkład alertów według poziomu zagrożenia
- Macierz konfuzji modelu ML
- Top IP w ruchu
- Rozkład protokołów
- **Mapa geograficzna** z lokalizacją podejrzanych IP (folium)

### Raporty
- Elegancki raport HTML z wszystkimi wynikami
- Osadzone wizualizacje
- Podsumowanie spełnionych wymagań

---

## Przykladowe wyniki

Po uruchomieniu analizy otrzymasz:

```
reports/
├── report_20241117_123456.html    # Główny raport HTML
└── visualizations/                # Wykresy
    ├── alerts_timeline.png
    ├── severity_distribution.png
    ├── confusion_matrix.png
    ├── protocol_distribution.png
    ├── top_dst_ip.png
    └── geo_map.html               # Mapa geograficzna
```

---

## Demonstracja spelnienia wymagan

### Wymaganie A.1 - Wczytywanie PCAP z NFStream
```python
from flow_analyzer import FlowAnalyzer

analyzer = FlowAnalyzer("data/demo_traffic.pcap")
flows = analyzer.load_flows()  # Wczytanie z NFStream
```

### Wymaganie A.2 - Statystyki flow
```python
stats = analyzer.get_flow_statistics()
# Zwraca: total_flows, unique_ips, total_packets, 
#            avg_packets_per_flow, top_host_pairs, etc.
```

### Wymaganie D.1 - Detection as a Code
```python
from detection_rules.detection_rules import create_default_detection_engine

engine = create_default_detection_engine()
alerts = engine.run_detection(flows)  # Reguły w Pythonie
```

### Wymaganie D.2 - Reguły Sigma
```python
from detection_rules.sigma_handler import SigmaRuleEngine

sigma_engine = SigmaRuleEngine()
sigma_engine.load_rules_from_directory("detection_rules/")
alerts = sigma_engine.run_detection(flows)  # Wczytanie Sigma
```

### Wymagania ML.1, ML.2, ML.3 - Machine Learning
```python
from models.ml_classifier import NetworkMLClassifier

classifier = NetworkMLClassifier()
metrics = classifier.train(flows)  # ML.1 - Klasyfikacja

# ML.2 - Metryki FPR, TPR
print(f"FPR: {metrics['fpr']}")
print(f"TPR: {metrics['tpr']}")

# ML.3 - Retrenowanie
classifier.retrain_with_new_data(new_flows, new_labels)
```

### Wymaganie E.1 - Threat Intelligence
```python
from threat_intel import ThreatIntelligenceEnricher

enricher = ThreatIntelligenceEnricher()
enriched = enricher.enrich_flows(flows)  # Geolokalizacja IP
```

### Wymagania V.1, V.2 - Wizualizacje
```python
from visualizations import NetworkVisualizer

viz = NetworkVisualizer()
viz.plot_alerts_timeline(alerts)     # V.1
viz.create_geo_map(enriched_flows)   # V.2
```

---

## Rozszerzenia

### Dodawanie własnych reguł detekcyjnych

```python
from detection_rules.detection_rules import DetectionRule

class MyCustomRule(DetectionRule):
    def __init__(self):
        super().__init__(
            name="My Custom Rule",
            description="Opis reguły",
            severity="high"
        )
    
    def detect(self, flow):
        if flow['dst_port'] == 1234:
            return True, f"Wykryto port 1234 z {flow['src_ip']}"
        return False, ""

# Użycie
engine.add_rule(MyCustomRule())
```

### Dodawanie własnych reguł Sigma

Utwórz plik `.yml` w `detection_rules/`:

```yaml
title: My Sigma Rule
description: Wykrywa specyficzny ruch
level: high
detection:
  selection:
    DestinationPort: 9999
  condition: selection
```

---

## Uwagi

1. **Enrichment IP** może być wolny - API mają limity zapytań
2. **Mapa geograficzna** wymaga biblioteki `folium`
3. **Model ML** używa syntetycznych etykiet do demonstracji - w produkcji należy użyć oznaczonych danych
4. **Reguły Sigma** mają uproszczoną implementację - w produkcji użyj PySigma

---

## Dokumentacja modułów

### flow_analyzer.py
Analiza przepływów sieciowych z NFStream

### detection_rules/detection_rules.py
Silnik reguł detekcyjnych Detection as a Code

### detection_rules/sigma_handler.py
Obsługa reguł w formacie Sigma

### models/ml_classifier.py
Klasyfikator ML z Random Forest

### threat_intel.py
Wzbogacanie danych o Threat Intelligence

### visualizations.py
Generator wykresów i map

### report_generator.py
Generator raportów HTML

### netanalyzer.py
Główny interfejs CLI

### simulate_traffic.py
Generator symulowanego ruchu do testów

---

## Autor

Projekt wykonany w ramach zajęć KRYCY - Politechnika Warszawska

---

## Licencja

Projekt edukacyjny - wykorzystanie zgodnie z polityką uczelni.
