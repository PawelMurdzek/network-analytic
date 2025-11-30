# Reguly Sigma - Dokumentacja

Ten katalog zawiera reguly detekcyjne w formacie Sigma - otwartym standardzie
do opisu regul detekcyjnych niezaleznym od platformy SIEM.

## Spis regul

| Plik | Opis | Poziom | MITRE ATT&CK |
|------|------|--------|--------------|
| `port_scan_detection.yml` | Wykrywanie skanowania portow | Medium | T1046 |
| `cobalt_strike_beacon.yml` | Wykrywanie beaconow Cobalt Strike | Critical | T1071.001 |
| `metasploit_reverse_shell.yml` | Wykrywanie reverse shell (port 4444) | Critical | T1059 |
| `dns_tunneling.yml` | Wykrywanie tunelowania DNS | Medium | T1071.004 |
| `smb_lateral_movement.yml` | Wykrywanie lateral movement przez SMB | High | T1021.002 |
| `rdp_brute_force.yml` | Wykrywanie atakow brute force na RDP | High | T1110 |
| `crypto_mining.yml` | Wykrywanie komunikacji z mining pools | High | T1496 |
| `tor_traffic.yml` | Wykrywanie ruchu Tor | Medium | T1090.003 |
| `data_exfiltration.yml` | Wykrywanie duzych transferow danych | Low | T1048 |
| `ssh_brute_force.yml` | Wykrywanie atakow brute force na SSH | Medium | T1110.001 |

## Struktura reguly Sigma

Kazda regula Sigma to plik YAML z nastepujaca struktura:

```yaml
title: Nazwa reguly (krotka, opisowa)
id: UUID (unikalny identyfikator)
status: experimental | test | stable
description: |
  Szczegolowy opis co regula wykrywa i dlaczego jest wazna.
  Mozna uzyc wielu linii.
author: Autor reguly
date: RRRR/MM/DD
modified: RRRR/MM/DD (opcjonalne)
references:
  - https://link-do-dokumentacji
  - https://attack.mitre.org/techniques/TXXXX/
logsource:
  category: network
  product: flow
detection:
  selection:
    DestinationPort: 4444
  condition: selection
level: low | medium | high | critical
tags:
  - attack.taktyka
  - attack.tXXXX
falsepositives:
  - Opis potencjalnych false positives
fields:
  - src_ip
  - dst_ip
  - dst_port
```

## Jak dodac nowa regule

### Krok 1: Utworz plik YAML

Utworz nowy plik w katalogu `detection_rules/sigma_rules/` z rozszerzeniem `.yml`:

```
detection_rules/sigma_rules/moja_regula.yml
```

### Krok 2: Wypelnij pola obowiazkowe

Minimalna regula:

```yaml
title: Moja Nowa Regula
id: wygeneruj-unikalny-uuid
description: Opis co regula wykrywa
author: Twoje imie
date: 2024/11/30
logsource:
  category: network
  product: flow
detection:
  selection:
    DestinationPort: 12345
  condition: selection
level: medium
```

### Krok 3: Dostepne pola do matchowania

W naszym systemie mozesz uzywac nastepujacych pol:

| Pole Sigma | Pole w systemie | Opis |
|------------|-----------------|------|
| `DestinationPort` | `dst_port` | Port docelowy |
| `SourcePort` | `src_port` | Port zrodlowy |
| `DestinationIp` | `dst_ip` | IP docelowe |
| `SourceIp` | `src_ip` | IP zrodlowe |
| `Protocol` | `protocol` | Protokol (TCP/UDP) |

### Krok 4: Wartosc pojedyncza vs lista

Pojedyncza wartosc:
```yaml
detection:
  selection:
    DestinationPort: 4444
  condition: selection
```

Lista wartosci (OR):
```yaml
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
      - 6666
  condition: selection
```

### Krok 5: Poziomy zagrozen

- `low` - Informacyjne, moze byc normalny ruch
- `medium` - Podejrzane, wymaga uwagi
- `high` - Prawdopodobne zagrozenie, wymaga akcji
- `critical` - Potwierdzony atak, natychmiastowa reakcja

### Krok 6: Tagi MITRE ATT&CK

Dodaj odpowiednie tagi z frameworku MITRE ATT&CK:

```yaml
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059
```

Taktyki MITRE:
- `attack.reconnaissance` - Rekonesans
- `attack.initial_access` - Poczatkowy dostep
- `attack.execution` - Wykonanie
- `attack.persistence` - Persistencja
- `attack.privilege_escalation` - Eskalacja uprawnien
- `attack.defense_evasion` - Unikanie detekcji
- `attack.credential_access` - Pozyskanie poswiadczen
- `attack.discovery` - Odkrywanie
- `attack.lateral_movement` - Ruch boczny
- `attack.collection` - Zbieranie danych
- `attack.command_and_control` - C2
- `attack.exfiltration` - Eksfiltracja
- `attack.impact` - Wplyw

## Testowanie regul

Po dodaniu reguly mozesz ja przetestowac:

```python
from detection_rules.sigma_handler import SigmaRuleEngine

# Wczytaj reguly
engine = SigmaRuleEngine()
engine.load_rules_from_directory("detection_rules/sigma_rules")

# Uruchom detekcje
alerts = engine.run_detection(flows_df)
```

## Przyklady regul dla roznych scenariuszy

### Wykrywanie C2 na nietypowym porcie

```yaml
title: C2 Communication on High Port
id: 12345678-abcd-efgh-ijkl-123456789012
description: Detects outbound connections to high ports often used by C2
logsource:
  category: network
  product: flow
detection:
  selection:
    DestinationPort:
      - 8080
      - 8443
      - 9443
  condition: selection
level: medium
tags:
  - attack.command_and_control
```

### Wykrywanie ruchu do znanych malware

```yaml
title: Known Malware Port
id: 87654321-dcba-hgfe-lkji-987654321012
description: Detects connections to ports associated with known malware
logsource:
  category: network
  product: flow
detection:
  selection:
    DestinationPort:
      - 666   # Often used by backdoors
      - 31337 # Elite/leet backdoor
      - 12345 # NetBus
  condition: selection
level: critical
tags:
  - attack.command_and_control
  - attack.t1095
```

## Zasoby

- [Oficjalna dokumentacja Sigma](https://github.com/SigmaHQ/sigma)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)

## Autor

Security Team - Network Analytic Project
