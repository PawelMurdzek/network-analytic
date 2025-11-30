"""
Generator raportów LaTeX z wynikami analizy sieciowej.
Tworzy profesjonalne dokumenty PDF.
"""

import pandas as pd
from typing import Dict, List, Optional
import os
from datetime import datetime
import logging
import subprocess
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LaTeXReportGenerator:
    """
    Generator raportów w formacie LaTeX.
    """
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Args:
            output_dir: Katalog do zapisywania raportów
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_latex_report(
        self,
        flows: pd.DataFrame,
        stats: Dict,
        alerts: Optional[pd.DataFrame] = None,
        ml_metrics: Optional[Dict] = None,
        enriched_flows: Optional[pd.DataFrame] = None,
        visualization_paths: Optional[Dict] = None,
        title: str = "Raport Analizy Ruchu Sieciowego",
        author: str = "System Analizy Sieciowej",
        compile_pdf: bool = True
    ) -> str:
        """
        Generuje raport LaTeX z wynikami analizy.
        
        Args:
            flows: DataFrame z przepływami
            stats: Słownik ze statystykami
            alerts: DataFrame z alertami
            ml_metrics: Metryki modelu ML
            enriched_flows: Przepływy wzbogacone o Threat Intel
            visualization_paths: Ścieżki do wizualizacji
            title: Tytuł raportu
            author: Autor raportu
            compile_pdf: Czy kompilować do PDF
            
        Returns:
            Ścieżka do wygenerowanego pliku .tex (lub .pdf)
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"report_{timestamp}"
        tex_path = os.path.join(self.output_dir, f"{report_name}.tex")
        
        # Budowanie dokumentu LaTeX
        latex_content = self._build_latex_document(
            flows=flows,
            stats=stats,
            alerts=alerts,
            ml_metrics=ml_metrics,
            enriched_flows=enriched_flows,
            visualization_paths=visualization_paths,
            title=title,
            author=author,
            timestamp=timestamp
        )
        
        # Zapis pliku .tex
        with open(tex_path, 'w', encoding='utf-8') as f:
            f.write(latex_content)
        
        logger.info(f"Raport LaTeX wygenerowany: {tex_path}")
        
        # Kompilacja do PDF
        if compile_pdf:
            pdf_path = self._compile_to_pdf(tex_path)
            if pdf_path:
                return pdf_path
        
        return tex_path
    
    def _build_latex_document(
        self,
        flows: pd.DataFrame,
        stats: Dict,
        alerts: Optional[pd.DataFrame],
        ml_metrics: Optional[Dict],
        enriched_flows: Optional[pd.DataFrame],
        visualization_paths: Optional[Dict],
        title: str,
        author: str,
        timestamp: str
    ) -> str:
        """Buduje pełny dokument LaTeX."""
        
        doc = self._get_preamble(title, author)
        doc += self._get_document_begin()
        
        # Strona tytułowa
        doc += self._get_title_page(title, author, timestamp)
        
        # Spis treści
        doc += r"""
\tableofcontents
\newpage
"""
        
        # Sekcja 1: Wstęp
        doc += self._get_introduction_section()
        
        # Sekcja 2: Statystyki przepływów
        doc += self._get_flow_statistics_section(stats)
        
        # Sekcja 3: Wykryte zagrożenia
        if alerts is not None and not alerts.empty:
            doc += self._get_alerts_section(alerts)
        
        # Sekcja 4: Machine Learning
        if ml_metrics:
            doc += self._get_ml_section(ml_metrics)
        
        # Sekcja 5: Threat Intelligence
        if enriched_flows is not None:
            doc += self._get_threat_intel_section(enriched_flows)
        
        # Sekcja 6: Wizualizacje
        if visualization_paths:
            doc += self._get_visualizations_section(visualization_paths)
        
        # Sekcja 7: Podsumowanie
        doc += self._get_summary_section(stats, alerts, ml_metrics)
        
        # Zakończenie dokumentu
        doc += self._get_document_end()
        
        return doc
    
    def _get_preamble(self, title: str, author: str) -> str:
        """Zwraca preambułę dokumentu LaTeX."""
        return r"""\documentclass[12pt,a4paper]{article}

% Kodowanie i język
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[polish]{babel}

% Marginesy
\usepackage[margin=2.5cm]{geometry}

% Grafika i tabele
\usepackage{graphicx}
\usepackage{float}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{multirow}
\usepackage{colortbl}
\usepackage{xcolor}

% Matematyka
\usepackage{amsmath}
\usepackage{amsfonts}

% Linki i odnośniki
\usepackage{hyperref}
\hypersetup{
    colorlinks=true,
    linkcolor=blue,
    urlcolor=blue,
    citecolor=blue
}

% Nagłówki i stopki
\usepackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\rhead{Analiza Ruchu Sieciowego}
\lhead{\leftmark}
\rfoot{Strona \thepage}

% Listingi kodu
\usepackage{listings}
\lstset{
    basicstyle=\ttfamily\small,
    breaklines=true,
    frame=single,
    backgroundcolor=\color{gray!10}
}

% Definicje kolorów
\definecolor{headerblue}{RGB}{102,126,234}
\definecolor{alertred}{RGB}{244,67,54}
\definecolor{alertorange}{RGB}{255,152,0}
\definecolor{alertgreen}{RGB}{76,175,80}

% Niestandardowe komendy
\newcommand{\alerthigh}[1]{\colorbox{alertred!20}{\textcolor{alertred}{\textbf{#1}}}}
\newcommand{\alertmedium}[1]{\colorbox{alertorange!20}{\textcolor{alertorange}{\textbf{#1}}}}
\newcommand{\alertlow}[1]{\colorbox{alertgreen!20}{\textcolor{alertgreen}{\textbf{#1}}}}

"""
    
    def _get_document_begin(self) -> str:
        """Zwraca początek dokumentu."""
        return r"""
\begin{document}
"""
    
    def _get_title_page(self, title: str, author: str, timestamp: str) -> str:
        """Zwraca stronę tytułową."""
        date_formatted = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%d.%m.%Y, %H:%M")
        
        return rf"""
\begin{{titlepage}}
    \centering
    \vspace*{{2cm}}
    
    \rule{{\textwidth}}{{1.5pt}}
    \vspace{{0.5cm}}
    
    {{\Huge \textbf{{{title}}}}}
    
    \vspace{{0.5cm}}
    \rule{{\textwidth}}{{1.5pt}}
    
    \vspace{{2cm}}
    
    {{\Large System Detection as a Code}}\\[0.5cm]
    {{\Large + Machine Learning + Threat Intelligence}}
    
    \vspace{{3cm}}
    
    {{\large \textbf{{Autor:}} {author}}}\\[0.5cm]
    {{\large \textbf{{Data:}} {date_formatted}}}
    
    \vspace{{2cm}}
    
    \includegraphics[width=0.3\textwidth]{{example-image}}
    
    \vfill
    
    {{\small Wygenerowano automatycznie przez system analizy sieciowej}}
    
\end{{titlepage}}
"""
    
    def _get_introduction_section(self) -> str:
        """Zwraca sekcję wprowadzenia."""
        return r"""
\section{Wprowadzenie}

Niniejszy raport przedstawia wyniki analizy ruchu sieciowego przeprowadzonej za pomocą zaawansowanego systemu detekcji zagrożeń. System wykorzystuje następujące komponenty:

\begin{itemize}
    \item \textbf{Analiza przepływów (Flow Analysis)} -- przetwarzanie plików PCAP przy użyciu NFStream/Scapy
    \item \textbf{Detection as a Code} -- reguły detekcyjne w Pythonie oraz format Sigma
    \item \textbf{Machine Learning} -- klasyfikacja przepływów przy użyciu algorytmów ML
    \item \textbf{Threat Intelligence} -- wzbogacanie danych o informacje geolokalizacyjne i reputacyjne
\end{itemize}

\subsection{Metodologia}

Analiza została przeprowadzona zgodnie z następującymi krokami:
\begin{enumerate}
    \item Wczytanie i parsowanie pliku PCAP
    \item Ekstrakcja przepływów sieciowych (5-tuple)
    \item Wykonanie reguł detekcyjnych
    \item Klasyfikacja ML
    \item Wzbogacenie o dane Threat Intelligence
    \item Generowanie wizualizacji i raportu
\end{enumerate}

"""
    
    def _get_flow_statistics_section(self, stats: Dict) -> str:
        """Zwraca sekcję ze statystykami przepływów."""
        
        # Top 5 par hostów
        top_pairs_rows = ""
        for i, pair in enumerate(stats.get('top_host_pairs', [])[:5], 1):
            top_pairs_rows += f"        {i} & {pair['src_ip']} & {pair['dst_ip']} & {pair['total_packets']:,} & {pair['total_bytes']:,} \\\\\n"
        
        # Protokoły
        protocols_text = ""
        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        for proto, count in stats.get('protocols', {}).items():
            proto_name = protocol_map.get(proto, f'Protocol {proto}')
            protocols_text += f"    \\item {proto_name}: {count} przepływów\n"
        
        return rf"""
\section{{Statystyki Przepływów}}
\label{{sec:statistics}}

Ta sekcja przedstawia podstawowe statystyki analizowanego ruchu sieciowego.

\subsection{{Podsumowanie}}

\begin{{table}}[H]
\centering
\caption{{Podstawowe statystyki przepływów}}
\begin{{tabular}}{{|l|r|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{Metryka}} & \textbf{{Wartość}} \\
\hline
Całkowita liczba przepływów & {stats.get('total_flows', 0):,} \\
Unikalne IP źródłowe & {stats.get('unique_src_ips', 0):,} \\
Unikalne IP docelowe & {stats.get('unique_dst_ips', 0):,} \\
Całkowita liczba pakietów & {stats.get('total_packets', 0):,} \\
Całkowita liczba bajtów & {stats.get('total_bytes', 0):,} \\
Średnia pakietów/przepływ & {stats.get('avg_packets_per_flow', 0):.2f} \\
Średnia bajtów/przepływ & {stats.get('avg_bytes_per_flow', 0):.2f} \\
\hline
\end{{tabular}}
\end{{table}}

\subsection{{Rozkład protokołów}}

W analizowanym ruchu wykryto następujące protokoły:
\begin{{itemize}}
{protocols_text}\end{{itemize}}

\subsection{{Top 5 komunikacji między hostami}}

\begin{{table}}[H]
\centering
\caption{{Najczęściej komunikujące się pary hostów}}
\begin{{tabular}}{{|c|l|l|r|r|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{\#}} & \textbf{{IP Źródłowe}} & \textbf{{IP Docelowe}} & \textbf{{Pakiety}} & \textbf{{Bajty}} \\
\hline
{top_pairs_rows}\hline
\end{{tabular}}
\end{{table}}

"""
    
    def _get_alerts_section(self, alerts: pd.DataFrame) -> str:
        """Zwraca sekcje z alertami."""
        
        # Statystyki alertow
        severity_counts = alerts['severity'].value_counts() if 'severity' in alerts.columns else {}
        
        high_count = severity_counts.get('high', 0) + severity_counts.get('critical', 0)
        medium_count = severity_counts.get('medium', 0)
        low_count = severity_counts.get('low', 0)
        
        # Tabela alertow (max 15)
        alerts_rows = ""
        for i, (_, alert) in enumerate(alerts.head(15).iterrows(), 1):
            rule = self._escape_latex(str(alert.get('rule', 'Unknown'))[:30])
            severity = alert.get('severity', 'low')
            message = self._escape_latex(str(alert.get('message', ''))[:50])
            
            severity_cmd = {
                'high': r'\alerthigh{HIGH}',
                'critical': r'\alerthigh{CRITICAL}',
                'medium': r'\alertmedium{MEDIUM}',
                'low': r'\alertlow{LOW}'
            }.get(severity, severity.upper())
            
            alerts_rows += f"        {i} & {rule} & {severity_cmd} & {message} \\\\\n"
        
        # Tabela regul Sigma
        sigma_rules_table = self._get_sigma_rules_table()
        
        return rf"""
\section{{Wykryte Zagrozenia}}
\label{{sec:alerts}}

System detekcji zidentyfikowal \textbf{{{len(alerts)}}} alertow bezpieczenstwa.

\subsection{{Rozklad wedlug poziomu zagrozenia}}

\begin{{table}}[H]
\centering
\caption{{Podział alertów według severity}}
\begin{{tabular}}{{|l|c|c|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{Poziom}} & \textbf{{Liczba}} & \textbf{{Procent}} \\
\hline
\alerthigh{{HIGH/CRITICAL}} & {high_count} & {high_count/len(alerts)*100:.1f}\% \\
\alertmedium{{MEDIUM}} & {medium_count} & {medium_count/len(alerts)*100:.1f}\% \\
\alertlow{{LOW}} & {low_count} & {low_count/len(alerts)*100:.1f}\% \\
\hline
\textbf{{RAZEM}} & \textbf{{{len(alerts)}}} & \textbf{{100\%}} \\
\hline
\end{{tabular}}
\end{{table}}

\subsection{{Lista wykrytych alertów}}

\begin{{longtable}}{{|c|p{{4cm}}|c|p{{6cm}}|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{\#}} & \textbf{{Reguła}} & \textbf{{Poziom}} & \textbf{{Wiadomość}} \\
\hline
\endfirsthead
\hline
\rowcolor{{headerblue!20}}
\textbf{{\#}} & \textbf{{Regula}} & \textbf{{Poziom}} & \textbf{{Wiadomosc}} \\
\hline
\endhead
{alerts_rows}\hline
\end{{longtable}}

{sigma_rules_table}
"""
    
    def _get_ml_section(self, ml_metrics: Dict) -> str:
        """Zwraca sekcję z wynikami ML."""
        
        # Macierz konfuzji
        cm = ml_metrics.get('confusion_matrix', [[0, 0], [0, 0]])
        tn, fp = cm[0] if len(cm) > 0 else (0, 0)
        fn, tp = cm[1] if len(cm) > 1 else (0, 0)
        
        return rf"""
\section{{Wyniki Klasyfikacji Machine Learning}}
\label{{sec:ml}}

Model Machine Learning został wykorzystany do klasyfikacji przepływów sieciowych jako normalne lub podejrzane.

\subsection{{Metryki jakości modelu}}

\begin{{table}}[H]
\centering
\caption{{Metryki wydajności klasyfikatora}}
\begin{{tabular}}{{|l|c|l|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{Metryka}} & \textbf{{Wartość}} & \textbf{{Opis}} \\
\hline
Accuracy & {ml_metrics.get('accuracy', 0):.4f} & Ogólna dokładność \\
Precision & {ml_metrics.get('precision', 0):.4f} & Precyzja (PPV) \\
Recall (TPR) & {ml_metrics.get('recall', ml_metrics.get('tpr', 0)):.4f} & True Positive Rate \\
F1 Score & {ml_metrics.get('f1_score', 0):.4f} & Średnia harmoniczna P i R \\
\hline
\rowcolor{{alertred!10}}
FPR & {ml_metrics.get('fpr', 0):.4f} & False Positive Rate \\
TNR & {ml_metrics.get('tnr', 0):.4f} & True Negative Rate \\
\hline
\end{{tabular}}
\end{{table}}

\subsection{{Macierz konfuzji}}

\begin{{table}}[H]
\centering
\caption{{Macierz konfuzji}}
\begin{{tabular}}{{|c|c|c|}}
\hline
\rowcolor{{headerblue!20}}
 & \textbf{{Pred: Normal}} & \textbf{{Pred: Suspicious}} \\
\hline
\textbf{{Real: Normal}} & {tn} (TN) & {fp} (FP) \\
\textbf{{Real: Suspicious}} & {fn} (FN) & {tp} (TP) \\
\hline
\end{{tabular}}
\end{{table}}

\subsection{{Interpretacja}}

\begin{{itemize}}
    \item \textbf{{True Positives (TP)}}: {tp} -- poprawnie wykryte zagrożenia
    \item \textbf{{True Negatives (TN)}}: {tn} -- poprawnie sklasyfikowany normalny ruch
    \item \textbf{{False Positives (FP)}}: {fp} -- fałszywe alarmy (normalny ruch oznaczony jako zagrożenie)
    \item \textbf{{False Negatives (FN)}}: {fn} -- pominięte zagrożenia
\end{{itemize}}

"""
    
    def _get_threat_intel_section(self, enriched_flows: pd.DataFrame) -> str:
        """Zwraca sekcję Threat Intelligence."""
        
        # Statystyki krajów
        countries = enriched_flows.get('dst_country', pd.Series()).value_counts().head(10)
        countries_rows = ""
        for country, count in countries.items():
            if pd.notna(country):
                countries_rows += f"        {self._escape_latex(str(country))} & {count} \\\\\n"
        
        return rf"""
\section{{Threat Intelligence}}
\label{{sec:threatintel}}

Przepływy zostały wzbogacone o dane geolokalizacyjne i informacje o reputacji adresów IP.

\subsection{{Top 10 krajów docelowych}}

\begin{{table}}[H]
\centering
\caption{{Rozkład geograficzny ruchu docelowego}}
\begin{{tabular}}{{|l|r|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{Kraj}} & \textbf{{Liczba przepływów}} \\
\hline
{countries_rows}\hline
\end{{tabular}}
\end{{table}}

\subsection{{Źródła danych Threat Intelligence}}

System wykorzystuje następujące źródła danych:
\begin{{itemize}}
    \item \textbf{{ip-api.com}} -- geolokalizacja IP (kraj, miasto, ISP)
    \item \textbf{{AbuseIPDB}} -- reputacja IP, raporty o nadużyciach (opcjonalnie)
    \item \textbf{{VirusTotal}} -- analiza złośliwości IP (opcjonalnie)
\end{{itemize}}

"""
    
    def _get_visualizations_section(self, visualization_paths: Dict) -> str:
        """Zwraca sekcję z wizualizacjami."""
        
        figures = ""
        for name, path in visualization_paths.items():
            if path and os.path.exists(path) and path.endswith('.png'):
                # Kopiuj obraz do katalogu raportów
                img_name = os.path.basename(path)
                figures += rf"""
\begin{{figure}}[H]
    \centering
    \includegraphics[width=0.9\textwidth]{{{img_name}}}
    \caption{{{name.replace('_', ' ').title()}}}
\end{{figure}}

"""
        
        return rf"""
\section{{Wizualizacje}}
\label{{sec:visualizations}}

Poniżej przedstawiono wizualizacje wyników analizy.

{figures}

"""
    
    def _get_summary_section(
        self, 
        stats: Dict, 
        alerts: Optional[pd.DataFrame], 
        ml_metrics: Optional[Dict]
    ) -> str:
        """Zwraca sekcję podsumowania."""
        
        alerts_count = len(alerts) if alerts is not None else 0
        high_severity = 0
        if alerts is not None and 'severity' in alerts.columns:
            high_severity = len(alerts[alerts['severity'].isin(['high', 'critical'])])
        
        # Przygotowanie linii o ML (nie mozna uzyc backslash w f-stringu)
        if ml_metrics:
            accuracy_pct = f"{ml_metrics.get('accuracy', 0):.2%}"
            ml_accuracy_line = f"\\item Model ML osiagnal dokladnosc \\textbf{{{accuracy_pct}}}"
        else:
            ml_accuracy_line = ""
        
        return rf"""
\section{{Podsumowanie i wnioski}}
\label{{sec:summary}}

\subsection{{Kluczowe ustalenia}}

\begin{{enumerate}}
    \item Przeanalizowano \textbf{{{stats.get('total_flows', 0):,}}} przeplywow sieciowych
    \item Wykryto \textbf{{{alerts_count}}} alertow bezpieczenstwa, w tym \textbf{{{high_severity}}} o wysokim priorytecie
    \item Ruch sieciowy obejmowal \textbf{{{stats.get('unique_src_ips', 0)}}} unikalnych zrodlowych i \textbf{{{stats.get('unique_dst_ips', 0)}}} docelowych adresow IP
    {ml_accuracy_line}
\end{{enumerate}}

\subsection{{Rekomendacje}}

Na podstawie przeprowadzonej analizy zaleca się:
\begin{{itemize}}
    \item Zbadanie alertów o wysokim priorytecie
    \item Weryfikacja podejrzanych adresów IP w systemach SIEM
    \item Aktualizacja reguł detekcyjnych na podstawie wykrytych wzorców
    \item Rozważenie blokady najbardziej podejrzanych adresów IP na firewallu
\end{{itemize}}

\subsection{{Spełnione wymagania projektowe}}

\begin{{table}}[H]
\centering
\caption{{Lista spełnionych wymagań}}
\begin{{tabular}}{{|c|l|c|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{ID}} & \textbf{{Wymaganie}} & \textbf{{Status}} \\
\hline
A.1 & Wczytywanie PCAP (NFStream/Scapy) & \checkmark \\
A.2 & Statystyki przepływów & \checkmark \\
D.1 & Reguły detekcyjne Python & \checkmark \\
D.2 & Reguły Sigma & \checkmark \\
ML.1 & Klasyfikacja ML & \checkmark \\
ML.2 & Metryki FPR/TPR & \checkmark \\
ML.3 & Trenowanie na nowych danych & \checkmark \\
E.1 & Threat Intelligence enrichment & \checkmark \\
V.1 & Wizualizacje alertów & \checkmark \\
V.2 & Mapa geograficzna & \checkmark \\
\hline
\end{{tabular}}
\end{{table}}

"""
    
    def _get_document_end(self) -> str:
        """Zwraca zakończenie dokumentu."""
        return r"""
\end{document}
"""
    
    def _escape_latex(self, text: str) -> str:
        """Escapuje znaki specjalne LaTeX."""
        if not isinstance(text, str):
            return str(text)
        
        replacements = [
            ('\\', r'\textbackslash{}'),
            ('&', r'\&'),
            ('%', r'\%'),
            ('$', r'\$'),
            ('#', r'\#'),
            ('_', r'\_'),
            ('{', r'\{'),
            ('}', r'\}'),
            ('~', r'\textasciitilde{}'),
            ('^', r'\textasciicircum{}'),
        ]
        
        for old, new in replacements:
            text = text.replace(old, new)
        
        return text
    
    def _get_sigma_rules_table(self) -> str:
        """Zwraca tabele z dostepnymi regulami Sigma."""
        import yaml
        
        sigma_rules_dir = os.path.join(os.path.dirname(__file__), 'detection_rules', 'sigma_rules')
        if not os.path.exists(sigma_rules_dir):
            sigma_rules_dir = 'detection_rules/sigma_rules'
        
        if not os.path.exists(sigma_rules_dir):
            return ""
        
        rules_info = []
        for filename in os.listdir(sigma_rules_dir):
            if filename.endswith('.yml'):
                try:
                    with open(os.path.join(sigma_rules_dir, filename), 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                    
                    tags = rule.get('tags', [])
                    mitre_tags = [t.split('.')[-1].upper() for t in tags if t.startswith('attack.t')]
                    
                    rules_info.append({
                        'title': rule.get('title', 'Unknown')[:35],
                        'level': rule.get('level', 'N/A'),
                        'mitre': ', '.join(mitre_tags[:2]) if mitre_tags else 'N/A'
                    })
                except:
                    pass
        
        if not rules_info:
            return ""
        
        rows = ""
        for rule in rules_info:
            title = self._escape_latex(rule['title'])
            level = rule['level'].upper()
            mitre = rule['mitre']
            rows += f"        {title} & {level} & {mitre} \\\\\n"
        
        return rf"""
\subsection{{Dostepne reguly Sigma}}

System wykorzystuje reguly Sigma zgodne z frameworkiem MITRE ATT\&CK:

\begin{{table}}[H]
\centering
\caption{{Lista regul Sigma}}
\begin{{tabular}}{{|p{{6cm}}|c|c|}}
\hline
\rowcolor{{headerblue!20}}
\textbf{{Regula}} & \textbf{{Poziom}} & \textbf{{MITRE}} \\
\hline
{rows}\hline
\end{{tabular}}
\end{{table}}

"""
    
    def _compile_to_pdf(self, tex_path: str) -> Optional[str]:
        """Kompiluje plik .tex do PDF używając pdflatex."""
        
        # Sprawdzenie czy pdflatex jest dostępny
        if not shutil.which('pdflatex'):
            logger.warning("pdflatex nie znaleziony - PDF nie zostanie wygenerowany")
            logger.info("Zainstaluj MiKTeX lub TeX Live aby generować PDF")
            return None
        
        try:
            output_dir = os.path.dirname(tex_path)
            
            # Uruchomienie pdflatex (2 razy dla poprawnych odnośników)
            for _ in range(2):
                result = subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', '-output-directory', output_dir, tex_path],
                    capture_output=True,
                    text=True,
                    cwd=output_dir
                )
            
            pdf_path = tex_path.replace('.tex', '.pdf')
            
            if os.path.exists(pdf_path):
                logger.info(f"PDF wygenerowany: {pdf_path}")
                
                # Usunięcie plików pomocniczych
                for ext in ['.aux', '.log', '.out', '.toc']:
                    aux_file = tex_path.replace('.tex', ext)
                    if os.path.exists(aux_file):
                        os.remove(aux_file)
                
                return pdf_path
            else:
                logger.warning("Kompilacja PDF nie powiodła się")
                return None
                
        except Exception as e:
            logger.error(f"Błąd podczas kompilacji PDF: {e}")
            return None


if __name__ == "__main__":
    # Przykład użycia
    logger.info("Generator raportów LaTeX gotowy do użycia")
    
    # Test z przykładowymi danymi
    import pandas as pd
    
    sample_stats = {
        'total_flows': 150,
        'unique_src_ips': 25,
        'unique_dst_ips': 45,
        'total_packets': 1500,
        'total_bytes': 250000,
        'avg_packets_per_flow': 10.0,
        'avg_bytes_per_flow': 1666.67,
        'protocols': {6: 100, 17: 40, 1: 10},
        'top_host_pairs': [
            {'src_ip': '192.168.1.10', 'dst_ip': '8.8.8.8', 'total_packets': 100, 'total_bytes': 5000},
            {'src_ip': '192.168.1.20', 'dst_ip': '1.1.1.1', 'total_packets': 80, 'total_bytes': 4000},
        ]
    }
    
    sample_alerts = pd.DataFrame([
        {'rule': 'Port Scan Detection', 'severity': 'high', 'message': 'Detected port scan from 192.168.1.99'},
        {'rule': 'Suspicious Port', 'severity': 'medium', 'message': 'Connection to port 4444'},
    ])
    
    sample_ml = {
        'accuracy': 0.95,
        'precision': 0.92,
        'recall': 0.88,
        'f1_score': 0.90,
        'fpr': 0.05,
        'tnr': 0.95,
        'tpr': 0.88,
        'confusion_matrix': [[90, 5], [10, 45]]
    }
    
    generator = LaTeXReportGenerator(output_dir="./test_reports")
    path = generator.generate_latex_report(
        flows=pd.DataFrame(),
        stats=sample_stats,
        alerts=sample_alerts,
        ml_metrics=sample_ml,
        compile_pdf=False  # Nie kompiluj jeśli nie ma pdflatex
    )
    
    print(f"Raport wygenerowany: {path}")
