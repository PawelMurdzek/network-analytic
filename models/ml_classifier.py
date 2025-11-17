"""
Moduł Machine Learning do klasyfikacji ruchu sieciowego.
Wymagania: ML.1, ML.2, ML.3
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve
)
import joblib
import logging
from typing import Dict, Tuple, Optional
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkMLClassifier:
    """
    Klasyfikator ML do analizy ruchu sieciowego.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Args:
            model_path: Ścieżka do zapisanego modelu (opcjonalnie)
        """
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.model_path = model_path
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def prepare_features(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        """
        Przygotowuje cechy do trenowania modelu.
        
        Args:
            flows_df: DataFrame z przepływami
            
        Returns:
            DataFrame z cechami
        """
        features = flows_df.copy()
        
        # Wybór istotnych cech numerycznych
        self.feature_columns = [
            'bidirectional_packets',
            'bidirectional_bytes',
            'src2dst_packets',
            'src2dst_bytes',
            'dst2src_packets',
            'dst2src_bytes',
            'bidirectional_duration_ms',
            'src_port',
            'dst_port',
            'protocol',
        ]
        
        # Upewnienie się, że wszystkie kolumny istnieją
        available_features = [col for col in self.feature_columns if col in features.columns]
        
        if not available_features:
            raise ValueError("Brak wymaganych kolumn w DataFrame")
        
        return features[available_features].fillna(0)
    
    def create_synthetic_labels(self, flows_df: pd.DataFrame) -> pd.Series:
        """
        Tworzy syntetyczne etykiety na podstawie heurystyk (do celów demonstracyjnych).
        W rzeczywistym scenariuszu należy użyć oznaczonych danych.
        
        Args:
            flows_df: DataFrame z przepływami
            
        Returns:
            Serie z etykietami (0 = normal, 1 = suspicious)
        """
        labels = []
        
        for _, flow in flows_df.iterrows():
            # Prosta heurystyka do tworzenia etykiet
            is_suspicious = False
            
            # Podejrzane porty
            suspicious_ports = [4444, 5555, 6667, 31337, 12345]
            if flow['dst_port'] in suspicious_ports:
                is_suspicious = True
            
            # Duże transfery danych
            if flow['bidirectional_bytes'] > 10_000_000:
                is_suspicious = True
            
            # Długie połączenia
            if flow['bidirectional_duration_ms'] > 3600000:
                is_suspicious = True
            
            labels.append(1 if is_suspicious else 0)
        
        return pd.Series(labels)
    
    def train(
        self, 
        flows_df: pd.DataFrame, 
        labels: Optional[pd.Series] = None,
        test_size: float = 0.3,
        tune_hyperparameters: bool = True
    ) -> Dict:
        """
        Trenuje model ML.
        Wymaganie: ML.1, ML.3
        
        Args:
            flows_df: DataFrame z przepływami
            labels: Etykiety (opcjonalnie, jeśli None - tworzy syntetyczne)
            test_size: Rozmiar zbioru testowego
            tune_hyperparameters: Czy wykonać tuning hiperparametrów
            
        Returns:
            Słownik z metrykami
        """
        logger.info("Rozpoczęcie trenowania modelu ML...")
        
        # Przygotowanie cech
        X = self.prepare_features(flows_df)
        
        # Przygotowanie etykiet
        if labels is None:
            logger.warning("Brak etykiet - tworzenie syntetycznych etykiet")
            y = self.create_synthetic_labels(flows_df)
        else:
            y = labels
        
        # Podział na zbiór treningowy i testowy
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Skalowanie cech
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Trenowanie modelu
        if tune_hyperparameters:
            logger.info("Wykonywanie tuningu hiperparametrów...")
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
            
            rf = RandomForestClassifier(random_state=42)
            grid_search = GridSearchCV(
                rf, param_grid, cv=3, scoring='f1', n_jobs=-1, verbose=1
            )
            grid_search.fit(X_train_scaled, y_train)
            self.model = grid_search.best_estimator_
            logger.info(f"Najlepsze parametry: {grid_search.best_params_}")
        else:
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=20, random_state=42
            )
            self.model.fit(X_train_scaled, y_train)
        
        # Predykcja
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Obliczenie metryk (Wymaganie ML.2)
        metrics = self.calculate_metrics(y_test, y_pred, y_pred_proba)
        
        logger.info(f"Model wytrenowany. Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def calculate_metrics(
        self, 
        y_true: np.ndarray, 
        y_pred: np.ndarray,
        y_pred_proba: Optional[np.ndarray] = None
    ) -> Dict:
        """
        Oblicza metryki jakości modelu.
        Wymaganie: ML.2
        
        Args:
            y_true: Prawdziwe etykiety
            y_pred: Predykcje modelu
            y_pred_proba: Prawdopodobieństwa predykcji
            
        Returns:
            Słownik z metrykami
        """
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
        }
        
        # Macierz konfuzji
        cm = confusion_matrix(y_true, y_pred)
        
        # Obliczenie TPR i FPR
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            
            # True Positive Rate (Sensitivity/Recall)
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            
            # False Positive Rate
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            # True Negative Rate (Specificity)
            tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
            
            metrics['tpr'] = tpr
            metrics['fpr'] = fpr
            metrics['tnr'] = tnr
            metrics['confusion_matrix'] = cm.tolist()
        
        # AUC-ROC jeśli dostępne prawdopodobieństwa
        if y_pred_proba is not None:
            try:
                metrics['auc_roc'] = roc_auc_score(y_true, y_pred_proba)
            except:
                metrics['auc_roc'] = None
        
        return metrics
    
    def predict(self, flows_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Wykonuje predykcję na przepływach.
        
        Args:
            flows_df: DataFrame z przepływami
            
        Returns:
            Tuple (predykcje, prawdopodobieństwa)
        """
        if self.model is None:
            raise ValueError("Model nie jest wytrenowany. Użyj train() lub load_model()")
        
        X = self.prepare_features(flows_df)
        X_scaled = self.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        return predictions, probabilities
    
    def save_model(self, path: str):
        """
        Zapisuje model do pliku.
        
        Args:
            path: Ścieżka do zapisu
        """
        if self.model is None:
            raise ValueError("Model nie jest wytrenowany")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Model zapisany do: {path}")
    
    def load_model(self, path: str):
        """
        Wczytuje model z pliku.
        
        Args:
            path: Ścieżka do modelu
        """
        model_data = joblib.load(path)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        
        logger.info(f"Model wczytany z: {path}")
    
    def retrain_with_new_data(
        self, 
        new_flows_df: pd.DataFrame, 
        new_labels: pd.Series
    ) -> Dict:
        """
        Ponownie trenuje model z nowymi danymi.
        Wymaganie: ML.3
        
        Args:
            new_flows_df: DataFrame z nowymi przepływami
            new_labels: Etykiety dla nowych danych
            
        Returns:
            Słownik z metrykami
        """
        logger.info("Ponowne trenowanie modelu z nowymi danymi...")
        
        return self.train(new_flows_df, new_labels, tune_hyperparameters=False)
    
    def get_feature_importance(self) -> pd.DataFrame:
        """
        Zwraca ważność cech.
        
        Returns:
            DataFrame z ważnością cech
        """
        if self.model is None or self.feature_columns is None:
            raise ValueError("Model nie jest wytrenowany")
        
        importance_df = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return importance_df


if __name__ == "__main__":
    # Przykład użycia
    import sys
    sys.path.append('..')
    from flow_analyzer import FlowAnalyzer
    
    if len(sys.argv) < 2:
        print("Użycie: python ml_classifier.py <ścieżka_do_pliku_pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Wczytanie przepływów
    analyzer = FlowAnalyzer(pcap_file)
    flows = analyzer.load_flows()
    
    # Utworzenie i trenowanie modelu
    classifier = NetworkMLClassifier()
    metrics = classifier.train(flows, tune_hyperparameters=False)
    
    # Wyświetlenie metryk
    print("\n=== METRYKI MODELU ML ===")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall (TPR): {metrics['recall']:.4f}")
    print(f"F1 Score: {metrics['f1_score']:.4f}")
    print(f"False Positive Rate (FPR): {metrics['fpr']:.4f}")
    print(f"True Negative Rate (Specificity): {metrics['tnr']:.4f}")
    
    if 'auc_roc' in metrics and metrics['auc_roc']:
        print(f"AUC-ROC: {metrics['auc_roc']:.4f}")
    
    # Macierz konfuzji
    print("\nMacierz konfuzji:")
    print(np.array(metrics['confusion_matrix']))
    
    # Zapis modelu
    model_path = "../models/network_classifier.pkl"
    classifier.save_model(model_path)
