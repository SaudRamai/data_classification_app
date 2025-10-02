"""
Federated Anomaly Detection Service

Trains per-partition (e.g., schema) anomaly detectors and aggregates their
signals (federated-style) without centralizing row-level data.

- Uses IsolationForest locally on engineered features
- Partitions by schema (derived as FULL_NAME prefix) or user-provided key
- Aggregates anomaly scores to global alerts
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest


@dataclass
class FedAnomaly:
    partition: str
    key: str  # user/object or composite
    score: float
    model_size: int


class FederatedAnomalyService:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state

    def _partition_key(self, full_name: str) -> str:
        try:
            parts = (full_name or '').split('.')
            if len(parts) >= 2:
                return parts[1]  # schema
        except Exception:
            pass
        return 'UNKNOWN'

    def train_partition_models(self, feats: pd.DataFrame, partition_col: str = 'FULL_NAME', feature_cols: Optional[List[str]] = None) -> Dict[str, IsolationForest]:
        if feats is None or feats.empty:
            return {}
        if feature_cols is None:
            feature_cols = [c for c in feats.columns if c not in ['USER_NAME', 'FULL_NAME']]
        models: Dict[str, IsolationForest] = {}
        feats = feats.copy()
        # Derive partition label
        feats['_PART'] = feats[partition_col].astype(str).map(self._partition_key)
        for part, g in feats.groupby('_PART'):
            X = g[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0.0).values
            if len(g) < 20:  # need enough samples
                continue
            try:
                clf = IsolationForest(n_estimators=100, contamination='auto', random_state=self.random_state)
                clf.fit(X)
                models[part] = clf
            except Exception:
                continue
        return models

    def score_anomalies(self, feats: pd.DataFrame, models: Dict[str, IsolationForest], partition_col: str = 'FULL_NAME', feature_cols: Optional[List[str]] = None, top_k: int = 100) -> List[FedAnomaly]:
        if feats is None or feats.empty or not models:
            return []
        if feature_cols is None:
            feature_cols = [c for c in feats.columns if c not in ['USER_NAME', 'FULL_NAME']]
        feats = feats.copy()
        feats['_PART'] = feats[partition_col].astype(str).map(self._partition_key)
        out: List[FedAnomaly] = []
        for part, g in feats.groupby('_PART'):
            model = models.get(part)
            if model is None or g.empty:
                continue
            X = g[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0.0).values
            try:
                scores = model.score_samples(X)  # higher is less anomalous
                anom = (-scores)  # invert
                g_local = g.reset_index(drop=True)
                for i, s in enumerate(anom):
                    key = f"{g_local.loc[i, 'USER_NAME']}|{g_local.loc[i, 'FULL_NAME']}"
                    out.append(FedAnomaly(partition=part, key=key, score=float(s), model_size=int(model.n_estimators_)))
            except Exception:
                continue
        # Sort desc (higher inverted score means more anomalous)
        out.sort(key=lambda r: r.score, reverse=True)
        return out[:top_k]


federated_anomaly_service = FederatedAnomalyService()
