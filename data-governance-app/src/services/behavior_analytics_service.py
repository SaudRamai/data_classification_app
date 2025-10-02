"""
Behavioral Analytics Service

Monitors Snowflake access/query activity and extracts behavioral features for
anomaly detection and access governance insights.

Design goals:
- Use only Snowflake ACCOUNT_USAGE (or fallbacks) with existing connector
- Lightweight, local inference (no external APIs)
- Safe on least-privilege accounts (graceful fallbacks)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
import math
import pandas as pd

from src.connectors.snowflake_connector import snowflake_connector


@dataclass
class Anomaly:
    user_name: str
    object_name: str
    score: float
    reason: str
    event_count: int
    baseline_mean: float
    baseline_std: float


class BehaviorAnalyticsService:
    """Feature engineering + simple anomaly detection on Snowflake usage logs."""

    def fetch_access_events(self, days: int = 7, limit: int = 50000) -> pd.DataFrame:
        """Fetch recent access/query events with graceful fallbacks.
        Prefers ACCOUNT_USAGE.QUERY_HISTORY. ACCESS_HISTORY may be restricted.
        """
        try:
            q = f"""
            SELECT
              USER_NAME,
              DATABASE_NAME,
              SCHEMA_NAME,
              OBJECTS_MODIFIED, -- array-like; presence indicates DML
              BYTES_SCANNED,
              QUERY_TEXT,
              START_TIME,
              ROWS_PRODUCED,
              ROWS_INSERTED,
              ROWS_UPDATED,
              ROWS_DELETED
            FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
            WHERE START_TIME >= DATEADD(day, -{int(days)}, CURRENT_TIMESTAMP())
            ORDER BY START_TIME DESC
            LIMIT {int(limit)}
            """
            rows = snowflake_connector.execute_query(q) or []
        except Exception:
            rows = []
        df = pd.DataFrame(rows)
        if df.empty:
            return df
        # Derive simple fields
        df['FULL_NAME'] = (
            df.get('DATABASE_NAME', '').astype(str) + '.' + df.get('SCHEMA_NAME', '').astype(str)
        )
        df['IS_WRITE'] = ((df.get('ROWS_INSERTED', 0).fillna(0) + df.get('ROWS_UPDATED', 0).fillna(0) + df.get('ROWS_DELETED', 0).fillna(0)) > 0).astype(int)
        try:
            df['HOUR'] = pd.to_datetime(df['START_TIME']).dt.hour
        except Exception:
            df['HOUR'] = 0
        df['QUERY_LEN'] = df.get('QUERY_TEXT', '').astype(str).str.len()
        df['BYTES_SCANNED'] = pd.to_numeric(df.get('BYTES_SCANNED'), errors='coerce').fillna(0)
        return df

    def aggregate_user_object_counts(self, df: pd.DataFrame) -> pd.DataFrame:
        """Count interactions per (user, object/schema) for anomaly detection."""
        if df is None or df.empty:
            return pd.DataFrame()
        key = df.groupby(['USER_NAME', 'FULL_NAME'], dropna=False).size().reset_index(name='EVENT_COUNT')
        return key

    def zscore_anomalies(self, counts: pd.DataFrame, z_thresh: float = 3.0, top_k: int = 50) -> List[Anomaly]:
        """Simple per-user z-score on object access counts."""
        if counts is None or counts.empty:
            return []
        out: List[Anomaly] = []
        for user, g in counts.groupby('USER_NAME'):
            vals = g['EVENT_COUNT'].astype(float)
            mu = float(vals.mean()) if len(vals) else 0.0
            sigma = float(vals.std(ddof=0)) if len(vals) else 0.0
            for _, row in g.iterrows():
                x = float(row['EVENT_COUNT'])
                z = (x - mu) / (sigma if sigma > 0 else 1.0)
                if z >= z_thresh and x >= max(5, mu + 3 * (sigma if sigma > 0 else 1)):
                    out.append(Anomaly(
                        user_name=str(user),
                        object_name=str(row['FULL_NAME']),
                        score=round(z, 2),
                        reason='High access volume vs user baseline',
                        event_count=int(x),
                        baseline_mean=round(mu, 2),
                        baseline_std=round(sigma, 2),
                    ))
        # Sort by score desc
        out.sort(key=lambda a: a.score, reverse=True)
        return out[:top_k]

    def build_feature_matrix(self, df: pd.DataFrame) -> pd.DataFrame:
        """Feature matrix per query row for ML anomaly models."""
        if df is None or df.empty:
            return pd.DataFrame()
        feats = df[['USER_NAME', 'FULL_NAME', 'HOUR', 'QUERY_LEN', 'BYTES_SCANNED', 'IS_WRITE']].copy()
        return feats


behavior_analytics_service = BehaviorAnalyticsService()
