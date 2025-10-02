"""
Continuous Classifier Service

Periodically scans Snowflake tables to:
- Classify assets (Public/Internal/Restricted/Confidential)
- Detect sensitive columns (PII/PHI/Financial/Auth)
- Tag objects/columns with standardized tags
- Optionally apply protection policies (masking/row access)

This module is synchronous, intended to be triggered manually from UI or
scheduled externally (cron, Airflow, Snowflake TASKs invoking a webhook/app).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import pandas as pd

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.ai_classification_service import ai_classification_service
from src.services.tagging_service import tagging_service
from src.services.policy_enforcement_service import policy_enforcement_service


@dataclass
class ScanResult:
    table: str
    classification: str
    frameworks: List[str]
    confidence: float
    sensitive_columns: List[Dict[str, Any]]
    tags_applied: bool
    policies_applied: int


class ContinuousClassifierService:
    def __init__(self):
        pass

    def list_tables(self, database: Optional[str] = None, limit: int = 500) -> List[str]:
        database = database or settings.SNOWFLAKE_DATABASE
        q = f"""
        SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
        FROM {database}.INFORMATION_SCHEMA.TABLES
        WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
        ORDER BY 1
        LIMIT {int(limit)}
        """
        rows = snowflake_connector.execute_query(q) or []
        return [r['FULL'] for r in rows if r.get('FULL')]

    def classify_and_tag_table(self, table: str, apply_policies: bool = True) -> ScanResult:
        # 1) Asset-level classification
        cls = ai_classification_service.classify_table(table)
        label = cls['classification']
        frameworks = cls.get('compliance_frameworks', [])
        conf = float(cls.get('confidence', 0.0))

        # Map classification to CIA defaults (heuristic)
        cia_c = 0
        if label == 'Internal':
            cia_c = 1
        elif label == 'Restricted':
            cia_c = 2
        elif label == 'Confidential':
            cia_c = 3

        # 2) Column-level sensitivity
        sens = ai_classification_service.detect_sensitive_columns(table, sample_size=80)

        # 3) Apply object-level tags
        try:
            tagging_service.apply_tags_to_object(
                table, 'TABLE', {
                    'DATA_CLASSIFICATION': label,
                    'CONFIDENTIALITY_LEVEL': str(cia_c),
                    'INTEGRITY_LEVEL': '1',
                    'AVAILABILITY_LEVEL': '1',
                }
            )
            tags_ok = True
        except Exception:
            tags_ok = False

        # 4) Apply column-level tags for sensitive columns
        for s in sens:
            cats = s.get('categories') or []
            if not cats:
                continue
            try:
                tagging_service.apply_tags_to_column(
                    table,
                    s['column'],
                    {
                        'DATA_CLASSIFICATION': 'Restricted' if 'PII' in cats or 'Financial' in cats or 'Auth' in cats else label,
                        'CONFIDENTIALITY_LEVEL': '2' if ('PII' in cats or 'Financial' in cats or 'Auth' in cats) else str(cia_c),
                        'INTEGRITY_LEVEL': '1',
                        'AVAILABILITY_LEVEL': '1',
                    }
                )
            except Exception:
                continue

        # 5) Optional enforcement
        applied = 0
        if apply_policies:
            try:
                res = policy_enforcement_service.auto_enforce_for_table(table, sens)
                applied = len(res.get('applied', []))
            except Exception:
                applied = 0

        return ScanResult(
            table=table,
            classification=label,
            frameworks=frameworks,
            confidence=conf,
            sensitive_columns=sens,
            tags_applied=tags_ok,
            policies_applied=applied,
        )

    def run_scan(self, limit: int = 50, apply_policies: bool = False) -> Dict[str, Any]:
        tables = self.list_tables(limit=limit)
        results: List[ScanResult] = []
        for t in tables:
            try:
                results.append(self.classify_and_tag_table(t, apply_policies=apply_policies))
            except Exception:
                continue
        # Summaries
        dist: Dict[str, int] = {}
        sens_cols = 0
        enforced = 0
        for r in results:
            dist[r.classification] = dist.get(r.classification, 0) + 1
            sens_cols += sum(1 for c in r.sensitive_columns if c.get('categories'))
            enforced += r.policies_applied
        return {
            'count_tables': len(results),
            'classification_distribution': dist,
            'sensitive_columns': sens_cols,
            'policies_applied': enforced,
            'results': [r.__dict__ for r in results],
        }


continuous_classifier_service = ContinuousClassifierService()
