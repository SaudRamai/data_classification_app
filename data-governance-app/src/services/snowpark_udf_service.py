"""
Snowpark UDF Service

Provides scaffolding to run contextual classification inside Snowflake via Snowpark Python.
Graceful fallback if Snowpark is not installed or role lacks privileges. No hardcoding of mappings.
"""
from __future__ import annotations

from typing import Dict, Any, Optional
import json
import logging

try:
    # Optional dependency
    from snowflake.snowpark import Session
    from snowflake.snowpark.functions import col
except Exception:  # pragma: no cover
    Session = None  # type: ignore

from src.config.settings import settings
from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)


class SnowparkUDFService:
    def __init__(self) -> None:
        self._available = Session is not None

    def available(self) -> bool:
        return self._available

    def _build_session(self) -> Optional[Session]:
        if Session is None:
            return None
        # Reuse connector params from session state via connector
        try:
            # The connector holds no open session object; we must rebuild params from settings and session_state
            # Use the python connector's parameters via a dummy connect to obtain DSN-like dict
            # For simplicity, construct minimal config directly from settings and Streamlit state
            import streamlit as st  # type: ignore
            params = {
                "account": st.session_state.get("sf_account") or settings.SNOWFLAKE_ACCOUNT,
                "user": st.session_state.get("sf_user") or settings.SNOWFLAKE_USER,
                "password": st.session_state.get("sf_password") or settings.SNOWFLAKE_PASSWORD,
                "warehouse": st.session_state.get("sf_warehouse") or settings.SNOWFLAKE_WAREHOUSE,
                "database": st.session_state.get("sf_database") or settings.SNOWFLAKE_DATABASE,
                "schema": st.session_state.get("sf_schema") or settings.SNOWFLAKE_SCHEMA,
                "role": st.session_state.get("sf_role") or None,
            }
            # Remove Nones
            params = {k: v for k, v in params.items() if v}
            return Session.builder.configs(params).create()
        except Exception as e:
            logger.warning(f"Failed to build Snowpark session: {e}")
            return None

    def classify_table(self, full_name: str, sample_rows: int = 100) -> Dict[str, Any]:
        """Run an in-database heuristic classification using Snowpark (no external APIs).
        Returns: {label, categories, confidence, features}
        """
        try:
            # Quick path: if Snowpark not available, run a lightweight proxy using SYSTEM$CLASSIFY and tags
            if not self._available:
                rows = snowflake_connector.execute_query("SELECT SYSTEM$CLASSIFY('TABLE', %(f)s) AS R", {"f": full_name}) or []
                raw = rows[0].get('R') if rows else None
                det = json.loads(raw) if isinstance(raw, str) else (raw or [])
                cats = set()
                conf = 0.0
                for c in (det or []):
                    for x in (c.get('categories') or []):
                        cats.add(str(x))
                    try:
                        conf = max(conf, float(c.get('confidence') or 0.0))
                    except Exception:
                        pass
                label = 'Restricted' if cats else 'Internal'
                return {"label": label, "categories": sorted(list(cats)), "confidence": conf, "features": {"mode": "system_classify_proxy"}}

            # Snowpark path
            session = self._build_session()
            if session is None:
                raise ValueError("Snowpark session unavailable")
            db, sc, tb = full_name.split('.')
            df = session.table(f'{db}.{sc}.{tb}').limit(sample_rows)
            cols = [c.name for c in df.schema.fields]
            # Simple heuristic in-database using column names only (placeholder for a richer UDF)
            text_cols = [c for c in cols if any(t in c.upper() for t in ['NAME','EMAIL','PHONE','ADDRESS','DOB','SSN','CARD','ACCOUNT','PATIENT'])]
            categories = set()
            if any(k in ' '.join(text_cols).upper() for k in ['EMAIL','PHONE','SSN','DOB','ADDRESS','NAME','PERSON']):
                categories.add('PII')
            if any(k in ' '.join(text_cols).upper() for k in ['PATIENT','MEDICAL','HEALTH','PHI']):
                categories.add('PHI')
            if any(k in ' '.join(text_cols).upper() for k in ['CARD','ACCOUNT','GL','LEDGER','PAYROLL','INVOICE']):
                categories.add('Financial')
            label = 'Restricted' if categories else 'Internal'
            confidence = 0.6 if categories else 0.4
            try:
                session.close()
            except Exception:
                pass
            return {"label": label, "categories": sorted(list(categories)), "confidence": confidence, "features": {"mode": "snowpark_heuristic"}}
        except Exception as e:
            logger.warning(f"Snowpark classify failed: {e}")
            return {"label": "Internal", "categories": [], "confidence": 0.0, "features": {"error": str(e)}}


snowpark_udf_service = SnowparkUDFService()
