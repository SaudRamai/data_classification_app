"""
Classification Audit Service

- Centralized service for all audit-related concerns including classification history and general workflow events.
- Designates a single authoritative layer for audit writes and reads.
- Delegates to repository layers for Snowflake interactions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
import json
import hashlib

from src.services.repositories import audit_repository as _audit_repo
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

try:
    import streamlit as st
except Exception:
    st = None

logger = logging.getLogger(__name__)

class ClassificationAuditService:
    def __init__(self) -> None:
        self._ensure_initialized = False

    def _get_db(self) -> str:
        """Resolve database from session or settings."""
        db = None
        try:
            if st is not None:
                db = st.session_state.get("sf_database")
        except Exception:
            pass
        
        if not db:
            db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            
        if not db or str(db).strip().upper() == 'NONE':
            # Last resort default if everything else fails
            return "DATA_CLASSIFICATION_DB"
        return str(db).strip()

    def _ensure_tables(self) -> None:
        """Lazy initialization of tables."""
        if self._ensure_initialized:
            return
        try:
            db = self._get_db()
            _audit_repo.ensure_audit_tables(db)
            self._ensure_initialized = True
        except Exception as e:
            logger.error(f"Failed to ensure audit tables: {e}")

    def log(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a generic workflow event.
        Alias for log_workflow_event provided for backward compatibility with audit_service.
        """
        self.log_workflow_event(user_id, action, resource_type, resource_id, details)

    def log_workflow_event(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a workflow event into the AUDIT_LOG table."""
        try:
            self._ensure_tables()
            db = self._get_db()
            _audit_repo.insert_audit_log(db, user_id, action, resource_type, resource_id, details)
        except Exception as e:
            logger.error(f"Failed to log workflow event: {e}")


    def fetch_audit(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        dataset_name: Optional[str] = None,
        classification_levels: Optional[List[str]] = None,
        owner: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch classification history (from CLASSIFICATION_DECISIONS).
        Matches the expected UI schema for classification history.
        """
        try:
            db = self._get_db()
            # Note: classification_audit_repository defaults schema to DATA_GOVERNANCE
            return _audit_repo.fetch_audit_rows(
                database=db,
                start_date=start_date,
                end_date=end_date,
                dataset_name=dataset_name,
                classification_levels=classification_levels,
                owner=owner,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Failed to fetch classification history: {e}")
            return []


    def get_daily_digest(self, day: str) -> Optional[Dict[str, Any]]:
        """Fetch a daily digest for a specific day."""
        try:
            db = self._get_db()
            return _audit_repo.get_daily_digest(db, day)
        except Exception as e:
            logger.error(f"Failed to get daily digest: {e}")
            return None


# Create singleton instance
classification_audit_service = ClassificationAuditService()

# Export helper functions for backward compatibility with existing functional calls
def fetch_audit(*args, **kwargs):
    return classification_audit_service.fetch_audit(*args, **kwargs)

def log_workflow_event(*args, **kwargs):
    return classification_audit_service.log_workflow_event(*args, **kwargs)
