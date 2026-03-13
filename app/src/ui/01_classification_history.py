"""
UI for Classification Management → History sub-tab.

Renders:
- Filters: date range, dataset name, classification level, owner
- Sortable/searchable grid of audit rows
- CSV download

Backend:
- Uses src/services/classification_audit_service.fetch_audit()
- All Snowflake SQL lives in the service. This UI is purely presentation.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from datetime import date, timedelta
import pandas as pd
import streamlit as st

from src.services.classification_audit_service import fetch_audit


CLASSIFICATION_LEVELS = ["Public", "Internal", "Restricted", "Confidential"]





    # Developer note: The Snowflake query lives in fetch_audit().
    # To customize for your schema, edit src/services/classification_audit_service.py
