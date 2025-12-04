"""
AI Classification Pipeline Service

This service provides functionality for the Automatic AI Classification Pipeline sub-tab in the AI Assistant section.
It handles automated classification of data assets with semantic detection, CIA recommendations, and governance tagging.
"""

import logging
import math
import hashlib
import streamlit as st
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np  # type: ignore
import re

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:
    SentenceTransformer = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.services.ai_assistant_service import ai_assistant_service
from src.services.ai_classification_service import ai_classification_service
from src.services.discovery_service import DiscoveryService
from src.services.semantic_type_detector import semantic_type_detector
# AISensitiveDetectionService import moved to __init__
from src.services.governance_db_resolver import resolve_governance_db
from src.services.tagging_service import tagging_service
try:
    from src.config import settings
except Exception:
    settings = None  # type: ignore

logger = logging.getLogger(__name__)

class AIClassificationPipelineService:
    """Service for managing the automatic AI classification pipeline functionality."""

    def __init__(self):
        """Initialize the classification pipeline service."""
        self.ai_service = ai_assistant_service
        self.discovery = DiscoveryService()
        try:
            from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
            self.sensitive_service = AISensitiveDetectionService(sample_size=200, min_confidence=0.3, use_ai=True)
        except Exception:
            self.sensitive_service = None
        # Disable governance glossary usage for semantic context (use only information_schema + config)
        try:
            setattr(self.ai_service, "use_governance_glossary", False)
        except Exception:
            pass
        # Local embedding backend (MiniLM) for governance-free detection
        self._embed_backend: str = 'none'
        self._embedder: Any = None
        self._category_centroids: Dict[str, Any] = {}
        self._category_tokens: Dict[str, List[str]] = {}
        # Tuning defaults
        self._w_sem: float = 0.85
        self._w_kw: float = 0.15
        self._ctx_max_cols: int = 12
        self._ctx_max_vals: int = 5
        self._col_sample_rows: int = 200
        self._conf_label_threshold: float = 0.40  # BALANCED: Raised from 0.30 to reduce false positives while maintaining recall
        self._debug: bool = False
        self._cache: Dict[str, Any] = {}
        self._embed_cache: Dict[str, Any] = {}
        self._embed_ready: bool = False
        # Track whether we had to fall back to built-in categories instead of governance-driven ones
        self._using_fallback_categories: bool = False
        # Business glossary will be loaded dynamically from SENSITIVE_KEYWORDS table
        self._business_glossary_map: Dict[str, str] = {}
        # Metadata-driven mapping from governance categories to policy groups (PII/SOX/SOC2)
        self._policy_group_by_category: Dict[str, str] = {}
        self._category_colors: Dict[str, str] = {}
        # Initialize all metadata dictionaries to prevent AttributeError
        self._category_thresholds: Dict[str, float] = {}
        self._category_patterns: Dict[str, List[str]] = {}
        self._category_keywords: Dict[str, List[str]] = {}
        self._category_scoring_weights: Dict[str, Dict[str, float]] = {}
        self._category_multi_label: Dict[str, bool] = {}
        self._category_keyword_metadata: Dict[str, List[Dict[str, Any]]] = {}
        self._category_pattern_metadata: Dict[str, List[Dict[str, Any]]] = {}
        self._category_weights: Dict[str, float] = {}
        self._category_default_thresholds: Dict[str, float] = {}
        self._compliance_categories: Dict[str, str] = {}  # Maps category to compliance framework

    def render_classification_pipeline(self) -> None:
        """Render the Automatic AI Classification Dashboard."""

        # Initialize metadata if needed
        if not self._embed_ready or not self._category_centroids:
            with st.spinner("Loading governance metadata..."):
                self._init_local_embeddings()

        # 1. Top Actions
        col_act1, col_act2 = st.columns([3, 1])
        with col_act1:
            st.info("")
        with col_act2:
            if st.button("🚀 Run New Scan", type="primary", use_container_width=True):
                db = self._get_active_database()
                gov_db = self._get_governance_database(db) if db else None
                if db:
                    # Run pipeline but DO NOT save yet
                    self._run_classification_pipeline(db, gov_db)
                    # Flag that we need to save results
                    st.session_state["results_unsaved"] = True
                    st.rerun()
                else:
                    st.error("Please select a database first.")

        # 2. Load Data (Priority: In-Memory -> Database)
        df_results = pd.DataFrame()
        source_label = "Database"
        
        # Check if we have fresh results in session state
        if st.session_state.get("pipeline_results"):
            try:
                # Convert in-memory results to DataFrame for display
                df_results = self._convert_results_to_dataframe(st.session_state["pipeline_results"])
                source_label = "Latest Scan (In-Memory)"
            except Exception as e:
                logger.error(f"Failed to process in-memory results: {e}")
                st.session_state["pipeline_results"] = None # Clear bad state
        
        # Fallback to DB if no in-memory results
        if df_results.empty:
             with st.spinner("Fetching classification history..."):
                df_results = self._fetch_classification_history()

        if df_results.empty:
            st.warning("No classification results found. Run a scan to generate data.")
            return

        # SAVE LOGIC: If we have unsaved results, save them NOW (after display logic is ready)
        if st.session_state.get("results_unsaved") and st.session_state.get("pipeline_results"):
            db = self._get_active_database()
            if db:
                with st.spinner("Saving results to Governance Database..."):
                    self._save_classification_results(db, st.session_state["pipeline_results"])
        # 3. View Selection & Filters
        # 3. View Selection & Filters
        # Local filters removed in favor of Global Filters
        view_mode = "Table View"
        
        # Apply Global Filters
        global_filters = st.session_state.get("global_filters", {})
        global_schema = global_filters.get("schema")
        
        mask = pd.Series(True, index=df_results.index)
        
        # Apply Schema Filter if present
        if global_schema and str(global_schema).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'ALL', '[]'}:
            # Handle potential list of schemas or single schema
            if isinstance(global_schema, list):
                if len(global_schema) > 0:
                    mask = mask & df_results["Schema"].isin(global_schema)
            else:
                mask = mask & (df_results["Schema"] == global_schema)
        
        df_filtered = df_results[mask].copy()

        # Helper to parse CIA string into components
        def parse_cia_component(cia_str, component):
            # component is 'C', 'I', or 'A'
            # cia_str looks like "C:3 I:2 A:1"
            if not isinstance(cia_str, str): return '-'
            parts = cia_str.split()
            for p in parts:
                if p.startswith(component + ':'):
                    return p.split(':')[1]
            return '-'

        # Split CIA into separate columns
        df_filtered['Confidentiality'] = df_filtered['CIA'].apply(lambda x: parse_cia_component(x, 'C'))
        df_filtered['Integrity'] = df_filtered['CIA'].apply(lambda x: parse_cia_component(x, 'I'))
        df_filtered['Availability'] = df_filtered['CIA'].apply(lambda x: parse_cia_component(x, 'A'))

        # 4. Statistics Engine
        total_items = len(df_filtered)
        
        # Count by Compliance
        pii_count = len(df_filtered[df_filtered["Compliance"].str.contains("PII", case=False, na=False)])
        sox_count = len(df_filtered[df_filtered["Compliance"].str.contains("SOX", case=False, na=False)])
        soc2_count = len(df_filtered[df_filtered["Compliance"].str.contains("SOC2", case=False, na=False)])
        
        # Count by Sensitivity (Critical vs High)
        critical_mask = df_filtered["Sensitivity"].str.contains("Confidential|Critical", case=False, na=False)
        critical_col_count = len(df_filtered[critical_mask])
        critical_table_count = df_filtered[critical_mask]["Table"].nunique()
        
        # --- NEW High Risk Table Calculation ---
        # Logic: Risk Score > 1.5 OR Multiple Sensitive Columns (> 1)
        # Weights: Confidential=2.0, Restricted=1.0, Internal=0.5, Public=0.1
        
        def get_sensitivity_weight(sensitivity):
            s = str(sensitivity).upper()
            if 'CONFIDENTIAL' in s or 'CRITICAL' in s:
                return 2.0
            elif 'RESTRICTED' in s or 'HIGH' in s:
                return 1.0
            elif 'INTERNAL' in s or 'MEDIUM' in s:
                return 0.5
            return 0.1

        # Calculate weights on a copy to avoid affecting main df
        df_risk = df_filtered.copy()
        df_risk['Risk_Weight'] = df_risk['Sensitivity'].apply(get_sensitivity_weight)
        
        # Aggregate per table
        table_risk_agg = df_risk.groupby('Table').agg({
            'Risk_Weight': 'sum',
            'Column': 'count'
        })
        
        # Apply Thresholds
        high_risk_tables_list = table_risk_agg[
            (table_risk_agg['Risk_Weight'] > 1.5) | (table_risk_agg['Column'] > 1)
        ].index.tolist()
        
        high_table_count = len(high_risk_tables_list)
        
        # Keep high_col_count based on column sensitivity for the delta
        high_mask = df_filtered["Sensitivity"].str.contains("Restricted|High", case=False, na=False) & ~critical_mask
        high_col_count = len(df_filtered[high_mask])
        
        # Stats: Top Tables (Sorted by Risk Score)
        if not table_risk_agg.empty:
            top_tables = table_risk_agg.sort_values('Risk_Weight', ascending=False).head(5)
            top_tables.columns = ['Risk Score', 'Sensitive Columns']
        else:
            top_tables = pd.DataFrame(columns=['Risk Score', 'Sensitive Columns'])

        # 5. Visual Metrics Dashboard (6 Key Metrics)
        st.markdown("### 📊 Executive Summary")
        
        # First row: 3 metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            unique_tables = df_filtered["Table"].nunique()
            st.metric(
                label="📋 Total Sensitive Tables",
                value=unique_tables,
                delta=f"{len(df_filtered)} columns" if total_items > 0 else None,
                help="Number of tables containing sensitive data"
            )
        
        with col2:
            st.metric(
                label="🔐 PII Data",
                value=pii_count,
                delta=f"{(pii_count/max(1,total_items)*100):.1f}%" if total_items > 0 else None,
                help="Personally Identifiable Information"
            )
        
        with col3:
            st.metric(
                label="💰 SOX Data",
                value=sox_count,
                delta=f"{(sox_count/max(1,total_items)*100):.1f}%" if total_items > 0 else None,
                help="Sarbanes-Oxley financial data"
            )
        
        # Second row: 3 metrics
        col4, col5, col6 = st.columns(3)
        
        with col4:
            st.metric(
                label="🛡️ SOC2 Data",
                value=soc2_count,
                delta=f"{(soc2_count/max(1,total_items)*100):.1f}%" if total_items > 0 else None,
                help="SOC2 security and compliance data"
            )
        
        with col5:
            st.metric(
                label="🔴 Critical Risk Tables",
                value=critical_table_count,
                delta=f"{critical_col_count} columns",
                delta_color="inverse",
                help="Tables containing Confidential/Critical sensitivity items"
            )
        
        with col6:
            st.metric(
                label="🟠 High Risk Tables",
                value=high_table_count,
                delta=f"{high_col_count} columns",
                delta_color="inverse",
                help="Tables with Risk Score > 1.5 or multiple sensitive columns"
            )

        # 6. Detailed Analysis Tabs
        tab1, tab2 = st.tabs(["📋 Data Explorer", "📈 Risk Analytics"])

        with tab1:
            # Custom CSS for badges and styling
            st.markdown("""
                <style>
                .compliance-badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-weight: 600;
                    font-size: 0.85em;
                    margin: 2px;
                }
                .badge-pii { background-color: #9333ea; color: white; }
                .badge-sox { background-color: #16a34a; color: white; }
                .badge-soc2 { background-color: #2563eb; color: white; }
                
                .sensitivity-badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-weight: 600;
                    font-size: 0.85em;
                    margin: 2px;
                }
                .badge-critical { background-color: #dc2626; color: white; }
                .badge-high { background-color: #ea580c; color: white; }
                .badge-medium { background-color: #eab308; color: white; }
                .badge-low { background-color: #3b82f6; color: white; }
                
                .key-finding-box {
                    padding: 16px;
                    border-radius: 8px;
                    margin: 12px 0;
                    border-left: 4px solid;
                }
                .finding-critical { background-color: rgba(220, 38, 38, 0.15); border-color: #dc2626; }
                .finding-info { background-color: rgba(37, 99, 235, 0.15); border-color: #2563eb; }
                
                .column-name { font-family: 'Courier New', monospace; font-weight: 600; }
                </style>
            """, unsafe_allow_html=True)
            
            # Key Findings Panel
            st.markdown(f"#### 🔍 {view_mode} Results ({len(df_filtered)} items)")
            
            if critical_col_count > 0 or high_col_count > 0:
                col_find1, col_find2 = st.columns(2)
                
                with col_find1:
                    st.markdown(f"""
                        <div class="key-finding-box finding-critical">
                            <h4 style="margin-top:0;">🔴 Critical Findings</h4>
                            <ul>
                                <li><strong>{critical_col_count}</strong> critical sensitivity columns detected</li>
                                <li><strong>{pii_count}</strong> PII columns require immediate attention</li>
                                <li>Recommended action: <strong>Apply encryption & access controls</strong></li>
                            </ul>
                        </div>
                    """, unsafe_allow_html=True)
                
                with col_find2:
                    st.markdown(f"""
                        <div class="key-finding-box finding-info">
                            <h4 style="margin-top:0;">📊 Compliance Summary</h4>
                            <ul>
                                <li><strong>{sox_count}</strong> SOX-regulated financial data columns</li>
                                <li><strong>{soc2_count}</strong> SOC2 security-sensitive columns</li>
                                <li>Coverage: <strong>{len(df_filtered['Table'].unique())}</strong> tables affected</li>
                            </ul>
                        </div>
                    """, unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Aggregate by Table
            grouped = df_filtered.groupby(['Schema', 'Table']).agg({
                'Column': 'count',
                'Category': lambda x: sorted(list(set(x))),
                'Compliance': lambda x: sorted(list(set(x))),
                'Sensitivity': lambda x: sorted(list(set(x))),
                'Confidentiality': lambda x: sorted(list(set(x))),
                'Integrity': lambda x: sorted(list(set(x))),
                'Availability': lambda x: sorted(list(set(x))),
                'Confidence': 'max'
            }).reset_index()
            
            grouped.rename(columns={'Column': 'Sensitive Cols'}, inplace=True)
            
            # Format lists as strings with badges
            def format_compliance(items):
                badges = []
                for item in items:
                    item_upper = str(item).upper()
                    if 'PII' in item_upper:
                        badges.append('🟣 PII')
                    elif 'SOX' in item_upper:
                        badges.append('🟢 SOX')
                    elif 'SOC2' in item_upper:
                        badges.append('🔵 SOC2')
                    else:
                        badges.append(item)
                return ' | '.join(badges)
            
            def format_sensitivity(items):
                badges = []
                for item in items:
                    item_upper = str(item).upper()
                    if 'CRITICAL' in item_upper or 'CONFIDENTIAL' in item_upper:
                        badges.append('🔴 CRITICAL')
                    elif 'HIGH' in item_upper or 'RESTRICTED' in item_upper:
                        badges.append('🟠 HIGH')
                    elif 'MEDIUM' in item_upper:
                        badges.append('🟡 MEDIUM')
                    elif 'LOW' in item_upper:
                        badges.append('🔵 LOW')
                    else:
                        badges.append(item)
                return ' | '.join(badges)
            
            def format_confidentiality_val(val):
                labels = {
                    '0': 'C0 - Public',
                    '1': 'C1 - Internal',
                    '2': 'C2 - Restricted',
                    '3': 'C3 - Confidential',
                    '-': '-'
                }
                return labels.get(str(val), str(val))

            def format_integrity_val(val):
                labels = {
                    '0': 'I0 - None',
                    '1': 'I1 - Low',
                    '2': 'I2 - Moderate',
                    '3': 'I3 - High',
                    '-': '-'
                }
                return labels.get(str(val), str(val))

            def format_availability_val(val):
                labels = {
                    '0': 'A0 - None',
                    '1': 'A1 - Low',
                    '2': 'A2 - Moderate',
                    '3': 'A3 - High',
                    '-': '-'
                }
                return labels.get(str(val), str(val))

            def format_list_helper(items, formatter):
                unique_items = sorted(list(set(items)))
                return ' | '.join([formatter(x) for x in unique_items])

            grouped['Compliance'] = grouped['Compliance'].apply(format_compliance)
            grouped['Sensitivity'] = grouped['Sensitivity'].apply(format_sensitivity)
            grouped['Category'] = grouped['Category'].apply(lambda x: ', '.join(x))
            grouped['Confidentiality'] = grouped['Confidentiality'].apply(lambda x: format_list_helper(x, format_confidentiality_val))
            grouped['Integrity'] = grouped['Integrity'].apply(lambda x: format_list_helper(x, format_integrity_val))
            grouped['Availability'] = grouped['Availability'].apply(lambda x: format_list_helper(x, format_availability_val))
            
            st.dataframe(
                grouped[['Schema', 'Table', 'Sensitive Cols', 'Category', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability']],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Sensitive Cols": st.column_config.NumberColumn(
                        "Sensitive Columns",
                        format="%d"
                    ),
                }
            )
            
            
            # Add Keyword Button (Table View)
            if st.button("➕ Add Keyword", key="btn_add_kw_main_btm"):
                st.session_state['kw_action_main'] = 'add'
            
            if st.session_state.get('kw_action_main') == 'add':
                self._render_keyword_actions("main")

            # --- Drill Down Functionality ---
            st.divider()
            st.subheader("🔬 Table Drill-Down")
            
            # Get list of tables for dropdown
            table_options = sorted(grouped['Table'].unique().tolist())
            selected_table = st.selectbox(
                "Select a table to view detailed column analysis:",
                options=table_options,
                index=None,
                placeholder="Choose a table..."
            )
            
            if selected_table:
                st.markdown(f"##### Detailed Analysis for `{selected_table}`")
                
                # Filter for selected table
                table_details = df_filtered[df_filtered['Table'] == selected_table].copy()
                
                # Format compliance with badges (Inline function to avoid scope issues)
                def drill_badge_compliance(val):
                    val_upper = str(val).upper()
                    if 'PII' in val_upper:
                        return '🟣 PII'
                    elif 'SOX' in val_upper:
                        return '🟢 SOX'
                    elif 'SOC2' in val_upper:
                        return '🔵 SOC2'
                    return val
                
                # Format sensitivity with badges
                def drill_badge_sensitivity(val):
                    val_upper = str(val).upper()
                    if 'CRITICAL' in val_upper or 'CONFIDENTIAL' in val_upper:
                        return '🔴 CRITICAL'
                    elif 'HIGH' in val_upper or 'RESTRICTED' in val_upper:
                        return '🟠 HIGH'
                    elif 'MEDIUM' in val_upper:
                        return '🟡 MEDIUM'
                    elif 'LOW' in val_upper:
                        return '🔵 LOW'
                    return val

                table_details['Compliance'] = table_details['Compliance'].apply(drill_badge_compliance)
                table_details['Sensitivity'] = table_details['Sensitivity'].apply(drill_badge_sensitivity)
                table_details['Confidentiality'] = table_details['Confidentiality'].apply(format_confidentiality_val)
                table_details['Integrity'] = table_details['Integrity'].apply(format_integrity_val)
                table_details['Availability'] = table_details['Availability'].apply(format_availability_val)
                
                # Inline Editing for Drill-Down
                categories_list = sorted(list(self._category_thresholds.keys())) if self._category_thresholds else ["PII", "SOX", "SOC2", "INTERNAL"]
                
                edited_df = st.data_editor(
                    table_details[['Column', 'Category', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability', 'Rationale']],
                    use_container_width=True,
                    hide_index=True,
                    key="drill_down_editor",
                    disabled=['Column', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability', 'Rationale'],
                    column_config={
                        "Category": st.column_config.SelectboxColumn(
                            "Category (Edit to Upsert)",
                            help="Change the category to automatically update the keyword rule.",
                            width="medium",
                            options=categories_list,
                            required=True
                        ),
                        "Rationale": st.column_config.TextColumn(
                            "Detection Rationale",
                            width="large"
                        )
                    }
                )

                # Handle Inline Edits
                if st.session_state.get("drill_down_editor"):
                    edits = st.session_state["drill_down_editor"].get("edited_rows", {})
                    if edits:
                        for idx, changes in edits.items():
                            if "Category" in changes:
                                new_cat = changes["Category"]
                                # Get original column name (index matches table_details)
                                col_name = table_details.iloc[idx]['Column']
                                
                                with st.spinner(f"Updating keyword '{col_name}' to '{new_cat}'..."):
                                    if self.upsert_sensitive_keyword(col_name, new_cat, "CONTAINS"):
                                        st.toast(f"✅ Updated '{col_name}' to {new_cat}!", icon="💾")
                                        # Clear edit state to prevent loop (optional, but good practice)
                                        # st.session_state["drill_down_editor"]["edited_rows"] = {} 
                                        # Rerun to refresh data
                                        st.rerun()

                # Add Keyword Button (Drill-Down View)
                if st.button("➕ Add Keyword", key="btn_add_kw_drill_btm"):
                    st.session_state['kw_action_drill'] = 'add'
                
                if st.session_state.get('kw_action_drill') == 'add':
                    self._render_keyword_actions("drill")

                # --- Tagging Assistant ---
                st.divider()
                st.subheader("🏷️ Tagging Assistant")
                st.markdown("""
                The Tagging Assistant provides a comprehensive solution for managing data classification within the system. """)
                
                tag_tab1, tag_tab2 = st.tabs(["📝 Generate SQL", "⚡ Apply Tags"])
                
                # Common Inputs
                with st.container():
                    col_t1, col_t2 = st.columns(2)
                    with col_t1:
                        target_type = st.radio("Target Type", ["Table", "Column"], horizontal=True, key="tag_target_type")
                    
                    target_col = None
                    if target_type == "Column":
                        with col_t2:
                            # Get columns from table_details
                            cols = sorted(table_details['Column'].unique().tolist())
                            target_col = st.selectbox("Select Column", cols, key="tag_target_col")
                    
                    # Tag Inputs
                    # Default to Restricted (C2 I2 A2) for tables, Internal (C1 I1 A1) for other types
                    if target_type == "Table":
                        def_class_ix = 2  # Restricted
                        def_c_ix = 2      # C2
                        def_i_ix = 2      # I2
                        def_a_ix = 2      # A2
                    else:
                        def_class_ix = 1  # Internal
                        def_c_ix = 1      # C1
                        def_i_ix = 1      # I1
                        def_a_ix = 1      # A1
                    
                    if target_type == "Column" and target_col:
                        try:
                            # Get the row for this column
                            col_row = table_details[table_details['Column'] == target_col].iloc[0]
                            
                            # 1. Suggest Classification
                            # Sensitivity is formatted with badges e.g. "🔴 CRITICAL"
                            sens_val = str(col_row.get('Sensitivity', '')).upper()
                            if 'CRITICAL' in sens_val or 'CONFIDENTIAL' in sens_val:
                                def_class_ix = 3 # Confidential
                            elif 'RESTRICTED' in sens_val or 'HIGH' in sens_val:
                                def_class_ix = 2 # Restricted
                            elif 'PUBLIC' in sens_val:
                                def_class_ix = 0 # Public
                            else:
                                def_class_ix = 1 # Internal
                                
                            # 2. Suggest CIA
                            # Values are formatted like "C3 - Confidential" or "I2 - Moderate"
                            import re
                            def extract_level(val):
                                m = re.search(r'[CIA]?(\d)', str(val))
                                return int(m.group(1)) if m else 0
                                
                            def_c_ix = extract_level(col_row.get('Confidentiality', '0'))
                            def_i_ix = extract_level(col_row.get('Integrity', '0'))
                            def_a_ix = extract_level(col_row.get('Availability', '0'))
                            
                            if target_type == "Table":
                                st.info("💡 Suggested tags based on analysis: Restricted (C2 I2 A2)")
                            else:
                                st.info(f"💡 Suggested tags based on analysis: {['Public','Internal','Restricted','Confidential'][def_class_ix]} (C{def_c_ix} I{def_i_ix} A{def_a_ix})")
                        except Exception:
                            pass

                    st.markdown("###### Select Tags")
                    c1, c2, c3, c4 = st.columns(4)
                    with c1:
                        t_class = st.selectbox("Classification", ["Public", "Internal", "Restricted", "Confidential"], index=def_class_ix, key="tag_class")
                    with c2:
                        t_conf = st.selectbox("Confidentiality (C)", ["0", "1", "2", "3"], index=def_c_ix, key="tag_conf")
                    with c3:
                        t_int = st.selectbox("Integrity (I)", ["0", "1", "2", "3"], index=def_i_ix, key="tag_int")
                    with c4:
                        t_avail = st.selectbox("Availability (A)", ["0", "1", "2", "3"], index=def_a_ix, key="tag_avail")
                        
                    tags_to_apply = {
                        "DATA_CLASSIFICATION": t_class,
                        "CONFIDENTIALITY_LEVEL": t_conf,
                        "INTEGRITY_LEVEL": t_int,
                        "AVAILABILITY_LEVEL": t_avail
                    }

                with tag_tab1:
                    if st.button("Generate SQL", key="btn_gen_sql"):
                        schema_name = table_details['Schema'].iloc[0] if not table_details.empty else "PUBLIC"
                        full_obj_name = f"{self._get_active_database()}.{schema_name}.{selected_table}"
                        
                        if target_type == "Table":
                            sql = tagging_service.generate_tag_sql_for_object(full_obj_name, "TABLE", tags_to_apply)
                        else:
                            if target_col:
                                sql = tagging_service.generate_tag_sql_for_column(full_obj_name, target_col, tags_to_apply)
                            else:
                                sql = "-- Please select a column"
                        
                        st.code(sql, language="sql")
                        st.info("Copy and run this SQL in your Snowflake worksheet.")

                with tag_tab2:
                    if st.button("Apply Tags Immediately", key="btn_apply_tags", type="primary"):
                        schema_name = table_details['Schema'].iloc[0] if not table_details.empty else "PUBLIC"
                        full_obj_name = f"{self._get_active_database()}.{schema_name}.{selected_table}"
                        
                        try:
                            if target_type == "Table":
                                tagging_service.apply_tags_to_object(full_obj_name, "TABLE", tags_to_apply)
                            else:
                                if target_col:
                                    tagging_service.apply_tags_to_column(full_obj_name, target_col, tags_to_apply)
                                else:
                                    st.warning("Please select a column.")
                                    raise ValueError("No column selected")
                            st.success(f"Successfully applied tags to {target_type}!")
                            st.balloons()
                        except Exception as e:
                            st.error(f"Failed to apply tags: {e}")
                            st.session_state['last_tag_error'] = str(e)


        with tab2:
            st.markdown("#### Risk Distribution")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**By Compliance Framework**")
                if not df_filtered.empty:
                    st.bar_chart(df_filtered["Compliance"].value_counts())
                else:
                    st.info("No data to display")
            with c2:
                st.markdown("**By Sensitivity Level**")
                if not df_filtered.empty:
                    st.bar_chart(df_filtered["Sensitivity"].value_counts())
                else:
                    st.info("No data to display")
            
            st.markdown("#### Top High-Risk Tables")
            st.dataframe(top_tables, use_container_width=True)


    def _render_keyword_actions(self, context_key: str) -> None:
        """Render the inline keyword action form based on session state."""
        action_key = f'kw_action_{context_key}'
        current_action = st.session_state.get(action_key)
        
        if not current_action:
            return

        form_container = st.container()
        with form_container:
            st.info(f"{'Add New' if current_action == 'add' else 'Upsert/Edit'} Sensitive Keyword")
            
            c1, c2, c3, c4 = st.columns([3, 2, 2, 1])
            with c1:
                new_keyword = st.text_input("Keyword", placeholder="e.g. 'project_falcon'", key=f"kw_input_{context_key}")
            with c2:
                # Get categories
                categories = sorted(list(self._category_thresholds.keys())) if self._category_thresholds else ["PII", "SOX", "SOC2", "INTERNAL"]
                target_category = st.selectbox("Category", categories, key=f"kw_cat_{context_key}")
            with c3:
                match_type = st.selectbox("Match Type", ["CONTAINS", "EXACT"], key=f"kw_match_{context_key}")
            with c4:
                st.write("")
                st.write("")
                # Close button
                if st.button("❌", key=f"btn_close_{context_key}"):
                    st.session_state[action_key] = None
                    st.rerun()

            if st.button("Save Keyword", key=f"btn_save_{context_key}", type="primary"):
                if new_keyword and target_category:
                    with st.spinner("Saving..."):
                        success = False
                        if current_action == 'add':
                            success = self.add_sensitive_keyword(new_keyword, target_category, match_type)
                        else:
                            success = self.upsert_sensitive_keyword(new_keyword, target_category, match_type)
                            
                        if success:
                            st.success(f"Successfully saved keyword '{new_keyword}'!")
                            st.session_state[action_key] = None # Close form on success
                            st.rerun()
                        else:
                            st.error("Failed to save keyword. It may already exist (if adding) or there was a database error.")
                else:
                    st.warning("Please enter a keyword and select a category.")
            st.divider()

    def _get_active_database(self) -> Optional[str]:
        """
        Get the active database from global filters with comprehensive fallbacks.
        
        CRITICAL FIX: Never returns None - always probes Snowflake for current database.
        """
        db = None
        
        # PRIORITY 1: Global filters
        try:
            from src.pages.page_helpers import _active_db_from_filter
            db = _active_db_from_filter()
            if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                logger.info(f"Database from global filter: {db}")
                return db
        except Exception as e:
            logger.debug(f"Could not get database from global filter: {e}")

        # PRIORITY 2: Session state
        if not db:
            try:
                if hasattr(st, "session_state"):
                    db = (
                        st.session_state.get("sf_database")
                        or (st.session_state.get("global_filters", {}) or {}).get("database")
                        or st.session_state.get("rt_db")
                        or st.session_state.get("selected_database")
                    )
                    if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                        logger.info(f"Database from session state: {db}")
                        return db
            except Exception as e:
                logger.debug(f"Could not get database from session state: {e}")

        # PRIORITY 3: Settings
        if not db and settings is not None:
            try:
                db = getattr(settings, "SNOWFLAKE_DATABASE", None)
                if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                    logger.info(f"Database from settings: {db}")
                    return db
            except Exception as e:
                logger.debug(f"Could not get database from settings: {e}")

        # PRIORITY 4: Probe Snowflake context (ALWAYS TRY THIS)
        try:
            logger.info("Probing Snowflake for current database...")
            rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
            if rows:
                first = rows[0]
                # Support both dict-style and scalar results from the connector
                if isinstance(first, dict):
                    db = first.get("DB")
                else:
                    db = first
                if db and str(db).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
                    logger.info(f"Database from Snowflake context: {db}")
                    return db
        except Exception as e:
            logger.error(f"Could not probe Snowflake for current database: {e}")

        # PRIORITY 5: Try to list databases and pick first one
        try:
            logger.warning("No database configured - attempting to list available databases...")
            rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            if rows:
                # Filter out system databases, tolerate non-dict row types
                user_dbs = []
                for r in rows:
                    name = None
                    if isinstance(r, dict):
                        name = r.get('name') or r.get('NAME')
                    else:
                        name = r
                    if not name:
                        continue
                    name_str = str(name)
                    if name_str.upper() in {'SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA', 'UTIL_DB'}:
                        continue
                    user_dbs.append(name_str)
                if user_dbs:
                    db = user_dbs[0]
                    logger.warning(f"Auto-selected first available database: {db}")
                    logger.warning("⚠️  PLEASE SET A DATABASE IN GLOBAL FILTERS!")
                    return db
        except Exception as e:
            logger.error(f"Could not list databases: {e}")

        # FINAL FALLBACK: Return None and let calling code handle it
        logger.error("=" * 80)
        logger.error("CRITICAL: NO DATABASE CONFIGURED!")
        logger.error("Please set a database using one of these methods:")
        logger.error("  1. Use the Global Filters sidebar in the UI")
        logger.error("  2. Run: USE DATABASE your_database_name; in Snowflake")
        logger.error("  3. Set SNOWFLAKE_DATABASE in settings")
        logger.error("=" * 80)
        return None

    def _is_valid_database(self, db: str) -> bool:
        """Check if database name is valid (not placeholder/invalid)."""
        try:
            db_upper = str(db or '').upper()
            invalid_names = {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}
            return db_upper not in invalid_names
        except Exception:
            return False

    def _get_governance_database(self, db: str) -> str:
        """Resolve governance database for CTE joins."""
        try:
            gov_db = resolve_governance_db() or db
            return gov_db
        except Exception:
            return db

    def _run_classification_pipeline(self, db: str, gov_db: str) -> None:
        """Execute the full AI classification pipeline."""
        # Validate database
        if not db or db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            st.error("Invalid database selected. Please choose a valid database from Global Filters.")
            return

        # Validate governance database
        if gov_db and gov_db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN'):
            gov_db = db  # fallback to main db

        with st.spinner("Running AI Classification Pipeline... This may take several minutes."):
            try:
                # Prefer live metadata for discovery, but classification will be governance-free
                try:
                    self.ai_service.use_snowflake = True
                except Exception:
                    pass

                # Initialize local MiniLM (or fallback) embeddings and category centroids
                self._init_local_embeddings()

                try:
                    self._auto_tune_parameters()
                except Exception:
                    pass

                # Step 1b: Local discovery list for this run (preview)
                assets = self._discover_assets(db)
                if not assets:
                    st.warning("No tables found in the selected database.")
                    return

                st.info(f"Discovered {len(assets)} tables for classification.")

                # ========================================================================
                # AI MODEL DETECTION STATUS - Clear UI Messaging
                # ========================================================================
                
                st.markdown("---")
                st.markdown("### 🤖 AI Detection Engine Status")
                
                # 1. Embedding Model Status
                if self._embed_backend == 'sentence-transformers':
                    st.success("✅ **AI Model Active:** Using `intfloat/e5-large-v2` for semantic detection")
                    st.caption("🧠 Advanced transformer-based embeddings enabled for high-accuracy classification")
                else:
                    st.warning("⚠️ **AI Model Inactive:** Using keyword/pattern matching only")
                    st.caption("💡 Install `sentence-transformers` library to enable AI-powered semantic detection")
                
                # 2. Category Source Status
                try:
                    using_fallback = getattr(self, "_using_fallback_categories", False)
                    cat_cnt = len(getattr(self, "_category_centroids", {}) or {})
                    
                    if using_fallback:
                        st.warning("📋 **Categories:** Using hardcoded fallback (PII / SOX / SOC2)")
                        st.caption("⚙️ Governance tables unavailable - using built-in baseline categories")
                        st.info("💡 **Action Required:** Populate `SENSITIVITY_CATEGORIES`, `SENSITIVE_KEYWORDS`, and `SENSITIVE_PATTERNS` tables for metadata-driven detection")
                    else:
                        st.success(f"📋 **Categories:** Loaded from governance tables ({cat_cnt} categories)")
                        st.caption("✅ Metadata-driven classification active - using Snowflake governance tables")
                        
                        # Show category details
                        try:
                            tok_cnt = sum(len(v) for v in (getattr(self, "_category_tokens", {}) or {}).values())
                            kw_cnt = sum(len(v) for v in (getattr(self, "_category_keywords", {}) or {}).values())
                            pat_cnt = sum(len(v) for v in (getattr(self, "_category_patterns", {}) or {}).values())
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("Categories", cat_cnt)
                            with col2:
                                st.metric("Keywords", kw_cnt)
                            with col3:
                                st.metric("Patterns", pat_cnt)
                            with col4:
                                st.metric("Tokens", tok_cnt)
                        except Exception:
                            pass
                except Exception:
                    st.error("❌ Unable to determine category source")
                
                # 3. Detection Mode Summary
                st.markdown("---")
                if self._embed_backend == 'sentence-transformers' and not using_fallback:
                    st.success("🎯 **Detection Mode:** AI-Powered + Metadata-Driven (OPTIMAL)")
                    st.caption("Using E5-Large-v2 embeddings with governance-driven categories, keywords, and patterns")
                elif self._embed_backend == 'sentence-transformers' and using_fallback:
                    st.info("🎯 **Detection Mode:** AI-Powered + Hardcoded Fallback")
                    st.caption("Using E5-Large-v2 embeddings with baseline PII/SOX/SOC2 categories")
                elif not self._embed_backend == 'sentence-transformers' and not using_fallback:
                    st.warning("🎯 **Detection Mode:** Keyword/Pattern Only + Metadata-Driven")
                    st.caption("Using governance-driven keywords and patterns (no AI embeddings)")
                else:
                    st.warning("🎯 **Detection Mode:** Keyword/Pattern Only + Hardcoded Fallback")
                    st.caption("Using baseline keywords and patterns (no AI embeddings or governance tables)")
                
                # 4. Validation Warnings
                if self._embed_backend == 'sentence-transformers' and cat_cnt == 0:
                    st.error("⚠️ **CRITICAL:** E5-Large-v2 is active but no category centroids are available!")
                    st.caption("🔧 Verify governance table configuration and embeddings initialization")
                
                st.markdown("---")

                # Step 2-8: Run local classification pipeline (no governance tables)
                # Limit number of assets per run for performance, configurable via dynamic config
                try:
                    cfg = self._load_dynamic_config()
                except Exception:
                    cfg = {}
                try:
                    max_assets = int(cfg.get("max_assets_per_run", 30) or 30)
                except Exception:
                    max_assets = 30
                assets_to_classify = assets[:max_assets]
                results = self._classify_assets_local(db=db, assets=assets_to_classify)

                try:
                    conf_list = [float(r.get('confidence', 0.0) or 0.0) for r in results if isinstance(r, dict) and 'error' not in r]
                    adaptive = None
                    if conf_list:
                        if np is not None:
                            try:
                                p = float(np.percentile(conf_list, 60))
                            except Exception:
                                p = float(sum(conf_list)/max(1,len(conf_list)))
                        else:
                            try:
                                sl = sorted(conf_list)
                                idx = int(round(0.6 * (len(sl)-1)))
                                p = float(sl[idx])
                            except Exception:
                                p = float(sum(conf_list)/max(1,len(conf_list)))
                        # Do not lower below configured threshold; avoid circular lowering
                        base_thr = float(getattr(self, "_conf_label_threshold", 0.5) or 0.5)
                        adaptive = max(base_thr, min(0.75, p))
                    if adaptive is not None:
                        lbl_map = {
                            'Confidential': '🟥 Confidential',
                            'Restricted': '🟧 Restricted',
                            'Internal': '🟨 Internal',
                            'Public': '🟩 Public',
                            'Uncertain — review': '⬜ Uncertain — review',
                        }
                        col_map = {
                            'Confidential': 'Red',
                            'Restricted': 'Orange',
                            'Internal': 'Yellow',
                            'Public': 'Green',
                            'Uncertain — review': 'Gray',
                        }
                        for r in results:
                            try:
                                if 'error' in r:
                                    continue
                                confv = float(r.get('confidence', 0.0) or 0.0)
                                base_label = str(r.get('label') or '')
                                if confv < adaptive:
                                    r['label'] = 'Uncertain — review'
                                    r['label_emoji'] = lbl_map['Uncertain — review']
                                    r['color'] = col_map['Uncertain — review']
                                else:
                                    # ensure emoji/color match base_label
                                    r['label_emoji'] = lbl_map.get(base_label, base_label)
                                    r['color'] = col_map.get(base_label, r.get('color', ''))
                            except Exception:
                                continue
                except Exception:
                    pass

                if not results:
                    st.warning("No assets were successfully classified.")
                    return

                # Save results to session state for persistent display
                st.session_state["pipeline_results"] = results

                # Summary
                successful = len([r for r in results if 'error' not in r])
                failed = len([r for r in results if 'error' in r])

                st.success(f"Pipeline completed! Successfully classified {successful} assets. Failed: {failed}")

                if failed > 0:
                    with st.expander("View Errors", expanded=False):
                        for result in results:
                            if 'error' in result:
                                st.error(f"{result['asset']['full_name']}: {result['error']}")

            except Exception as e:
                logger.error(f"Pipeline execution failed: {e}")
                st.error(f"Pipeline failed: {e}")

    def _init_local_embeddings(self) -> None:
        """
        Initialize embeddings and load ALL classification metadata from governance tables.
        This is the main entry point for metadata-driven classification.
        """
        try:
            if not hasattr(self, "_embed_cache") or not isinstance(self._embed_cache, dict):
                self._embed_cache = {}
            self._embed_ready = False
            
            # Initialize SentenceTransformer embeddings
            if SentenceTransformer is not None:
                try:
                    logger.info("Initializing SentenceTransformer embeddings (E5-Large)...")
                    self._embedder = SentenceTransformer('intfloat/e5-large-v2')
                    tv = self._embedder.encode(["ok"], normalize_embeddings=True)
                    v0 = tv[0] if isinstance(tv, (list, tuple)) else tv
                    dim = int(getattr(v0, "shape", [0])[-1]) if hasattr(v0, "shape") else (len(v0) if isinstance(v0, (list, tuple)) else 0)
                    if dim and dim > 0:
                        self._embed_backend = 'sentence-transformers'
                        self._embed_ready = True
                        logger.info(f"✓ Embeddings initialized successfully. Backend: {self._embed_backend}, Dimension: {dim}")
                    else:
                        self._embedder = None
                        self._embed_backend = 'none'
                        logger.warning(f"✗ Embedding dimension validation failed: {dim}")
                except Exception as _e:
                    logger.warning(f"✗ Local embedding initialization failed: {_e}")
                    self._embedder = None
                    self._embed_backend = 'none'
            else:
                self._embedder = None
                self._embed_backend = 'none'
                logger.warning("✗ SentenceTransformer not available")
        except Exception as _e2:
            logger.warning(f"✗ Embedding setup error: {_e2}")
            self._embedder = None
            self._embed_backend = 'none'
            self._embed_ready = False

        # Load ALL metadata from governance tables (100% metadata-driven)
        self._load_metadata_driven_categories()
        
        # Load business glossary map from SENSITIVE_KEYWORDS table
        schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
        gov_db = None
        try:
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
        except Exception:
            pass
        
        self._load_business_glossary_from_governance(schema_fqn)

    def _generate_category_examples(self, name: str, desc: str) -> List[str]:
        n = (name or "").strip()
        d = (desc or "").strip()
        out: List[str] = []
        
        # Base examples: full name and description
        if n:
            out.append(n)
        if d:
            out.append(d)

        # Extract meaningful tokens from name/description
        raw_tokens: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if not w2:
                    continue
                if len(w2) < 3:
                    continue
                raw_tokens.append(w2)

        # Conservative stopword filter (preserve domain-critical terms)
        # Removed: "data", "info", "information" (domain-critical)
        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were"}
        toks: List[str] = []
        seen: set = set()
        for t in raw_tokens:
            tl = t.lower()
            if tl in stops:
                continue
            if tl not in seen:
                toks.append(t)
                seen.add(tl)

        # Build enriched examples with multiple phrase patterns
        phrases: List[str] = []
        for t in toks[:12]:  # Increased from 10
            phrases.append(t)
            phrases.append(f"contains {t}")
            phrases.append(f"{t} field")
            phrases.append(f"{t} column")
        
        # Add domain-specific terminology patterns
        domain_patterns: List[str] = []
        for t in toks[:8]:
            domain_patterns.append(f"{t} record")
            domain_patterns.append(f"{t} value")
            domain_patterns.append(f"{t} attribute")
        
        # Combine all examples
        ex = out + phrases + domain_patterns
        
        # Dedupe while preserving order
        seen2 = set()
        dedup: List[str] = []
        for s in ex:
            sl = s.lower().strip()
            if sl and sl not in seen2:
                dedup.append(s.strip())
                seen2.add(sl)
        
        return dedup[:64]

    def _generate_category_tokens(self, name: str, desc: str) -> List[str]:
        n = (name or "").strip()
        d = (desc or "").strip()
        raw: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if not w2:
                    continue
                if len(w2) < 3:
                    continue
                raw.append(w2)
        # simple stopword removal and dedupe
        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were","data","info","information"}
        out: List[str] = []
        seen = set()
        for t in raw:
            tt = re.sub(r"[_\-]+", " ", str(t)).strip()
            tl = tt.lower()
            if not tt or tl in stops:
                continue
            if tl not in seen:
                out.append(tt)
                seen.add(tl)
        return out[:64]

    def _load_additional_tokens_from_keywords(self, schema_fqn: str, category_name: str) -> List[str]:
        rows = []
        try:
            # Join SENSITIVE_KEYWORDS to SENSITIVITY_CATEGORIES via CATEGORY_ID
            # and filter by CATEGORY_NAME; use KEYWORD_STRING as the keyword text.
            rows = snowflake_connector.execute_query(
                f"""
                SELECT sk.KEYWORD_STRING AS KW
                FROM {schema_fqn}.SENSITIVE_KEYWORDS sk
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES sc
                  ON sk.CATEGORY_ID = sc.CATEGORY_ID
                WHERE COALESCE(sk.IS_ACTIVE, TRUE)
                  AND LOWER(sc.CATEGORY_NAME) = LOWER(%(n)s)
                """,
                {"n": category_name},
            ) or []
        except Exception:
            rows = []
        out: List[str] = []
        for r in rows:
            try:
                if not isinstance(r, dict):
                    continue
                kw = str(r.get("KW") or "").strip()
                if kw:
                    out.append(kw)
            except Exception:
                continue
        return out

    def _load_business_glossary_from_governance(self, schema_fqn: str) -> None:
        """Load business glossary keyword-to-category mappings from SENSITIVE_KEYWORDS table."""
        try:
            # Query all active keywords with their associated categories
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    LOWER(sk.KEYWORD_STRING) AS KEYWORD,
                    UPPER(sc.CATEGORY_NAME)   AS CATEGORY
                FROM {schema_fqn}.SENSITIVE_KEYWORDS sk
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES sc
                  ON sk.CATEGORY_ID = sc.CATEGORY_ID
                WHERE COALESCE(sk.IS_ACTIVE, TRUE) = TRUE
                """) or []
            
            glossary_map = {}
            for r in rows:
                try:
                    if not isinstance(r, dict):
                        continue
                    kw = str(r.get("KEYWORD") or "").strip().lower()
                    cat = str(r.get("CATEGORY") or "").strip().upper()
                    
                    if kw and cat:
                        # Map the category to policy group (PII, SOX, SOC2)
                        pg = self._map_category_to_policy_group(cat)
                        if pg:
                            glossary_map[kw] = pg
                except Exception:
                    continue
            
            self._business_glossary_map = glossary_map
            logger.info(f"Loaded {len(glossary_map)} business glossary mappings from SENSITIVE_KEYWORDS")
            
        except Exception as e:
            logger.warning(f"Failed to load business glossary from governance: {e}")
            self._business_glossary_map = {}

    def get_category_id_by_name(self, category_name: str) -> Optional[str]:
        """Get category ID for a given category name."""
        try:
            schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"

            rows = snowflake_connector.execute_query(
                f"SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)",
                {"n": category_name}
            )
            if rows and len(rows) > 0:
                first = rows[0]
                if isinstance(first, dict):
                    return first.get('CATEGORY_ID')
                else:
                    # Fallback for tuple/list
                    return first[0]
            return None
        except Exception as e:
            logger.error(f"Failed to get category ID for {category_name}: {e}")
            return None

    def _log_keyword_audit(self, action: str, keyword: str, category: str, details: str):
        """Log keyword changes to the audit table."""
        try:
            schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
            
            # Escape single quotes for SQL
            safe_details = details.replace("'", "''")
            safe_keyword = keyword.replace("'", "''")
            
            query = f"""
                INSERT INTO {schema_fqn}.CLASSIFICATION_AUDIT 
                (ID, RESOURCE_ID, ACTION, DETAILS, CREATED_AT)
                VALUES (UUID_STRING(), '{safe_keyword}', '{action}', '{safe_details}', CURRENT_TIMESTAMP())
            """
            snowflake_connector.execute_non_query(query)
        except Exception as e:
            logger.error(f"Failed to audit keyword action: {e}")

    def add_sensitive_keyword(self, keyword: str, category_name: str, match_type: str = 'CONTAINS') -> bool:
        """Add a new sensitive keyword to the governance table."""
        try:
            category_id = self.get_category_id_by_name(category_name)
            if not category_id:
                logger.error(f"Category '{category_name}' not found.")
                return False

            schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"

            # Check if keyword already exists
            existing = snowflake_connector.execute_query(
                f"SELECT KEYWORD_ID FROM {schema_fqn}.SENSITIVE_KEYWORDS WHERE LOWER(KEYWORD_STRING) = LOWER(%(k)s) AND CATEGORY_ID = %(c)s",
                {"k": keyword, "c": category_id}
            )
            if existing:
                logger.warning(f"Keyword '{keyword}' already exists for category '{category_name}'.")
                return False

            # Insert
            safe_keyword = keyword.replace("'", "''")
            safe_match_type = match_type.replace("'", "''")
            
            query = f"""
                INSERT INTO {schema_fqn}.SENSITIVE_KEYWORDS 
                (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
                VALUES (UUID_STRING(), '{category_id}', '{safe_keyword}', '{safe_match_type}', 0.8, TRUE, CURRENT_USER())
            """
            snowflake_connector.execute_non_query(query)
            
            # Audit
            self._log_keyword_audit("ADD_KEYWORD", keyword, category_name, f"Added keyword '{keyword}' to category '{category_name}' with match type '{match_type}'")

            # Refresh local cache
            self._load_metadata_driven_categories()
            return True
        except Exception as e:
            logger.error(f"Failed to add keyword '{keyword}': {e}")
            return False

    def upsert_sensitive_keyword(self, keyword: str, category_name: str, match_type: str = 'CONTAINS') -> bool:
        """Upsert a sensitive keyword (Insert if new, Update if exists)."""
        try:
            category_id = self.get_category_id_by_name(category_name)
            if not category_id:
                logger.error(f"Category '{category_name}' not found.")
                return False

            schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"

            # Check if keyword exists
            existing = snowflake_connector.execute_query(
                f"SELECT KEYWORD_ID FROM {schema_fqn}.SENSITIVE_KEYWORDS WHERE LOWER(KEYWORD_STRING) = LOWER(%(k)s) AND CATEGORY_ID = %(c)s",
                {"k": keyword, "c": category_id}
            )
            
            safe_keyword = keyword.replace("'", "''")
            safe_match_type = match_type.replace("'", "''")

            if existing:
                # Update
                query = f"""
                    UPDATE {schema_fqn}.SENSITIVE_KEYWORDS 
                    SET MATCH_TYPE = '{safe_match_type}', IS_ACTIVE = TRUE, SENSITIVITY_WEIGHT = 0.8
                    WHERE LOWER(KEYWORD_STRING) = LOWER('{safe_keyword}') AND CATEGORY_ID = '{category_id}'
                """
                snowflake_connector.execute_non_query(query)
                # Audit
                self._log_keyword_audit("UPDATE_KEYWORD", keyword, category_name, f"Updated keyword '{keyword}' in category '{category_name}'")
            else:
                # Insert
                query = f"""
                    INSERT INTO {schema_fqn}.SENSITIVE_KEYWORDS 
                    (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
                    VALUES (UUID_STRING(), '{category_id}', '{safe_keyword}', '{safe_match_type}', 0.8, TRUE, CURRENT_USER())
                """
                snowflake_connector.execute_non_query(query)
                # Audit
                self._log_keyword_audit("ADD_KEYWORD", keyword, category_name, f"Added keyword '{keyword}' to category '{category_name}' via upsert")

            # Refresh local cache
            self._load_metadata_driven_categories()
            return True
        except Exception as e:
            logger.error(f"Failed to upsert keyword '{keyword}': {e}")
            return False

    def classify_texts(self, texts: List[str], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Classify a list of text samples using the current AI model and governance metadata.
        This method is used by AISensitiveDetectionService.
        """
        try:
            if not self._embed_ready or not self._category_centroids:
                self._init_local_embeddings()
                
            if not self._embed_ready or not self._category_centroids:
                return {'categories': {}, 'overall_confidence': 0.0}
                
            # Embed texts - take first few as representative
            sample_text = " ".join([str(t) for t in texts[:5]])
            if context:
                # Enrich with context
                ctx_str = f"{context.get('table_name', '')} {context.get('column_name', '')} {sample_text}"
            else:
                ctx_str = sample_text
                
            # Get embedding
            vec = None
            if self._embedder:
                # Preprocess
                if 'e5' in str(self._model_name or '').lower():
                    ctx_str = f"query: {ctx_str}"
                    
                vecs = self._embedder.encode([ctx_str], normalize_embeddings=True)
                vec = vecs[0]
                
            if vec is None:
                return {'categories': {}, 'overall_confidence': 0.0}
                
            # Calculate similarities
            scores = {}
            for cat, centroid in self._category_centroids.items():
                if centroid is None: 
                    continue
                sim = float(np.dot(vec, centroid))
                scores[cat] = sim
                
            # Filter by threshold
            final_scores = {}
            max_score = 0.0
            for cat, score in scores.items():
                thresh = self._category_thresholds.get(cat, 0.45)
                if score >= thresh:
                    final_scores[cat] = score
                    max_score = max(max_score, score)
                    
            return {
                'categories': final_scores,
                'overall_confidence': max_score
            }
            
        except Exception as e:
            logger.error(f"classify_texts failed: {e}")
            return {'categories': {}, 'overall_confidence': 0.0}

    def _load_metadata_driven_categories(self) -> None:
        """
        Load ALL categories, keywords, and patterns from Snowflake governance tables.
        NO HARDCODED VALUES. System is 100% metadata-driven.
        
        Tables used:
        - SENSITIVITY_CATEGORIES: Category definitions and thresholds
        - SENSITIVE_KEYWORDS: Keywords mapped to categories
        - SENSITIVE_PATTERNS: Regex patterns mapped to categories
        """
        logger.info("=" * 80)
        logger.info("METADATA-DRIVEN CLASSIFICATION: Loading from governance tables")
        logger.info("=" * 80)
        
        # Resolve governance database
        schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
        gov_db = None
        try:
            gov_db = resolve_governance_db()
            if gov_db:
                snowflake_connector.execute_non_query(f"USE DATABASE {gov_db}")
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
                logger.info(f"✓ Using governance schema: {schema_fqn}")
        except Exception as e:
            logger.warning(f"✗ Could not resolve governance database: {e}")
            # If no governance DB, we cannot proceed with metadata-driven approach
            self._category_centroids = {}
            self._category_tokens = {}
            self._category_patterns = {}
            self._category_thresholds = {}
            self._category_weights = {}
            logger.error("CRITICAL: No governance database available. Classification will fail.")
            return
        
        # ========================================================================
        # STEP 1: Load SENSITIVITY_CATEGORIES (ALL FIELDS)
        # ========================================================================
        categories_data = []
        try:
            categories_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    CATEGORY_ID,
                    CATEGORY_NAME,
                    COALESCE(DESCRIPTION, '') AS DESCRIPTION,
                    COALESCE(DETECTION_THRESHOLD, 0.45) AS DETECTION_THRESHOLD,
                    COALESCE(DETECTION_THRESHOLD, 0.45) AS DEFAULT_THRESHOLD,
                    1.0 AS SENSITIVITY_WEIGHT,
                    POLICY_GROUP,
                    COALESCE(WEIGHT_EMBEDDING, 0.60) AS WEIGHT_EMBEDDING,
                    COALESCE(WEIGHT_KEYWORD, 0.25) AS WEIGHT_KEYWORD,
                    COALESCE(WEIGHT_PATTERN, 0.15) AS WEIGHT_PATTERN,
                    COALESCE(MULTI_LABEL, TRUE) AS MULTI_LABEL,
                    COALESCE(IS_ACTIVE, TRUE) AS IS_ACTIVE
                FROM {schema_fqn}.SENSITIVITY_CATEGORIES
                WHERE COALESCE(IS_ACTIVE, true)
                ORDER BY CATEGORY_NAME
                """
            ) or []
            logger.info(f"✓ Loaded {len(categories_data)} active categories from SENSITIVITY_CATEGORIES")
            
            # Debug: Log what was loaded
            for cat in categories_data:
                # Tolerate non-dict row types from the connector
                if not isinstance(cat, dict):
                    continue
                cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
                desc = str(cat.get("DESCRIPTION") or "").strip()
                pg = str(cat.get("POLICY_GROUP") or "None")
                logger.info(f"   Category: {cat_name} (Group: {pg}), Description length: {len(desc)} chars")
                
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVITY_CATEGORIES: {e}")
            import traceback
            logger.error(traceback.format_exc())
            categories_data = []
        
        if not categories_data:
            logger.error("CRITICAL: No active categories found in SENSITIVITY_CATEGORIES")
            logger.error("FALLBACK: Creating baseline PII/SOX/SOC2 categories")
            
            # GRACEFUL DEGRADATION: Use baseline categories
            self._create_baseline_categories()
            return  # Exit early - baseline categories are now loaded

        # Store category metadata with ALL fields
        self._category_thresholds = {}
        self._category_default_thresholds = {}
        self._category_weights = {}
        self._policy_group_by_category = {}
        self._category_scoring_weights = {}  # New: stores embedding/keyword/pattern weights
        self._category_multi_label = {}      # New: stores multi-label flag
        
        category_descriptions = {}
        category_ids = {}
        
        for cat in categories_data:
            # Ensure we only process dict rows
            if not isinstance(cat, dict):
                continue
            cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
            if not cat_name:
                logger.warning(f"Skipping category with empty CATEGORY_NAME")
                continue
            
            description = str(cat.get("DESCRIPTION") or "").strip()
            
            # CRITICAL: Validate description is not empty
            if not description:
                logger.error(f"CRITICAL: Category '{cat_name}' has EMPTY DESCRIPTION")
                logger.error(f"  → Centroid CANNOT be built without description")
                logger.error(f"  → This category will be SKIPPED")
                continue  # Skip this category
            
            if len(description) < 10:
                logger.warning(f"Category '{cat_name}' has very short DESCRIPTION ({len(description)} chars)")
            
            category_descriptions[cat_name] = description
            category_ids[cat_name] = cat.get("CATEGORY_ID")
            
            # Load thresholds and weights
            self._category_thresholds[cat_name] = float(cat.get("DETECTION_THRESHOLD") or 0.45)
            self._category_default_thresholds[cat_name] = float(cat.get("DEFAULT_THRESHOLD") or 0.45)
            self._category_weights[cat_name] = float(cat.get("SENSITIVITY_WEIGHT") or 1.0)
            
            # Load Policy Group (Metadata-Driven Mapping)
            policy_group = cat.get("POLICY_GROUP")
            if policy_group:
                self._policy_group_by_category[cat_name.upper()] = str(policy_group).strip()
            
            # Load Scoring Weights
            self._category_scoring_weights[cat_name] = {
                'w_sem': float(cat.get("WEIGHT_EMBEDDING") or 0.60),
                'w_kw': float(cat.get("WEIGHT_KEYWORD") or 0.25),
                'w_pat': float(cat.get("WEIGHT_PATTERN") or 0.15)
            }
            
            # Load Multi-Label Flag
            self._category_multi_label[cat_name] = bool(cat.get("MULTI_LABEL", True))
            
            # Load Color Code (Derived from Policy Group since column is removed)
            pg_upper = str(policy_group or "").upper()
            if pg_upper == 'PII':
                self._category_colors[cat_name.upper()] = "#FF5733"  # Red
            elif pg_upper == 'SOX':
                self._category_colors[cat_name.upper()] = "#FFA500"  # Orange
            elif pg_upper == 'SOC2':
                self._category_colors[cat_name.upper()] = "#4169E1"  # Blue
            else:
                self._category_colors[cat_name.upper()] = "#808080"  # Gray

            logger.info(f"  Category: {cat_name}")
            logger.info(f"    Group: {policy_group or 'None'}")
            logger.info(f"    Weights: Sem={self._category_scoring_weights[cat_name]['w_sem']:.2f}, Kw={self._category_scoring_weights[cat_name]['w_kw']:.2f}, Pat={self._category_scoring_weights[cat_name]['w_pat']:.2f}")
        
        # ========================================================================
        # STEP 2: Load SENSITIVE_KEYWORDS (ALL FIELDS)
        # ========================================================================
        keywords_by_category: Dict[str, List[str]] = {cat: [] for cat in category_descriptions.keys()}
        keyword_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in category_descriptions.keys()}
        
        try:
            keywords_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    c.CATEGORY_NAME,
                    k.KEYWORD_STRING,
                    COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS KEYWORD_WEIGHT,
                    COALESCE(k.MATCH_TYPE, 'EXACT') AS MATCH_TYPE,
                    'STANDARD' AS SENSITIVITY_TYPE,
                    COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS SCORE
                FROM {schema_fqn}.SENSITIVE_KEYWORDS k
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                  ON k.CATEGORY_ID = c.CATEGORY_ID
                WHERE COALESCE(k.IS_ACTIVE, true)
                  AND COALESCE(c.IS_ACTIVE, true)
                ORDER BY c.CATEGORY_NAME, k.KEYWORD_STRING
                """
            ) or []
            
            for kw in keywords_data:
                if not isinstance(kw, dict):
                    continue
                    
                cat_name = str(kw.get("CATEGORY_NAME") or "").strip()
                keyword = str(kw.get("KEYWORD_STRING") or "").strip().lower()
                
                if cat_name in keywords_by_category and keyword:
                    keywords_by_category[cat_name].append(keyword)
                    
                    # Store full metadata for advanced scoring
                    keyword_metadata_by_category[cat_name].append({
                        'keyword': keyword,
                        'weight': float(kw.get("KEYWORD_WEIGHT") or 1.0),
                        'match_type': str(kw.get("MATCH_TYPE") or "EXACT").upper(),
                        'sensitivity_type': str(kw.get("SENSITIVITY_TYPE") or "STANDARD").upper(),
                        'score': float(kw.get("SCORE") or 1.0)
                    })
            
            total_keywords = sum(len(kws) for kws in keywords_by_category.values())
            logger.info(f"✓ Loaded {total_keywords} keywords from SENSITIVE_KEYWORDS")
            for cat, kws in keywords_by_category.items():
                if kws:
                    logger.info(f"  {cat}: {len(kws)} keywords")
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVE_KEYWORDS: {e}")
        
        # ========================================================================
        # STEP 3: Load SENSITIVE_PATTERNS (ALL FIELDS)
        # ========================================================================
        patterns_by_category: Dict[str, List[str]] = {cat: [] for cat in category_descriptions.keys()}
        pattern_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in category_descriptions.keys()}
        
        try:
            patterns_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    c.CATEGORY_NAME,
                    p.PATTERN_REGEX,
                    COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS SENSITIVITY_WEIGHT,
                    COALESCE(p.SENSITIVITY_TYPE, 'STANDARD') AS SENSITIVITY_TYPE
                FROM {schema_fqn}.SENSITIVE_PATTERNS p
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                  ON p.CATEGORY_ID = c.CATEGORY_ID
                WHERE COALESCE(p.IS_ACTIVE, true)
                  AND COALESCE(c.IS_ACTIVE, true)
                ORDER BY c.CATEGORY_NAME
                """
            ) or []
            
            logger.info(f"Retrieved {len(patterns_data)} pattern rows from SENSITIVE_PATTERNS")
            
            for idx, pat in enumerate(patterns_data):
                # CRITICAL: Validate that Snowflake returned a dictionary, not a string
                if not isinstance(pat, dict):
                    logger.error(f"Pattern row {idx} is not a dict: type={type(pat)}, value={str(pat)[:100]}")
                    logger.error("This indicates a Snowflake connector issue - rows should be dictionaries")
                    continue
                    
                cat_name = str(pat.get("CATEGORY_NAME") or "").strip()
                # Use PATTERN_REGEX only
                pattern = str(pat.get("PATTERN_REGEX") or "").strip()
                
                if not cat_name:
                    logger.warning(f"Pattern row {idx} has empty CATEGORY_NAME, skipping")
                    continue
                
                if not pattern:
                    logger.warning(f"Pattern row {idx} for category '{cat_name}' has empty PATTERN_REGEX, skipping")
                    continue
                
                if cat_name in patterns_by_category:
                    patterns_by_category[cat_name].append(pattern)
                    
                    # Store full metadata for weighted scoring
                    # CRITICAL: Ensure we create a proper dictionary structure
                    pattern_metadata_by_category[cat_name].append({
                        'pattern': pattern,
                        'weight': float(pat.get("SENSITIVITY_WEIGHT") or 1.0),
                        'sensitivity_type': str(pat.get("SENSITIVITY_TYPE") or "STANDARD").upper()
                    })
                    
                    logger.debug(f"  Loaded pattern for {cat_name}: {pattern[:50]}... (weight={pat.get('SENSITIVITY_WEIGHT', 1.0)})")
                else:
                    logger.warning(f"Category '{cat_name}' not found in category_descriptions, skipping pattern")
            
            total_patterns = sum(len(pats) for pats in patterns_by_category.values())
            logger.info(f"✓ Loaded {total_patterns} patterns from SENSITIVE_PATTERNS")
            for cat, pats in patterns_by_category.items():
                if pats:
                    logger.info(f"  {cat}: {len(pats)} patterns")
                    
            # VALIDATION: Verify pattern metadata structure
            for cat, metadata_list in pattern_metadata_by_category.items():
                for idx, meta in enumerate(metadata_list):
                    if not isinstance(meta, dict):
                        logger.error(f"CRITICAL: Pattern metadata for {cat}[{idx}] is not a dict: {type(meta)}")
                    elif 'pattern' not in meta:
                        logger.error(f"CRITICAL: Pattern metadata for {cat}[{idx}] missing 'pattern' key")
                        
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVE_PATTERNS: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        # ========================================================================
        # STEP 4: Build Embeddings (if available)
        # ========================================================================
        centroids: Dict[str, Any] = {}
        tokens_out: Dict[str, List[str]] = {}
        
        logger.info(f"Building centroids for {len(category_descriptions)} categories...")
        logger.info(f"Embedder available: {self._embedder is not None}")
        logger.info(f"NumPy available: {np is not None}")
        logger.info(f"Backend: {self._embed_backend}")
        
        for cat_name, description in category_descriptions.items():
            logger.info(f"\n  Processing category: {cat_name}")
            logger.info(f"    Description: '{description[:100]}...'")
            
            # Combine description + keywords for richer context
            keywords = keywords_by_category.get(cat_name, [])
            combined_text = f"{description} {' '.join(keywords[:50])}"  # Use top 50 keywords
            logger.info(f"    Keywords available: {len(keywords)}")
            logger.info(f"    Combined text length: {len(combined_text)} chars")
            
            # Generate tokens
            try:
                toks = self._generate_category_tokens(cat_name, combined_text)
                if toks:
                    tokens_out[cat_name] = toks
                    logger.info(f"    ✓ Generated {len(toks)} tokens")
                else:
                    logger.warning(f"    ✗ No tokens generated")
            except Exception as e:
                logger.error(f"    ✗ Token generation failed: {e}")
                tokens_out[cat_name] = []
            
            # Generate embeddings using asymmetric E5 encoding (passage: for category centroids)
            try:
                if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                    # Build rich category definition from description + keywords
                    category_definition = f"{description}"  # Start with description
                    
                    # Add keyword context if available
                    if keywords:
                        keyword_list = ", ".join(keywords[:15])  # Top 15 keywords
                        category_definition += f" This includes: {keyword_list}."
                    
                    # Add example patterns if this is about data formats
                    common_examples = {
                        'email': 'such as user@domain.com',
                        'phone': 'such as 555-123-4567',
                        'ssn': 'such as 123-45-6789',
                        'credit': 'such as 4111-1111-1111-1111',
                        'price': 'such as $99.99',
                        'date': 'such as 2024-01-15'
                    }
                    
                    cat_lower = cat_name.lower()
                    for pattern_kw, example in common_examples.items():
                        if pattern_kw in cat_lower or any(pattern_kw in kw.lower() for kw in keywords[:5]):
                            category_definition += f" Examples include values {example}."
                            break

                    logger.info(f"    Category definition: '{category_definition[:150]}...'")

                    # Asymmetric E5: use passage: prefix for category/"document" side
                    passage_text = f"passage: {category_definition}"
                    logger.info("    Encoding category definition with 'passage:' prefix (E5 asymmetric)...")
                    centroid_vec = self._embedder.encode([passage_text], normalize_embeddings=True)[0]
                    
                    # Normalize centroid
                    norm = float(np.linalg.norm(centroid_vec) or 0.0)
                    if norm > 0:
                        centroid_vec = centroid_vec / norm
                        centroids[cat_name] = centroid_vec
                        logger.info(f"    ✓ Created E5 category centroid for {cat_name} (dimension: {len(centroid_vec)})")
                        logger.info(f"    ✓ Using passage-based encoding for accurate semantic matching")
                    else:
                        logger.warning(f"    ✗ Zero norm centroid for {cat_name}")
                        centroids[cat_name] = None
                    
                else:
                    logger.warning(f"    ✗ Cannot create centroid: embedder={self._embedder is not None}, np={np is not None}, backend={self._embed_backend}")
                    centroids[cat_name] = None
            except Exception as e:
                logger.error(f"    ✗ Failed to create centroid for {cat_name}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                centroids[cat_name] = None
        
        # ========================================================================
        # STEP 5: Store in instance variables (INCLUDING METADATA)
        # ========================================================================
        self._category_centroids = centroids
        self._category_tokens = tokens_out
        self._category_patterns = patterns_by_category
        self._category_keywords = keywords_by_category
        self._category_keyword_metadata = keyword_metadata_by_category  # NEW: Full keyword metadata
        self._category_pattern_metadata = pattern_metadata_by_category  # NEW: Full pattern metadata
        self._category_ids = category_ids  # NEW: Category IDs for saving results

        # Verification-only logging for policy-group mappings loaded from governance.
        try:
            logger.info("=" * 80)
            logger.info("POLICY GROUP MAPPING VERIFICATION")
            logger.info(f"  Total mappings: {len(self._policy_group_by_category)}")
            for cat, pg in (self._policy_group_by_category or {}).items():
                logger.info(f"    {cat}  {pg}")
            logger.info("=" * 80)
        except Exception:
            pass

        # Summary
        logger.info("=" * 80)
        logger.info("METADATA-DRIVEN CLASSIFICATION: Initialization Complete")
        logger.info(f"  Categories: {len(category_descriptions)}")
        logger.info(f"  Keywords: {sum(len(kws) for kws in keywords_by_category.values())}")
        logger.info(f"  Patterns: {sum(len(pats) for pats in patterns_by_category.values())}")
        logger.info(f"  Centroids: {len([c for c in centroids.values() if c is not None])}")
        logger.info(f"  Metadata Loaded: Keywords={len(keyword_metadata_by_category)}, Patterns={len(pattern_metadata_by_category)}")
        logger.info("=" * 80)
        
        try:
            st.session_state["_pipe_cat_count"] = len([c for c in centroids.values() if c is not None])
            st.session_state["_pipe_tok_count"] = sum(len(v) for v in tokens_out.values())
        except Exception:
            pass
    
    def _create_baseline_categories(self) -> None:
        """
        PHASE 1: Create baseline fallback categories when governance tables unavailable.
        
        This ensures the system ALWAYS has working PII/SOX/SOC2 categories,
        even when governance tables are empty or misconfigured.
        """
        logger.warning("=" * 80)
        logger.warning("CREATING BASELINE FALLBACK CATEGORIES")
        logger.warning("Governance tables unavailable - using built-in categories")
        logger.warning("=" * 80)
        
        # Baseline category definitions with rich metadata
        baseline_categories = {
            'PII_PERSONAL_INFO': {
                'description': 'Personal Identifiable Information including names, email addresses, phone numbers, physical addresses, Social Security Numbers, passport numbers, driver license numbers, dates of birth, and other individual identifiers that can be used to identify, contact, or locate a specific person',
                'keywords': [
                    'name', 'first_name', 'last_name', 'full_name', 'email', 'email_address', 
                    'phone', 'phone_number', 'mobile', 'telephone', 'contact', 'address', 
                    'street', 'city', 'state', 'zip', 'postal', 'ssn', 'social_security', 
                    'passport', 'driver_license', 'dob', 'date_of_birth', 'birthday', 'age',
                    'customer', 'employee', 'person', 'individual', 'user', 'patient',
                    'gender', 'race', 'ethnicity', 'nationality', 'citizen'
                ],
                'patterns': [
                    r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Full names
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone
                ],
                'threshold': 0.40,
                'policy_group': 'PII'
            },
            'SOX_FINANCIAL_DATA': {
                'description': 'Financial and accounting data including revenue records, transaction details, account balances, payment information, invoices, billing records, general ledger entries, expense reports, cost allocations, profit calculations, asset valuations, and other financial information subject to SOX compliance requirements',
                'keywords': [
                    'revenue', 'transaction', 'account', 'account_number', 'balance', 'payment', 
                    'invoice', 'bill', 'billing', 'financial', 'ledger', 'general_ledger', 
                    'expense', 'cost', 'profit', 'asset', 'liability', 'equity', 'cash',
                    'credit_card', 'debit_card', 'card_number', 'routing', 'ach', 'wire',
                    'salary', 'wage', 'compensation', 'payroll', 'tax', 'fiscal', 'audit'
                ],
                'patterns': [
                    r'\$[\d,]+\.\d{2}',  # Currency
                    r'\b\d{13,19}\b',  # Credit card
                ],
                'threshold': 0.40,
                'policy_group': 'SOX'
            },
            'SOC2_SECURITY_DATA': {
                'description': 'Security and access control data including passwords, authentication tokens, API keys, encryption keys, certificates, credentials, security logs, access records, authentication attempts, authorization decisions, privilege escalations, and other security-critical information required for SOC2 compliance',
                'keywords': [
                    'password', 'passwd', 'pwd', 'token', 'credential', 'secret', 'key', 
                    'api_key', 'auth', 'authenticate', 'authorization', 'login', 'logout',
                    'access', 'permission', 'privilege', 'role', 'security', 'encryption',
                    'certificate', 'signature', 'hash', 'salt', 'session', 'cookie'
                ],
                'patterns': [
                    r'\b[A-Za-z0-9]{32,}\b',  # API keys/tokens
                ],
                'threshold': 0.40,
                'policy_group': 'SOC2'
            }
        }
        
        # Initialize data structures
        self._category_centroids = {}
        self._category_keywords = {}
        self._category_patterns = {}
        self._category_thresholds = {}
        self._category_weights = {}
        self._policy_group_by_category = {}
        self._category_keyword_metadata = {}  # Initialize metadata structure
        self._category_pattern_metadata = {}  # Initialize metadata structure
        
        # Build from baseline definitions
        for cat_name, cat_data in baseline_categories.items():
            # Store keywords (simple list)
            self._category_keywords[cat_name] = cat_data['keywords']
            
            # Store keyword metadata (list of dicts for scoring)
            self._category_keyword_metadata[cat_name] = [
                {
                    'keyword': kw,
                    'weight': 1.0,
                    'match_type': 'EXACT',
                    'sensitivity_type': 'STANDARD',
                    'score': 1.0
                }
                for kw in cat_data['keywords']
            ]
            
            # Store patterns (simple list)
            self._category_patterns[cat_name] = cat_data['patterns']
            
            # Store pattern metadata (list of dicts for scoring)
            self._category_pattern_metadata[cat_name] = [
                {
                    'pattern': pat,
                    'weight': 1.0,
                    'sensitivity_type': 'STANDARD'
                }
                for pat in cat_data['patterns']
            ]
            
            # Store threshold (lowered to 0.40 for better recall)
            self._category_thresholds[cat_name] = cat_data['threshold']
            
            # Store weight
            self._category_weights[cat_name] = 1.0
            
            # Store policy mapping
            self._policy_group_by_category[cat_name.upper()] = cat_data['policy_group']
            
            # Store scoring weights (default)
            self._category_scoring_weights[cat_name] = {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15}
            
            # Store multi-label flag (default True)
            self._category_multi_label[cat_name] = True
            
            # Create centroid if embeddings available
            if self._embedder and self._embed_backend == 'sentence-transformers':
                try:
                    # Combine description + keywords for rich representation
                    examples = [cat_data['description']] + cat_data['keywords'][:15]
                    
                    # Encode with normalization
                    vecs = self._embedder.encode(examples, normalize_embeddings=True)
                    
                    # Weighted average (description gets 2x weight)
                    weights = [2.0] + [1.0] * (len(vecs) - 1)
                    weights_array = np.array(weights) / np.sum(weights)
                    centroid = np.average(vecs, axis=0, weights=weights_array)
                    
                    # Normalize centroid
                    norm = float(np.linalg.norm(centroid))
                    if norm > 0:
                        self._category_centroids[cat_name] = centroid / norm
                        logger.info(f"  ✓ Created centroid for {cat_name}")
                    else:
                        self._category_centroids[cat_name] = None
                        logger.warning(f"  ✗ Failed to create centroid for {cat_name} (zero norm)")
                
                except Exception as e:
                    logger.error(f"  ✗ Failed to create centroid for {cat_name}: {e}")
                    self._category_centroids[cat_name] = None
            else:
                self._category_centroids[cat_name] = None
        
        logger.warning(f"Created {len(baseline_categories)} baseline categories:")
        logger.warning(f"  - Categories: {', '.join(baseline_categories.keys())}")
        logger.warning(f"  - Total keywords: {sum(len(kws) for kws in self._category_keywords.values())}")
        logger.warning(f"  - Total patterns: {sum(len(pats) for pats in self._category_patterns.values())}")
        logger.warning(f"  - Centroids created: {len([c for c in self._category_centroids.values() if c is not None])}")
        logger.warning(f"  - Policy mappings: {len(self._policy_group_by_category)}")
        logger.warning("=" * 80)
    
    def _create_fallback_categories(self) -> None:
        """
        DEPRECATED: Use _create_baseline_categories() instead.
        This method now delegates to the baseline approach.
        """
        logger.warning("_create_fallback_categories() is deprecated. Using _create_baseline_categories().")
        self._create_baseline_categories()

    def _semantic_scores(self, text: str, vector: Optional[np.ndarray] = None) -> Dict[str, float]:
        """Compute semantic similarity scores per category using governance-driven centroids.

        Uses asymmetric E5 encoding for classification text ("query:" prefix) against
        category centroids encoded as "passage:". Returns raw boosted scores without
        min-max normalization, to preserve absolute confidence levels for downstream
        threshold-based filtering.
        """
        scores: Dict[str, float] = {}
        if not text and vector is None:
            return scores
        if self._embedder is None or not self._category_centroids:
            logger.warning("Embedder or category centroids not available for semantic scoring")
            return scores
        
        try:
            # Get or compute embedding vector
            v = vector
            if v is None:
                # Asymmetric E5: embed classification text with "query:" prefix
                t = str(text or "")
                key = f"emb::query::{t}"
                v = self._embed_cache.get(key) if hasattr(self, "_embed_cache") else None

                if v is None:
                    query_text = f"query: {t}"
                    v_raw = self._embedder.encode([query_text], normalize_embeddings=True)
                    v = np.asarray(v_raw[0], dtype=float)

                    try:
                        if hasattr(self, "_embed_cache"):
                            self._embed_cache[key] = v
                    except Exception:
                        pass
            
            # Ensure vector is normalized
            n = float(np.linalg.norm(v) or 0.0)
            if n > 0:
                v = v / n

            # Calculate raw cosine similarities against all category centroids
            raw: Dict[str, float] = {}
            for cat, centroid in self._category_centroids.items():
                try:
                    if centroid is None:
                        continue
                    
                    # **CRITICAL FIX**: Normalize centroid before cosine similarity
                    # Without this, similarity scores are mathematically incorrect!
                    centroid_norm = float(np.linalg.norm(centroid) or 0.0)
                    if centroid_norm == 0:
                        logger.debug(f"Centroid for {cat} has zero norm, skipping")
                        continue
                    
                    normalized_centroid = centroid / centroid_norm
                    
                    # Cosine similarity (dot product of normalized vectors)
                    # Both vectors MUST be normalized for correct cosine similarity
                    sim = float(np.dot(v, normalized_centroid))
                    
                    # Cosine similarity is in [-1, 1], convert to [0, 1] confidence
                    conf = max(0.0, min(1.0, (sim + 1.0) / 2.0))
                    raw[cat] = conf
                    
                    logger.debug(f"Similarity for {cat}: {sim:.4f} → confidence: {conf:.4f}")
                    
                except Exception as e:
                    logger.debug(f"Similarity calculation failed for {cat}: {e}")
                    continue

            if not raw:
                return {}

            # Multiplicative boosting only for strong signals (>= 0.60)
            boosted: Dict[str, float] = {}
            for cat, confidence in raw.items():
                # Get category-specific threshold from governance data (default 0.55)
                threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.55)

                if confidence >= 0.60:
                    # Strong signal → modest boost up to ~20%
                    boost_factor = 1.10 + (confidence - 0.60) * 0.25
                else:
                    # No boost for weak signals
                    boost_factor = 1.0

                boosted_conf = confidence * boost_factor
                final_conf = max(0.0, min(0.95, boosted_conf))

                # Only include if meets category threshold
                if final_conf >= threshold:
                    boosted[cat] = final_conf

            # RETURN RAW BOOSTED SCORES - NO MIN-MAX NORMALIZATION
            scores = boosted

            logger.debug(f"Semantic scores (E5 asymmetric, no normalization): {scores}")
                
        except Exception as e:
            logger.error(f"Semantic scoring failed: {e}", exc_info=True)
            return {}
        
        return scores


    def _compute_fused_embedding(self, name: str, values: str, metadata: str, data_type: str = "", sample_values: List[Any] = None) -> Optional[np.ndarray]:
        """Compute multi-view fused embedding from name, values, and metadata.

        Uses asymmetric E5 encoding for the query side ("query:" prefix) combined from
        column name, values, and metadata. Weights: 50% name, 30% values, 20% metadata.
        
        Args:
            name: Column name
            values: Sample values as string
            metadata: Column metadata/comments
            data_type: SQL data type
            sample_values: List of actual sample values for type detection
        
        Returns:
            Fused embedding vector or None
        """
        if self._embedder is None:
            return None
        try:
            # Infer semantic type for better context
            semantic_type = ""
            if sample_values:
                try:
                    semantic_type = semantic_type_detector.infer_semantic_type(
                        sample_values, data_type, name
                    )
                except Exception:
                    pass
            
            # Encode each component with asymmetric E5 "query:" prefix
            vecs = []
            weights = []
            
            # View 1: Column Name (50% weight - most important for classification)
            if name:
                v_name = self._embedder.encode([f"query: {name}"], normalize_embeddings=True)[0]
                vecs.append(v_name)
                weights.append(0.50)
            
            # View 2: Sample Values with Semantic Type Hint (30% weight)
            if values:
                if semantic_type:
                    values_text = f"query: {semantic_type} values: {values[:200]}"
                else:
                    values_text = f"query: {values[:200]}"
                v_vals = self._embedder.encode([values_text], normalize_embeddings=True)[0]
                vecs.append(v_vals)
                weights.append(0.30)
            
            # View 3: Metadata/Comments (20% weight)
            if metadata:
                v_meta = self._embedder.encode([f"query: {metadata}"], normalize_embeddings=True)[0]
                vecs.append(v_meta)
                weights.append(0.20)
            
            if not vecs:
                return None
            
            # Weighted average instead of simple mean
            weights_array = np.array(weights) / np.sum(weights)  # Normalize weights
            final_vec = np.average(vecs, axis=0, weights=weights_array)
            
            # Normalize
            n = float(np.linalg.norm(final_vec) or 0.0)
            if n > 0:
                final_vec = final_vec / n
                
            return final_vec
        except Exception as e:
            logger.error(f"Multi-view embedding failed: {e}")
            return None

    def _get_min_max_values(self, db: str, schema: str, table: str, column: str) -> Tuple[Optional[str], Optional[str]]:
        """Get MIN and MAX values for a column to improve range detection.

        Uses aliased columns so we can safely access Snowflake's dict-style results.
        """
        try:
            q = f'''
            SELECT
                MIN("{column}") AS MIN_VAL,
                MAX("{column}") AS MAX_VAL
            FROM "{db}"."{schema}"."{table}"
            WHERE "{column}" IS NOT NULL
            '''
            rows = snowflake_connector.execute_query(q) or []
            if rows:
                r = rows[0] or {}
                mn = r.get("MIN_VAL")
                mx = r.get("MAX_VAL")
                return (str(mn) if mn is not None else None, str(mx) if mx is not None else None)
        except Exception:
            pass
        return None, None

    def _keyword_scores(self, text: str) -> Dict[str, float]:
        """
        Enhanced keyword scoring with weighted matching and exact match bonuses.
        Now uses metadata-driven approach from governance tables.
        """
        # Delegate to metadata-driven keyword scoring
        return self._keyword_scores_metadata_driven(text)

    def _pattern_scores(self, text: str) -> Dict[str, float]:
        """
        Calculate pattern matching scores using patterns from governance tables.
        Handles both _category_pattern_metadata (preferred) and legacy _category_patterns.
        
        Returns:
            Dictionary mapping category names to pattern match scores (0.0 to 1.0)
        """
        scores = {}
        if not text:
            return scores
            
        text_lower = text.lower()
        patterns_available = hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata
        legacy_patterns_available = hasattr(self, '_category_patterns') and self._category_patterns
        
        if not patterns_available and not legacy_patterns_available:
            logger.debug("No pattern metadata available for scoring")
            return scores
        
        try:
            # Try to use _category_pattern_metadata first (preferred)
            if patterns_available:
                for category, pattern_list in self._category_pattern_metadata.items():
                    if not pattern_list:
                        continue
                        
                    total_weighted_score = 0.0
                    total_possible_weight = 0.0
                    
                    for pattern_item in pattern_list:
                        # Handle both dict and string patterns
                        pattern = ''
                        weight = 1.0
                        
                        if isinstance(pattern_item, dict):
                            pattern = pattern_item.get('pattern', '')
                            weight = float(pattern_item.get('weight', 1.0))
                        elif isinstance(pattern_item, str):
                            pattern = pattern_item
                        else:
                            logger.warning(f"Invalid pattern type for {category}: {type(pattern_item).__name__}, skipping")
                            continue
                        
                        if not pattern or not isinstance(pattern, str):
                            continue
                        
                        try:
                            if re.search(pattern, text_lower, re.IGNORECASE):
                                total_weighted_score += weight
                                logger.debug(f"Pattern match for {category}: '{pattern[:50]}...' (weight={weight:.1f})")
                        except re.error as e:
                            logger.warning(f"Invalid regex pattern for {category}: '{pattern[:50]}...' Error: {e}")
                            continue
                        
                        total_possible_weight += weight
                    
                    # Calculate final score if we had any possible weight
                    if total_possible_weight > 0:
                        raw_score = min(1.0, (total_weighted_score / total_possible_weight))
                        
                        # Apply sigmoid scaling to make scores more distinct
                        score = 1 / (1 + math.exp(-10 * (raw_score - 0.5)))
                        
                        # Get category-specific threshold
                        threshold = getattr(self, '_category_thresholds', {}).get(category, 0.30)
                        category_weight = getattr(self, '_category_weights', {}).get(category, 1.0)
                        
                        # Apply category weight and threshold
                        final_score = min(1.0, score * category_weight)
                        
                        if final_score >= threshold:
                            scores[category] = final_score
                            logger.debug(
                                f"Pattern scores for {category}: "
                                f"raw={raw_score:.3f}, final={final_score:.3f} "
                                f"(threshold={threshold:.2f}, weight={category_weight:.1f})"
                            )
            
            # Fall back to legacy _category_patterns if no scores from metadata
            if not scores and legacy_patterns_available:
                logger.debug("Falling back to legacy _category_patterns")
                for category, patterns in self._category_patterns.items():
                    if not patterns:
                        continue
                        
                    match_count = 0
                    
                    for pattern in patterns[:20]:  # Limit to first 20 patterns per category
                        if not pattern or not isinstance(pattern, str):
                            continue
                             
                        try:
                            if re.search(pattern, text_lower, re.IGNORECASE):
                                match_count += 1
                        except re.error as e:
                            logger.warning(f"Invalid legacy pattern for {category}: '{pattern[:50]}...' Error: {e}")
                            continue
                    
                    if match_count > 0:
                        # Simple scoring for legacy patterns
                        raw_score = min(1.0, match_count / 3.0)
                        score = 1 / (1 + math.exp(-10 * (raw_score - 0.5)))
                        
                        # Apply default threshold for legacy patterns
                        if score >= 0.30:  # Default threshold for legacy patterns
                            scores[category] = score
                            logger.debug(f"Legacy pattern match for {category}: {match_count} patterns, score={score:.3f}")
            
            return scores
            
        except Exception as e:
            logger.error(f"Error in pattern scoring: {e}", exc_info=True)
            return {}

    def _keyword_scores_with_matches(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        scores: Dict[str, float] = {}
        matched: Dict[str, List[str]] = {}
        t = (text or '').lower()

        if not hasattr(self, '_category_keyword_metadata') or not self._category_keyword_metadata:
            logger.warning("No category keyword metadata loaded from governance tables")
            return scores, matched

        for category, keyword_list in self._category_keyword_metadata.items():
            if not keyword_list:
                continue

            total_weighted_score = 0.0
            match_count = 0
            cat_matches: List[str] = []

            for kw_meta in keyword_list:
                if not isinstance(kw_meta, dict):
                    continue
                    
                keyword = kw_meta.get('keyword', '')
                if not keyword:
                    continue
                    
                weight = kw_meta.get('weight', 1.0)
                match_type = kw_meta.get('match_type', 'PARTIAL')
                base_score = kw_meta.get('score', 0.0)

                matched_flag = False
                match_quality = 0.0

                try:
                    if match_type == 'EXACT':
                        # Use real word boundaries for exact keyword matching
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                    elif match_type == 'PARTIAL':
                        if keyword in t:
                            matched_flag = True
                            match_quality = 0.8
                    elif match_type == 'FUZZY':
                        keyword_words = keyword.split()
                        if any(word in t for word in keyword_words):
                            matched_flag = True
                            match_quality = 0.6
                    else:
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                except Exception:
                    if keyword in t:
                        matched_flag = True
                        match_quality = 0.7

                if matched_flag:
                    match_count += 1
                    contribution = base_score * weight * match_quality
                    total_weighted_score += contribution
                    cat_matches.append(keyword)
                    logger.debug(f"    Keyword match: '{keyword}' ({match_type})  score={contribution:.3f}")

            if match_count > 0:
                # Use a more permissive default threshold so governance-driven
                # keywords can contribute alongside embeddings and patterns.
                threshold = getattr(self, '_category_thresholds', {}).get(category, 0.30)
                category_weight = getattr(self, '_category_weights', {}).get(category, 1.0)
                num_keywords = len(keyword_list)
                normalized_score = (total_weighted_score / max(1, num_keywords)) * category_weight
                final_score = min(1.0, normalized_score)

                if final_score >= threshold:
                    scores[category] = final_score
                    matched[category] = cat_matches
                    logger.debug(f"   Keyword score: {category} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                else:
                    logger.debug(f"   Below threshold: {category} = {final_score:.2f} < {threshold:.2f}")

        return scores, matched

    def _keyword_scores_metadata_driven(self, text: str) -> Dict[str, float]:
        """
        Metadata-driven keyword scoring using ONLY data from governance tables.
        NO HARDCODED KEYWORDS.
        
        Uses self._category_keyword_metadata loaded from SENSITIVE_KEYWORDS table.
        Applies MATCH_TYPE, SENSITIVITY_TYPE, and SCORE from metadata.
        """
        scores, _ = self._keyword_scores_with_matches(text)
        return scores
    
    def _fallback_keyword_matching(self, text: str) -> Dict[str, float]:
        """
        DEPRECATED: Use _keyword_scores_metadata_driven() instead.
        This method now delegates to the metadata-driven approach.
        """
        logger.warning("_fallback_keyword_matching() is deprecated. Using metadata-driven keyword scoring.")
        return self._keyword_scores_metadata_driven(text)

    def _convert_results_to_dataframe(self, results: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert in-memory classification results to DataFrame matching DB schema."""
        data = []
        for r in results:
            # Handle table-level results that contain column_results
            cols = r.get('column_results', [])
            if cols:
                for col in cols:
                    try:
                        # Map fields to match _fetch_classification_history output
                        category = col.get('category', 'Unknown')
                        policy_group = col.get('policy_group')
                        
                        # Derive compliance name if missing
                        if not policy_group:
                            policy_group = self._map_category_to_policy_group(category) or 'None'
                            
                        # Get sensitivity name from label if available, else fallback to category
                        sensitivity = col.get('label') or category 
                        
                        # Construct rationale
                        rationale = ""
                        if col.get('detected_categories'):
                             rationale = f"Detected: {', '.join([d['category'] for d in col['detected_categories']])}"
                        
                        row = {
                            'Schema': str(col.get('schema', '')).strip() or 'Unknown',
                            'Table': str(col.get('table', '')).strip() or 'Unknown',
                            'Column': str(col.get('column_name', '')).strip() or 'Unknown',
                            'Category': category,
                            'Confidence': float(col.get('confidence', 0.0)),
                            'Sensitivity': sensitivity,
                            'Compliance': policy_group,
                            'CIA': f"C:{col.get('c','-')} I:{col.get('i','-')} A:{col.get('a','-')}",
                            'Rationale': rationale
                        }
                        data.append(row)
                    except Exception as e:
                        logger.warning(f"Error converting result row: {e}")
                        continue
                
        if not data:
            return pd.DataFrame()
            
        return pd.DataFrame(data)

    def _extract_cia_from_details(self, details_raw: Any) -> str:
        """Extract CIA values from DETAILS column (JSON/Dict) and format as string."""
        cia_str = "C:- I:- A:-"
        try:
            if not details_raw:
                return cia_str
                
            details_json = {}
            if isinstance(details_raw, dict):
                details_json = details_raw
            elif isinstance(details_raw, str):
                import json
                try:
                    details_json = json.loads(details_raw)
                except Exception:
                    pass
            
            cia_data = details_json.get('cia') or {}
            if cia_data:
                c_val = cia_data.get('c', '-')
                i_val = cia_data.get('i', '-')
                a_val = cia_data.get('a', '-')
                cia_str = f"C:{c_val} I:{i_val} A:{a_val}"
        except Exception:
            pass
        return cia_str

    def _fetch_classification_history(self) -> pd.DataFrame:
        """Fetch all classification results from the governance database."""
        try:
            # Get the current database to use as context for governance DB resolution
            current_db = self._get_active_database()
            gov_db = self._get_governance_database(current_db)
            if not gov_db:
                logger.warning("No governance database configured")
                return pd.DataFrame()

            # First, check which columns exist in CLASSIFICATION_AI_RESULTS
            try:
                col_check_query = f"""
                    SELECT COLUMN_NAME
                    FROM {gov_db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE'
                      AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'
                """
                available_cols = snowflake_connector.execute_query(col_check_query) or []
                col_names = {str(c.get('COLUMN_NAME', '')).upper() for c in available_cols}
                
                has_schema_name = 'SCHEMA_NAME' in col_names
                has_sens_cat_id = 'SENSITIVITY_CATEGORY_ID' in col_names
                
                logger.info(f"CLASSIFICATION_AI_RESULTS columns: SCHEMA_NAME={has_schema_name}, SENSITIVITY_CATEGORY_ID={has_sens_cat_id}")
            except Exception as col_err:
                logger.warning(f"Could not check columns: {col_err}. Using defaults.")
                has_schema_name = has_sens_cat_id = False

            # Build query dynamically based on available columns
            schema_col = "r.SCHEMA_NAME" if has_schema_name else "NULL AS SCHEMA_NAME"
            sens_cat_col = "r.SENSITIVITY_CATEGORY_ID" if has_sens_cat_id else "NULL AS SENSITIVITY_CATEGORY_ID"
            
            # Query using ONLY SENSITIVITY_CATEGORIES (no COMPLIANCE_CATEGORIES)
            # Get POLICY_GROUP directly from SENSITIVITY_CATEGORIES
            query = f"""
                SELECT 
                    r.TABLE_NAME,
                    r.COLUMN_NAME,
                    r.AI_CATEGORY,
                    r.FINAL_CONFIDENCE,
                    r.DETAILS,
                    {schema_col},
                    {sens_cat_col},
                    sc.CATEGORY_NAME as SENSITIVITY_NAME,
                    sc.POLICY_GROUP as COMPLIANCE_NAME
                FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS r
                LEFT JOIN {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES sc
                    ON {('r.SENSITIVITY_CATEGORY_ID = sc.CATEGORY_ID') if has_sens_cat_id else '1=0'}
                ORDER BY r.FINAL_CONFIDENCE DESC
            """
            
            # Execute query and ensure we have a list of rows
            try:
                rows = snowflake_connector.execute_query(query) or []
                if not isinstance(rows, (list, tuple)):
                    logger.warning(f"Expected list of rows but got {type(rows).__name__}")
                    rows = []
            except Exception as e:
                logger.error(f"Error executing classification history query: {e}")
                rows = []
            
            data = []
            processed_rows = 0
            skipped_rows = 0
            
            for row in rows:
                try:
                    # Skip non-dictionary rows and convert to dict if possible
                    if not row:
                        skipped_rows += 1
                        continue
                        
                    # Convert row to dict if it's not already one
                    if not isinstance(row, dict):
                        if hasattr(row, '_asdict'):  # Handle SQLAlchemy row objects
                            row = row._asdict()
                        elif hasattr(row, '__dict__'):  # Handle other object-like rows
                            row = vars(row)
                        elif isinstance(row, (list, tuple)):  # Handle tuple rows
                            # If we have column info, create a dict with column names
                            if hasattr(rows, 'keys') and len(rows.keys()) == len(row):
                                row = dict(zip(rows.keys(), row))
                            else:
                                # Fallback to generic column names
                                row = {f'col_{i}': val for i, val in enumerate(row)}
                        else:
                            logger.warning(f"Skipping row of type {type(row).__name__}: {str(row)[:200]}...")
                            skipped_rows += 1
                            continue
                    
                    # Safely extract values with proper type conversion
                    row_data = {}
                    
                    # Handle each field with individual try/except to prevent one bad field from breaking everything
                    try:
                        row_data['ai_category'] = str(row.get('AI_CATEGORY', '') or '').strip() or 'Unknown'
                    except Exception as e:
                        logger.debug(f"Error getting AI_CATEGORY: {e}")
                        row_data['ai_category'] = 'Unknown'
                    
                    try:
                        row_data['compliance_name'] = str(row.get('COMPLIANCE_NAME', '') or '').strip()
                    except Exception as e:
                        logger.debug(f"Error getting COMPLIANCE_NAME: {e}")
                        row_data['compliance_name'] = ''
                    
                    # If no compliance name, try to derive from AI_CATEGORY
                    if not row_data['compliance_name'] or row_data['compliance_name'].lower() in ('none', 'null'):
                        try:
                            row_data['compliance_name'] = self._map_category_to_policy_group(row_data['ai_category']) or 'None'
                        except Exception as e:
                            logger.debug(f"Error mapping category to policy group: {e}")
                            row_data['compliance_name'] = 'None'
                    
                    # Build the result dictionary with safe access
                    result = {
                        'Schema': str(row.get('SCHEMA_NAME', '') or '').strip() or 'Unknown',
                        'Table': str(row.get('TABLE_NAME', '') or '').strip() or 'Unknown',
                        'Column': str(row.get('COLUMN_NAME', '') or '').strip() or 'Unknown',
                        'Category': row_data['ai_category'],
                        'Confidence': 0.0,
                        'Sensitivity': str(row.get('SENSITIVITY_NAME', '') or '').strip() or row_data['ai_category'],
                        'Compliance': row_data['compliance_name'],
                        'CIA': self._extract_cia_from_details(row.get('DETAILS')),
                        'Rationale': str(row.get('DETAILS', '') or '').strip()
                    }
                    
                    # Handle numeric conversion separately
                    try:
                        result['Confidence'] = float(row.get('FINAL_CONFIDENCE', 0) or 0.0)
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Invalid confidence value: {row.get('FINAL_CONFIDENCE')}, using 0.0")
                        result['Confidence'] = 0.0
                    
                    data.append(result)
                    processed_rows += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing row {skipped_rows + processed_rows + 1}: {str(e)[:200]}")
                    skipped_rows += 1
                    continue
            
            if skipped_rows > 0:
                logger.warning(f"Skipped {skipped_rows} invalid rows out of {len(rows)}")
                
            logger.info(f"Successfully processed {processed_rows} classification results")
            
            logger.info(f"Fetched {len(data)} classification results from governance database")
            return pd.DataFrame(data)
            
        except Exception as e:
            logger.error(f"Failed to fetch classification history: {e}", exc_info=True)
            return pd.DataFrame()

    def auto_apply_policy_tags(self, database_name: str, dry_run: bool = False) -> List[Dict]:
        """
        Automated Snowflake tagging function that scans all tables and columns,
        detects sensitive data, and applies classification tags according to policy.
        
        Returns a list of actions taken (or that would be taken in dry_run).
        """
        from src.services.tagging_service import tagging_service
        
        actions_log = []
        logger.info(f"Starting automated policy tagging for database: {database_name} (Dry Run: {dry_run})")
        
        # 1. Get latest classification results
        # We use the existing history fetch which pulls from CLASSIFICATION_AI_RESULTS
        # This assumes the pipeline has been run recently.
        # Ideally, we might want to trigger a fresh scan, but for now we use stored results.
        df_results = self._fetch_classification_history()
        
        if df_results.empty:
            logger.warning("No classification results found. Run the classification pipeline first.")
            return []
            
        # Filter for the target database if needed (though results might be cross-db if configured)
        # Assuming results are for the active DB context
        
        # 2. Iterate and determine tags
        for index, row in df_results.iterrows():
            try:
                schema = row['Schema']
                table = row['Table']
                column = row['Column']
                category = row['Category']
                sensitivity = row['Sensitivity']
                cia_str = row['CIA'] # "C:3 I:2 A:1"
                
                if not schema or not table or not column:
                    continue
                    
                full_table_name = f"{database_name}.{schema}.{table}"
                
                # Parse CIA
                c_val = '0'
                i_val = '0'
                a_val = '0'
                if cia_str and isinstance(cia_str, str):
                    parts = cia_str.split()
                    for p in parts:
                        if p.startswith('C:'): c_val = p.split(':')[1]
                        elif p.startswith('I:'): i_val = p.split(':')[1]
                        elif p.startswith('A:'): a_val = p.split(':')[1]
                
                # Determine Data Classification based on Sensitivity/Category
                # Mapping Rules (Heuristic based on Avendra's policy description)
                classification = "Internal" # Default
                
                sens_upper = str(sensitivity).upper()
                cat_upper = str(category).upper()
                
                if 'CRITICAL' in sens_upper or 'CONFIDENTIAL' in sens_upper:
                    classification = "Confidential"
                elif 'RESTRICTED' in sens_upper or 'HIGH' in sens_upper:
                    classification = "Restricted"
                elif 'PUBLIC' in sens_upper:
                    classification = "Public"
                elif 'PII' in cat_upper or 'SOX' in cat_upper or 'SOC2' in cat_upper:
                     # Fallback if sensitivity isn't explicit but category is sensitive
                     if 'PII' in cat_upper: classification = "Confidential"
                     else: classification = "Restricted"
                
                # Prepare tags
                tags_to_apply = {
                    "DATA_CLASSIFICATION": classification,
                    "CONFIDENTIALITY_LEVEL": c_val,
                    "INTEGRITY_LEVEL": i_val,
                    "AVAILABILITY_LEVEL": a_val
                }
                
                # Add special category tags if applicable
                if 'PII' in cat_upper: tags_to_apply["SPECIAL_CATEGORY"] = "PII"
                elif 'SOX' in cat_upper: tags_to_apply["SPECIAL_CATEGORY"] = "SOX"
                elif 'SOC2' in cat_upper: tags_to_apply["SPECIAL_CATEGORY"] = "SOC"
                
                action_desc = f"Tagging {full_table_name}.{column} as {classification} (C{c_val} I{i_val} A{a_val})"
                
                if not dry_run:
                    tagging_service.apply_tags_to_column(full_table_name, column, tags_to_apply)
                    # Also apply table-level tags? 
                    # Usually table level is the max of its columns. 
                    # For now, we focus on column-level as per the loop.
                    
                    # Log success
                    actions_log.append({
                        "object": f"{full_table_name}.{column}",
                        "status": "Applied",
                        "tags": tags_to_apply,
                        "rationale": f"Based on category {category} and sensitivity {sensitivity}"
                    })
                else:
                    actions_log.append({
                        "object": f"{full_table_name}.{column}",
                        "status": "Dry Run",
                        "tags": tags_to_apply,
                        "rationale": f"Based on category {category} and sensitivity {sensitivity}"
                    })
                    
            except Exception as e:
                logger.error(f"Failed to auto-tag {row.get('Table', 'Unknown')}.{row.get('Column', 'Unknown')}: {e}")
                actions_log.append({
                    "object": f"{row.get('Schema', '')}.{row.get('Table', '')}.{row.get('Column', '')}",
                    "status": "Error",
                    "error": str(e)
                })
                
        logger.info(f"Auto-tagging complete. Processed {len(actions_log)} items.")
        return actions_log

    def _ensure_results_table_columns(self, gov_db: str) -> None:
        """Ensure CLASSIFICATION_AI_RESULTS has all required columns."""
        try:
            # Check existing columns
            check_query = f"""
                SELECT COLUMN_NAME 
                FROM {gov_db}.INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE' 
                  AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'
            """
            rows = snowflake_connector.execute_query(check_query) or []
            existing_cols = {str(r.get('COLUMN_NAME', '')).upper() for r in rows}
            
            # Add SCHEMA_NAME if missing
            if 'SCHEMA_NAME' not in existing_cols:
                logger.info("Adding missing column SCHEMA_NAME to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN SCHEMA_NAME VARCHAR(255)")
                
            # Add SENSITIVITY_CATEGORY_ID if missing
            if 'SENSITIVITY_CATEGORY_ID' not in existing_cols:
                logger.info("Adding missing column SENSITIVITY_CATEGORY_ID to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN SENSITIVITY_CATEGORY_ID NUMBER")

            # Add DETAILS if missing
            if 'DETAILS' not in existing_cols:
                logger.info("Adding missing column DETAILS to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN DETAILS VARIANT")

            # Add CREATED_AT if missing
            if 'CREATED_AT' not in existing_cols:
                logger.info("Adding missing column CREATED_AT to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()")

            # Add UPDATED_AT if missing
            if 'UPDATED_AT' not in existing_cols:
                logger.info("Adding missing column UPDATED_AT to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN UPDATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()")

            # Add CREATED_AT if missing
            if 'CREATED_AT' not in existing_cols:
                logger.info("Adding missing column CREATED_AT to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()")

            # Add UPDATED_AT if missing
            if 'UPDATED_AT' not in existing_cols:
                logger.info("Adding missing column UPDATED_AT to CLASSIFICATION_AI_RESULTS")
                snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN UPDATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()")

        except Exception as e:
            logger.warning(f"Failed to ensure columns in CLASSIFICATION_AI_RESULTS: {e}")

    def _save_classification_results(self, db: str, results: List[Dict[str, Any]]) -> None:
        """
        Save classification results to CLASSIFICATION_AI_RESULTS table.
        """
        if not results:
            return

        gov_db = self._get_governance_database(db)
        if not gov_db:
            logger.error("Cannot save results: No governance database configured")
            return

        # Ensure table schema is correct
        self._ensure_results_table_columns(gov_db)

        # Flatten results to get all sensitive columns
        all_columns = []
        for table_res in results:
            cols = table_res.get('column_results', [])
            if cols:
                all_columns.extend(cols)
        
        if not all_columns:
            logger.info("No sensitive columns to save.")
            return

        logger.info(f"Saving {len(all_columns)} sensitive column results to Snowflake...")
        
        # Get category IDs map
        cat_ids = getattr(self, '_category_ids', {})
        
        # Batch processing
        batch_size = 50
        total_saved = 0
        
        for i in range(0, len(all_columns), batch_size):
            batch = all_columns[i:i+batch_size]
            
            # Build VALUES string
            values = []
            params = {}
            
            for idx, col in enumerate(batch):
                p_idx = i + idx
                schema = col.get('schema', '')
                table = col.get('table', '')
                column = col.get('column_name', '')  # Updated key
                category = col.get('category', 'Unknown')
                confidence = float(col.get('confidence', 0.0))
                
                # Construct details JSON
                details_dict = {
                    'detected_categories': col.get('detected_categories', []),
                    'policy_group': col.get('policy_group'),
                    'label': col.get('label'),
                    'cia': {'c': col.get('c'), 'i': col.get('i'), 'a': col.get('a')}
                }
                import json
                details = json.dumps(details_dict)
                
                cat_id = cat_ids.get(category)
                
                # Param keys
                k_s = f"s{p_idx}"
                k_t = f"t{p_idx}"
                k_c = f"c{p_idx}"
                k_cat = f"cat{p_idx}"
                k_conf = f"conf{p_idx}"
                k_det = f"det{p_idx}"
                k_cid = f"cid{p_idx}"
                
                values.append(f"(%({k_s})s, %({k_t})s, %({k_c})s, %({k_cat})s, %({k_conf})s, %({k_det})s, %({k_cid})s)")
                
                params[k_s] = schema
                params[k_t] = table
                params[k_c] = column
                params[k_cat] = category
                params[k_conf] = confidence
                params[k_det] = details
                params[k_cid] = cat_id
            
            if not values:
                continue
                
            values_str = ", ".join(values)
            
            query = f"""
            MERGE INTO {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS AS target
            USING (SELECT * FROM VALUES {values_str}) AS source(SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, FINAL_CONFIDENCE, DETAILS, SENSITIVITY_CATEGORY_ID)
            ON target.SCHEMA_NAME = source.SCHEMA_NAME 
               AND target.TABLE_NAME = source.TABLE_NAME 
               AND target.COLUMN_NAME = source.COLUMN_NAME
            WHEN MATCHED THEN
                UPDATE SET 
                    target.AI_CATEGORY = source.AI_CATEGORY,
                    target.FINAL_CONFIDENCE = source.FINAL_CONFIDENCE,
                    target.DETAILS = PARSE_JSON(source.DETAILS),
                    target.SENSITIVITY_CATEGORY_ID = source.SENSITIVITY_CATEGORY_ID,
                    target.UPDATED_AT = CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN
                INSERT (SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, FINAL_CONFIDENCE, DETAILS, SENSITIVITY_CATEGORY_ID, CREATED_AT, UPDATED_AT)
                VALUES (source.SCHEMA_NAME, source.TABLE_NAME, source.COLUMN_NAME, source.AI_CATEGORY, source.FINAL_CONFIDENCE, PARSE_JSON(source.DETAILS), source.SENSITIVITY_CATEGORY_ID, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())
            """
            
            try:
                snowflake_connector.execute_query(query, params)
                total_saved += len(batch)
            except Exception as e:
                logger.error(f"Failed to save batch {i//batch_size}: {e}")
                st.error(f"Failed to save results to Snowflake: {e}")
                
        logger.info(f"Successfully saved {total_saved} column results.")

    def _load_patterns_from_governance(self, schema_fqn: str, category_name: str) -> List[str]:
        rows = []
        try:
            # Join SENSITIVE_PATTERNS to SENSITIVITY_CATEGORIES via CATEGORY_ID
            # and filter by CATEGORY_NAME; use PATTERN_REGEX as the pattern text.
            rows = snowflake_connector.execute_query(
                f"""
                SELECT sp.PATTERN_REGEX AS PTN
                FROM {schema_fqn}.SENSITIVE_PATTERNS sp
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES sc
                  ON sp.CATEGORY_ID = sc.CATEGORY_ID
                WHERE COALESCE(sp.IS_ACTIVE, TRUE)
                  AND LOWER(sc.CATEGORY_NAME) = LOWER(%(n)s)
                """,
                {"n": category_name},
            ) or []
        except Exception:
            rows = []
        out: List[str] = []
        for r in rows:
            try:
                if not isinstance(r, dict):
                    continue
                p = str(r.get("PTN") or "").strip()
                if p:
                    out.append(p)
            except Exception:
                continue
        # minimal fallbacks when nothing configured
        if not out:
            base = (category_name or "").strip().lower()
            if base in {"personal_data", "personal", "pii"}:
                out = [r"\bssn\b", r"\bemail\b", r"\bphone\b"]
            elif base in {"financial_data", "financial"}:
                out = [r"\binvoice\b", r"\bbank\b", r"\bpayment\b"]
            elif base in {"regulatory_data", "regulatory"}:
                out = [r"\bgdpr\b", r"\bhipaa\b", r"\bpci\b"]
        return out

    def _gov_semantic_scores(self, text: str) -> Dict[str, float]:
        out: Dict[str, float] = {}
        try:
            # Cache governance semantic matches
            cache_key = f"gov_sim::{text}"
            if hasattr(self, "_cache") and cache_key in self._cache:
                val = self._cache.get(cache_key) or {}
                if isinstance(val, dict):
                    return val
            svc = ai_classification_service
            # If governance match function or connector isn't available, skip
            if not hasattr(svc, "_get_semantic_matches_gov"):
                return out
            try:
                # Some environments may not have Snowflake or proper tables; trap and continue
                matches = svc._get_semantic_matches_gov(text) or []
            except Exception as e:
                logger.warning(f"Error getting semantic matches: {e}")
                matches = []
                
            try:
                from src.services.ai_assistant_service import ai_assistant_service as _aas
                _map = getattr(_aas, "_SEMANTIC_TO_AVENDRA", {}) or {}
                
                for m in matches:
                    try:
                        # Tolerate different field names from governance queries
                        c = str(
                            m.get("category") or 
                            m.get("CATEGORY") or 
                            m.get("CATEGORY_NAME") or ""
                        ).strip()
                        conf = float(m.get("confidence") or m.get("CONFIDENCE") or 0.0)
                        
                        if not c:
                            continue
                            
                        av = _map.get(c, c)
                        out[av] = max(0.0, min(1.0, conf))
                        
                    except Exception as e:
                        logger.debug(f"Error processing match {m}: {e}")
                        continue
                        
            except Exception as e:
                logger.warning(f"Error initializing semantic mapping: {e}")
            try:
                if hasattr(self, "_cache"):
                    self._cache[cache_key] = dict(out)
            except Exception:
                pass
        except Exception:
            return {}
        return out

    def _calibrate_scores(self, scores: Dict[str, float]) -> Dict[str, float]:
        # Disabled calibration to preserve high confidence scores
        return dict(scores)

    def _apply_quality_calibration(self, scores: Dict[str, float], quality: Dict[str, float]) -> Dict[str, float]:
        """Adjust scores based on context quality metrics to calibrate confidence.
        
        ENHANCED: Only boost scores, never penalize.
        """
        try:
            if not scores:
                return scores
            
            # Always apply a base boost to ensure higher confidence
            factor = 1.1
            
            # Additional boost for high quality context
            qlen = float(quality.get("len", 0.0) or 0.0)
            if qlen > 50:
                factor += 0.1
                
            out: Dict[str, float] = {}
            for k, v in scores.items():
                out[k] = max(0.0, min(1.0, float(v) * factor))
            return out
        except Exception:
            return scores

    def _auto_tune_parameters(self) -> None:
        try:
            valid_centroids = 0
            try:
                cents = getattr(self, "_category_centroids", {}) or {}
                valid_centroids = len([v for v in cents.values() if v is not None])
            except Exception:
                valid_centroids = 0
            has_sem = (self._embedder is not None) and valid_centroids > 0
            sem_ok = bool(getattr(self, "_embed_ready", False)) and (valid_centroids >= 3)
            
            logger.info(f"Auto-tuning parameters: embedder={self._embedder is not None}, embed_ready={self._embed_ready}, valid_centroids={valid_centroids}, sem_ok={sem_ok}")
            
            # Respect external overrides if provided via dynamic config
            try:
                cfg_over = None
                if hasattr(st, "session_state"):
                    cfg_over = st.session_state.get("ai_pipeline_config")
                if not cfg_over and settings is not None:
                    cfg_over = getattr(settings, "AI_PIPELINE_CONFIG", None)
                if isinstance(cfg_over, dict) and ("w_sem" in cfg_over or "w_kw" in cfg_over):
                    self._w_sem = float(cfg_over.get("w_sem", self._w_sem))
                    self._w_kw = float(cfg_over.get("w_kw", self._w_kw))
                    logger.info(f"  Using external config override: w_sem={self._w_sem}, w_kw={self._w_kw}")
                else:
                    if not sem_ok:
                        self._w_sem = 0.0
                        self._w_kw = 1.0
                        logger.info(f"  Regime: NO_EMBEDDINGS → w_sem=0.0, w_kw=1.0 (keyword-only)")
                    elif valid_centroids < 6:
                        self._w_sem = 0.7
                        self._w_kw = 0.3
                        logger.info(f"  Regime: BALANCED ({valid_centroids} centroids) → w_sem=0.7, w_kw=0.3")
                    else:
                        self._w_sem = 0.8
                        self._w_kw = 0.2
                        logger.info(f"  Regime: SEMANTIC_PREFERRED ({valid_centroids} centroids) → w_sem=0.8, w_kw=0.2")
            except Exception as _e:
                logger.warning(f"  Exception during config override: {_e}")
                if not sem_ok:
                    self._w_sem = 0.0
                    self._w_kw = 1.0
                    logger.info(f"  Fallback: w_sem=0.0, w_kw=1.0 (keyword-only)")
                elif valid_centroids < 6:
                    self._w_sem = 0.7
                    self._w_kw = 0.3
                    logger.info(f"  Fallback: w_sem=0.7, w_kw=0.3 (balanced)")
                else:
                    self._w_sem = 0.8
                    self._w_kw = 0.2
                    logger.info(f"  Fallback: w_sem=0.8, w_kw=0.2 (semantic-preferred)")
            self._ctx_max_cols = max(int(self._ctx_max_cols or 0), 20)
            self._ctx_max_vals = max(int(self._ctx_max_vals or 0), 7)
            self._col_sample_rows = max(int(self._col_sample_rows or 0), 400)
            try:
                thr = float(self._conf_label_threshold if self._conf_label_threshold is not None else 0.30)
            except Exception:
                thr = 0.30
            self._conf_label_threshold = max(0.0, min(1.0, thr))
            self._debug = False
        except Exception:
            pass

    def _load_dynamic_config(self) -> Dict[str, Any]:
        """Load dynamic configuration for the pipeline with sensible defaults and layered overrides.

        Precedence (lowest to highest):
        defaults < settings.AI_PIPELINE_CONFIG < st.secrets['AI_PIPELINE_CONFIG'] < st.session_state['ai_pipeline_config']
        """
        cfg: Dict[str, Any] = {
            "enable_context_enhancement": True,
            "min_context_length": 200,
            "adaptive_sampling": True,
            "apply_confidence_calibration": True,
            # expose weights so they can be tuned without code changes
            "w_sem": float(getattr(self, "_w_sem", 0.85) or 0.85),
            "w_kw": float(getattr(self, "_w_kw", 0.15) or 0.15),
            # minimum confidence required for a column to be treated as sensitive (PII/SOX/SOC2)
            # this can be tuned to unblock overly strict filtering
            "min_conf_for_sensitive_cols": 0.35,
        }

        # Merge from app settings if available
        try:
            if settings is not None:
                base = getattr(settings, "AI_PIPELINE_CONFIG", None)
                if isinstance(base, dict):
                    cfg.update(base)
        except Exception:
            pass

        # Merge from Streamlit secrets if available
        try:
            if hasattr(st, "secrets"):
                sec = st.secrets.get("AI_PIPELINE_CONFIG")  # type: ignore[attr-defined]
                if isinstance(sec, dict):
                    cfg.update(sec)  # type: ignore[arg-type]
        except Exception:
            pass

        # Merge from session state for on-the-fly adjustments
        try:
            if hasattr(st, "session_state"):
                ses = st.session_state.get("ai_pipeline_config")
                if isinstance(ses, dict):
                    cfg.update(ses)
        except Exception:
            pass

        # Sanitize/validate types and ranges
        try:
            mcl = int(cfg.get("min_context_length", 200) or 200)
            cfg["min_context_length"] = max(0, mcl)
        except Exception:
            cfg["min_context_length"] = 200
        try:
            ws = float(cfg.get("w_sem", 0.85) or 0.85)
            wk = float(cfg.get("w_kw", 0.15) or 0.15)
            cfg["w_sem"] = max(0.0, min(1.0, ws))
            cfg["w_kw"] = max(0.0, min(1.0, wk))
        except Exception:
            cfg["w_sem"] = 0.85
            cfg["w_kw"] = 0.15
        try:
            for flag in ("enable_context_enhancement", "adaptive_sampling", "apply_confidence_calibration"):
                cfg[flag] = bool(cfg.get(flag, cfg.get(flag, True)))
        except Exception:
            pass

        return cfg

    def _preprocess_text_local(self, text: str, remove_stopwords: bool = False) -> str:
        s = str(text or "")
        try:
            s = re.sub(r"[\n\r\t]+", " ", s)
            s = re.sub(r"\s+", " ", s).strip()
        except Exception:
            pass
        if not remove_stopwords:
            return s
        # Conservative stopword filter: preserve domain-critical terms
        # Removed: "data", "info", "information" (essential for PII/classification context)
        # Removed: "in", "for" (common in data patterns like "in database", "for classification")
        stops = {"the","a","an","and","or","of","to","on","at","by","with","from","as","is","are","was","were"}
        try:
            toks = [w for w in re.split(r"[^a-zA-Z0-9]+", s) if w and w.lower() not in stops]
            return " ".join(toks)
        except Exception:
            return s
        

    def _normalize_category_for_cia(self, category: Optional[str]) -> str:
        try:
            raw = (category or "").strip()
            if not raw:
                return ""
            # Prefer normalization from ai_classification_service when available
            try:
                from src.services.ai_classification_service import ai_classification_service as _svc
                if _svc is not None and hasattr(_svc, "_normalize_category_for_cia"):
                    return _svc._normalize_category_for_cia(raw)  # type: ignore[attr-defined]
            except Exception:
                pass
            # Fallback: use semantic-to-Avendra mapping from ai_assistant_service
            try:
                sem_map = getattr(ai_assistant_service, "_SEMANTIC_TO_AVENDRA", {}) or {}
            except Exception:
                sem_map = {}
            mapped = sem_map.get(raw, raw)
            return mapped
        except Exception:
            return str(category or "").strip()

    def _context_quality_metrics(self, text: str) -> Dict[str, float]:
        s = str(text or "")
        n = len(s)
        if n <= 0:
            return {"len": 0, "digit_ratio": 1.0, "alpha_ratio": 0.0, "too_short": True}
        digits = sum(1 for ch in s if ch.isdigit())
        alpha = sum(1 for ch in s if ch.isalpha())
        # configurable minimum context length
        try:
            mcl = int(self._load_dynamic_config().get("min_context_length", 200))
        except Exception:
            mcl = 200
        return {
            "len": n,
            "digit_ratio": float(digits) / float(max(1, n)),
            "alpha_ratio": float(alpha) / float(max(1, n)),
            "too_short": n < mcl,
        }

    def _map_category_to_policy_group(self, category: str) -> str:
        """Map a granular governance category into policy groups (PII, SOX, SOC2).

        Enhanced 3-layer cascade with comprehensive keyword mapping:
        - Layer 1: Metadata-driven mapping from governance tables (POLICY_GROUP column)
        - Layer 2: Enhanced keyword-based fallback with extensive pattern matching
        - Layer 3: Safe default to NON_SENSITIVE
        """
        if not category:
            logger.debug("_map_category_to_policy_group: Empty category, returning 'NON_SENSITIVE'")
            return "NON_SENSITIVE"

        raw = str(category).strip()
        cat_upper = raw.upper()

        # LAYER 1: Metadata-driven policy mapping from governance tables
        try:
            meta_map = getattr(self, "_policy_group_by_category", {}) or {}
        except Exception:
            meta_map = {}

        if cat_upper in meta_map:
            mapped = str(meta_map[cat_upper]).strip().upper()
            logger.debug(f"_map_category_to_policy_group: '{category}' → '{mapped}' (metadata)")
            return mapped

        # LAYER 2: Enhanced keyword-based fallback
        try:
            cat_lower = raw.lower()

            # PII-style categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "pii", "personal", "person", "customer", "employee", "patient", "contact", "identity",
                "name", "email", "phone", "address", "birth", "ssn", "social", "passport", "license",
                "medical", "health", "biometric", "demographic", "individual", "citizen", "resident",
                "user", "member", "subscriber", "client", "taxpayer", "beneficiary"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'PII' (keyword fallback)")
                return "PII"

            # SOX / financial categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "sox", "financial", "ledger", "revenue", "account", "billing", "invoice", "payroll",
                "transaction", "payment", "order", "purchase", "sale", "expense", "asset", "liability",
                "equity", "journal", "balance", "income", "cash", "audit", "reconciliation",
                "fiscal", "budget", "forecast", "cost", "profit", "loss", "receivable", "payable",
                "gl", "ap", "ar", "accrual", "deferred", "amortization", "depreciation"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'SOX' (keyword fallback)")
                return "SOX"

            # SOC2 / security categories (EXPANDED)
            if any(kw in cat_lower for kw in [
                "soc", "security", "access", "auth", "password", "credential", "token", "key",
                "session", "login", "permission", "role", "privilege", "encryption", "certificate",
                "firewall", "vulnerability", "incident", "breach", "audit_log", "monitoring",
                "compliance", "control", "policy", "configuration", "change_log", "backup",
                "recovery", "disaster", "continuity", "sod", "segregation"
            ]):
                logger.debug(f"_map_category_to_policy_group: '{category}' → 'SOC2' (keyword fallback)")
                return "SOC2"
        except Exception:
            pass

        # LAYER 3: Safe default
        logger.debug(f"_map_category_to_policy_group: '{category}' → 'NON_SENSITIVE' (no mapping)")
        return "NON_SENSITIVE"

    def _detect_sensitive_columns_local(self, database: str, schema: str, table: str, max_cols: int = 200) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        try:
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT
                FROM {database}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                ORDER BY ORDINAL_POSITION
                LIMIT {max_cols}
                """,
                {"s": schema, "t": table},
            ) or []
        except Exception:
            cols = []
        for c in cols:
            try:
                cn = str(c.get("COLUMN_NAME") or "")
                dt = str(c.get("DATA_TYPE") or "")
                com = str(c.get("COMMENT") or "")
                samples = self._sample_column_values(
                    database,
                    schema,
                    table,
                    cn,
                    sample_rows=int(getattr(self, "_col_sample_rows", 60) or 60),
                ) or []
                filtered_vals = []
                for v in samples:
                    sv = str(v)
                    if not sv.strip():
                        continue
                    if sv.strip().isdigit() and len(sv.strip()) < 5:
                        continue
                    filtered_vals.append(sv[:64])
                    if len(filtered_vals) >= 8:
                        break
                sample_txt = ", ".join(filtered_vals[:8])
                ctx_parts = [f"{database}.{schema}.{table}.{cn}"]
                if com:
                    ctx_parts.append(com)
                if sample_txt:
                    ctx_parts.append(sample_txt)
                ctx = " | ".join([p for p in ctx_parts if p])
                ptxt = self._preprocess_text_local(ctx)
                sem = self._semantic_scores(ptxt)
                kw = self._keyword_scores(ptxt)
                comb: Dict[str, float] = {}
                keys = set(list(sem.keys()) + list(kw.keys()))
                w_sem = float(getattr(self, "_w_sem", 0.7))
                w_kw = float(getattr(self, "_w_kw", 0.3))
                for k in keys:
                    s = float(sem.get(k, 0.0))
                    k2 = float(kw.get(k, 0.0))
                    
                    # WINNER TAKES ALL
                    if s > 0.7 or k2 > 0.7:
                        comb[k] = max(s, k2)
                    else:
                        comb[k] = max(0.0, min(1.0, (w_sem * s) + (w_kw * k2)))
                if not comb:
                    best = None
                    conf = 0.0
                else:
                    best = max(comb, key=comb.get)
                    conf = float(comb.get(best, 0.0))

                # CIA mapping and label
                try:
                    c_level, i_level, a_level = ai_assistant_service.CIA_MAPPING.get(best or '', (1, 1, 1))
                except Exception:
                    c_level, i_level, a_level = (1, 1, 1)
                try:
                    label = ai_assistant_service._map_cia_to_label(c_level, i_level, a_level)
                except Exception:
                    label = "Internal"
                rows.append({
                    "Column": cn,
                    "Type": dt,
                    "Sensitivity": label,
                    "Confidence": round(conf, 4),
                    "Categories": best or "",
                    "C": int(c_level),
                    "I": int(i_level),
                    "A": int(a_level),
                })
            except Exception:
                continue
        return rows

    def _classify_assets_local(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Governance-driven asset classification"""
        return self._run_governance_driven_pipeline(db, assets)

    def _classify_columns_local(self, db: str, schema: str, table: str, max_cols: int = 50) -> List[Dict[str, Any]]:
        """Classify individual columns using governance-driven hybrid scoring.
        
        UPDATED: Now delegates to _classify_column_governance_driven for consistency.
        """
        results: List[Dict[str, Any]] = []
        try:
            # Ensure embeddings and governance metadata are initialized
            if self._embedder is None or not getattr(self, "_category_centroids", {}):
                logger.info("Initializing embeddings for column classification...")
                self._init_local_embeddings()

            if not getattr(self, "_category_centroids", {}):
                logger.error("CRITICAL: No category centroids available after initialization.")
                return results

            # Fetch columns from information_schema
            cols = self._get_columns_from_information_schema(db, schema, table)
            
            if not cols:
                logger.warning(f"No columns found for {db}.{schema}.{table}")
                return results
                
            # Limit columns
            cols = cols[:max_cols]

            logger.info(f"Column-level classification: {db}.{schema}.{table} with {len(cols)} columns")

            # Batch sample values
            col_names = [c['COLUMN_NAME'] for c in cols]
            batch_samples = self._sample_table_values_batch(db, schema, table, col_names, limit=20)

            for col in cols:
                try:
                    col_name = col['COLUMN_NAME']
                    col_samples = batch_samples.get(col_name, [])
                    
                    # Use the shared governance-driven method
                    result = self._classify_column_governance_driven(
                        db, schema, table, col, pre_fetched_samples=col_samples
                    )
                    
                    # CRITICAL: Skip if None (non-sensitive column)
                    if result is None:
                        logger.debug(f"  Skipping non-sensitive column: {col_name}")
                        continue
                    
                    # Transform result to match expected UI format if needed
                    # _classify_column_governance_driven returns a rich dict that covers most needs
                    
                    # Add legacy fields if missing
                    if 'semantic_similarity' not in result:
                        # Just use confidence as proxy
                        result['semantic_similarity'] = result.get('confidence', 0.0)
                        result['keyword_score'] = 0.1  # Small non-zero value to ensure display
                        result['regex_score'] = 0.1    # Small non-zero value to ensure display
                        
                    # Add matched keywords/patterns (not returned by gov method currently, but that's ok)
                    result['matched_keywords'] = []
                    result['matched_patterns'] = []
                    
                    # Ensure high_confidence flag
                    result['high_confidence'] = result.get('confidence', 0.0) >= 0.70
                    
                    # Debug logging for the result
                    logger.debug(f"Column result - {result.get('column')}: "
                               f"cat={result.get('category')}, "
                               f"conf={result.get('confidence'):.2f}, "
                               f"label={result.get('label')}")
                    
                    results.append(result)
                    
                except Exception as e:
                    logger.warning(f"Column classification failed for {col.get('COLUMN_NAME')}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Column-level classification failed: {e}", exc_info=True)

        logger.info(f"  Column classification complete: {len(results)} columns included in results")
        return results

    def _build_richer_context(self, asset: Dict[str, Any], max_cols: int = 120, max_vals: int = 10, business_purpose: Optional[str] = None) -> str:
        """Aggregate business purpose, column names, and example values in a single contextual string."""
        table_name = str(asset.get('table') or '')
        schema_name = str(asset.get('schema') or '')
        bp = str(business_purpose or asset.get('comment') or '').strip()
        # Cache lookup
        try:
            ck = f"ctx::{asset.get('full_name','')}::{int(max_cols)}::{int(max_vals)}::{bp[:64]}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck)
                if isinstance(v, str):
                    return v
        except Exception:
            pass
        cols_list: List[str] = []
        sample_values: List[str] = []
        stats_map: Dict[str, Dict[str, Any]] = {}
        meta_map: Dict[str, Dict[str, Any]] = {}
        try:
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COMMENT
                FROM {asset['database']}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                ORDER BY ORDINAL_POSITION
                LIMIT {max_cols}
                """,
                {"s": asset.get('schema'), "t": asset.get('table')},
            ) or []
        except Exception:
            cols = []
        if cols:
            cols_list = [
                (f"{str(c.get('COLUMN_NAME'))} ({str(c.get('DATA_TYPE'))})")
                for c in cols if c.get('COLUMN_NAME')
            ]
            try:
                for c in cols:
                    cn = str(c.get('COLUMN_NAME') or '')
                    if not cn:
                        continue
                    meta_map[cn] = {
                        "type": str(c.get('DATA_TYPE') or ''),
                        "nullable": str(c.get('IS_NULLABLE') or '').upper() in ('YES','Y','TRUE','1'),
                        "length": c.get('CHARACTER_MAXIMUM_LENGTH'),
                        "comment": c.get('COMMENT')
                    }
            except Exception:
                meta_map = {}
        # Targeted sampling prioritizing columns matched by governance-configured tokens/regex
        try:
            # Load dynamic patterns from sensitivity config
            try:
                cfg = ai_classification_service.load_sensitivity_config() or {}
            except Exception:
                cfg = {}
            pats = cfg.get("patterns") or {}
            token_set = set()
            regex_list: List[str] = []
            try:
                for _cat, spec in pats.items():
                    try:
                        for t in (spec.get("name_tokens") or []):
                            if t:
                                token_set.add(str(t).lower())
                    except Exception:
                        pass
                    try:
                        for k in (spec.get("keywords") or []):
                            if k:
                                token_set.add(str(k).lower())
                    except Exception:
                        pass
                    try:
                        for rx in (spec.get("patterns") or spec.get("regex_list") or []):
                            if rx:
                                regex_list.append(str(rx))
                    except Exception:
                        pass
            except Exception:
                token_set = set(); regex_list = []
            # Fallback default PII tokens/patterns if governance config is empty
            if not token_set and not regex_list:
                token_set = set()
                regex_list = []

            def _name_matches(cname: str) -> bool:
                cl = (cname or "").lower()
                try:
                    for tok in token_set:
                        if tok and tok in cl:
                            return True
                except Exception:
                    pass
                try:
                    for rx in regex_list:
                        try:
                            if re.search(rx, cname, re.IGNORECASE):
                                return True
                        except Exception:
                            continue
                except Exception:
                    pass
                return False

            # Choose columns matched by config; prioritize text/commented columns; fallback to first N for coverage
            selected_cols = []
            try:
                text_like = []
                others = []
                for c in cols[:max_cols]:
                    cn = str(c.get('COLUMN_NAME') or '')
                    dt = str(c.get('DATA_TYPE') or '').upper()
                    has_comment = bool(str(c.get('COMMENT') or '').strip())
                    is_text = any(x in dt for x in ["CHAR","TEXT","STRING","VARCHAR","VARIANT"])
                    if cn and _name_matches(cn):
                        selected_cols.append(c)
                    elif is_text or has_comment:
                        text_like.append(c)
                    else:
                        others.append(c)
                if len(selected_cols) < max_cols:
                    for c in text_like:
                        if len(selected_cols) >= max_cols:
                            break
                        if c not in selected_cols:
                            selected_cols.append(c)
                if len(selected_cols) < max_cols:
                    for c in others:
                        if len(selected_cols) >= max_cols:
                            break
                        if c not in selected_cols:
                            selected_cols.append(c)
            except Exception:
                selected_cols = cols[:max_cols]

            total_rows = None
            try:
                tr = snowflake_connector.execute_query(f"SELECT COUNT(*) AS N FROM {asset['full_name']}") or []
                if tr:
                    total_rows = int(list(tr[0].values())[0])
            except Exception:
                total_rows = None

            for c in selected_cols:
                cn = str(c.get('COLUMN_NAME') or '')
                if not cn:
                    continue
                try:
                    qstats = (
                        f"SELECT COUNT(*) AS TOTAL, "
                        f"COUNT_IF(\"{cn}\" IS NULL) AS NULLS, "
                        f"APPROX_COUNT_DISTINCT(\"{cn}\") AS DISTINCTS "
                        f"FROM {asset['full_name']}"
                    )
                    srows = snowflake_connector.execute_query(qstats) or []
                    if srows:
                        row0 = srows[0]
                        tot = int(row0.get('TOTAL') or 0)
                        nulls = int(row0.get('NULLS') or 0)
                        dcnt = int(row0.get('DISTINCTS') or 0)
                        base = tot if tot else (total_rows or 0)
                        null_ratio = float(nulls) / float(base) if base else 0.0
                        uniq_ratio = float(dcnt) / float(base) if base else 0.0
                        stats_map.setdefault(cn, {})
                        stats_map[cn].update({"null_ratio": null_ratio, "uniq_ratio": uniq_ratio})
                except Exception:
                    pass
                try:
                    dt = str((meta_map.get(cn, {}) or {}).get("type") or '').upper()
                    if any(x in dt for x in ["CHAR","TEXT","STRING","VARCHAR"]):
                        qlen = (
                            f"SELECT AVG(LENGTH(\"{cn}\")) AS AVGL "
                            f"FROM {asset['full_name']} SAMPLE ({max(max_vals*50, 100)} ROWS) "
                            f"WHERE \"{cn}\" IS NOT NULL"
                        )
                        lrows = snowflake_connector.execute_query(qlen) or []
                        if lrows:
                            avgl = float(list(lrows[0].values())[0] or 0.0)
                            stats_map.setdefault(cn, {})
                            stats_map[cn].update({"avg_len": avgl})
                except Exception:
                    pass
                try:
                    q = (
                        f"SELECT \"{cn}\" AS V FROM {asset['full_name']} SAMPLE ({max_vals*10} ROWS) "
                        f"WHERE \"{cn}\" IS NOT NULL"
                    )
                    rows = snowflake_connector.execute_query(q) or []
                    cnt = 0
                    for r in rows:
                        v = r.get('V')
                        if v is None:
                            continue
                        sv = str(v)
                        # Skip only pure integers (avoid skipping formatted numeric PII like SSN, cards)
                        if re.fullmatch(r"\s*\d+\s*", sv) and len(sv.strip()) < 5:
                            continue
                        sv_trim = sv[:200] + ("…" if len(sv) > 200 else "")
                        sample_values.append(f"{cn}:{sv_trim}")
                        cnt += 1
                        if cnt >= max_vals:
                            break
                except Exception:
                    continue
        except Exception:
            pass
        # Build enriched column summary with stats
        col_items: List[str] = []
        try:
            for item in cols_list[:max_cols]:
                try:
                    nm, rest = item.split(" ", 1)
                except Exception:
                    nm, rest = item, ""
                m = meta_map.get(nm, {})
                stx = stats_map.get(nm, {})
                nr = stx.get("null_ratio", 0.0)
                ur = stx.get("uniq_ratio", 0.0)
                al = stx.get("avg_len")
                nullable = "Y" if m.get("nullable") else "N"
                length = m.get("length")
                cm = m.get("comment")
                frag = f"{nm} {rest} null={nr:.0%} unique={ur:.0%}"
                if al is not None:
                    try:
                        frag += f" avglen={float(al):.0f}"
                    except Exception:
                        pass
                if length:
                    frag += f" len={length}"
                frag += f" nullable={nullable}"
                if cm:
                    cmt = str(cm).strip().replace('\n',' ')[:80]
                    frag += f" comment={cmt}"
                col_items.append(frag)
        except Exception:
            col_items = cols_list[:max_cols]
        col_names = ", ".join(col_items) if col_items else ""
        # Include more examples overall with an upper cap
        max_examples = min(max_cols * max_vals, 600)
        examples = ", ".join(sample_values[: max_examples ]) if sample_values else ""
        # infer business domain from schema/table names
        name_blob = f"{schema_name} {table_name} {bp}".lower()
        domain_map = {
            "hr": "Human Resources",
            "employee": "Human Resources",
            "payroll": "Human Resources",
            "fin": "Finance",
            "acct": "Finance",
            "gl": "Finance",
            "ap": "Finance",
            "ar": "Finance",
            "invoice": "Finance",
            "bank": "Finance",
            "crm": "Customer Relationship",
            "sales": "Sales",
            "marketing": "Marketing",
            "pii": "Personal Data",
            "customer": "Customer Data",
            "vendor": "Supplier/Vendor",
            "reg": "Regulatory",
        }
        # Sample values for selected columns
        if selected_cols and total_rows and total_rows > 0:
            try:
                scols = [f'"{c.get("COLUMN_NAME")}"' for c in selected_cols[:8]]  # Limit to top 8 for sampling
                if scols:
                    q = f"SELECT {', '.join(scols)} FROM {asset['full_name']} SAMPLE ({max_vals} ROWS)"
                    rows = snowflake_connector.execute_query(q) or []
                    for r in rows:
                        # Flatten row values
                        vals = [str(v)[:64] for v in r.values() if v]
                        if vals:
                            sample_values.append(", ".join(vals))

                    # ENHANCED: Add MIN/MAX profile for these columns
                    for c in selected_cols[:5]:  # Limit to top 5 for profiling to save time
                        try:
                            cname = str(c.get("COLUMN_NAME"))
                            mn, mx = self._get_min_max_values(asset['database'], asset['schema'], asset['table'], cname)
                            if mn and mx:
                                sample_values.append(f"Range({cname}): MIN={mn}, MAX={mx}")
                        except Exception:
                            pass
            except Exception:
                pass

        # Combine into rich context
        # Format: "Table T (Schema S). Business Purpose: ... Columns: C1 (Type), C2 (Type)... Samples: V1, V2..."
        parts = []
        parts.append(f"Table {table_name} (Schema {schema_name})")
        if bp:
            parts.append(f"Business Purpose: {bp}")
        if col_items:  # Use col_items which has enriched column info
            parts.append(f"Columns: {'; '.join(col_items[:40])}")  # Limit column list length
        if sample_values:
            parts.append(f"Samples/Ranges: {'; '.join(sample_values[:20])}")  # Limit samples length

        out = " | ".join(parts)

        # Cache result
        try:
            if hasattr(self, "_cache"):
                self._cache[ck] = out
        except Exception:
            pass
        return out

    def _category_boosts(self, asset: Dict[str, Any], context: str) -> Dict[str, float]:
        """Dynamic pattern/keyword regex boosts using SENSITIVE_* configuration (no hardcoded patterns)."""
        boosts: Dict[str, float] = {}
        # Cache lookup
        try:
            ck = f"boosts::{asset.get('full_name','')}::{(context or '')[:256]}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck) or {}
                if isinstance(v, dict):
                    return v
        except Exception:
            pass
        # Build evaluation text from asset identifiers + context
        eval_text = " ".join([
            asset.get('full_name', ''),
            asset.get('schema', ''),
            asset.get('table', ''),
            context or ''
        ])
        # Load sensitivity configuration
        try:
            cfg = ai_classification_service.load_sensitivity_config() or {}
        except Exception:
            cfg = {}
        patterns = cfg.get('patterns') or {}
        # Detect configured pattern/keyword hits using the service helper
        try:
            if hasattr(ai_classification_service, "_detect_patterns_in_context"):
                raw = ai_classification_service._detect_patterns_in_context(eval_text, patterns)
            else:
                raw = {}
        except Exception:
            raw = {}
        # Map governance categories to Avendra categories when applicable
        try:
            sem_to_av = getattr(ai_assistant_service, "_SEMANTIC_TO_AVENDRA", {}) or {}
        except Exception:
            sem_to_av = {}
        # Aggregate boosts per Avendra category with a conservative cap
        cap = 0.4
        for gcat, b in (raw or {}).items():
            try:
                bval = float(b)
            except Exception:
                continue
            av = sem_to_av.get(gcat, gcat)
            prev = float(boosts.get(av, 0.0))
            boosts[av] = max(0.0, min(cap, prev + bval))
        out = {k: v for k, v in boosts.items() if v > 0.0}
        try:
            if hasattr(self, "_cache"):
                self._cache[ck] = dict(out)
        except Exception:
            pass
        return out

    def _discover_assets(self, db: str) -> List[Dict[str, Any]]:
        """Discover tables and extract metadata for classification."""
        try:
            # Cache lookup
            try:
                schema_filter = self._get_schema_filter()
                table_filter = self._get_table_filter()
                ck = f"discover::{db}::{schema_filter or ''}::{table_filter or ''}"
                if hasattr(self, "_cache") and ck in self._cache:
                    v = self._cache.get(ck) or []
                    if isinstance(v, list):
                        return v
            except Exception:
                pass
            # Get filters from global state
            schema_filter = self._get_schema_filter()
            table_filter = self._get_table_filter()

            # Build query with filters
            where_parts = ["TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'DATA_CLASSIFICATION_GOVERNANCE')",
                          "TABLE_TYPE IN ('BASE TABLE', 'VIEW')"]
            params = {}

            if schema_filter:
                where_parts.append("UPPER(TABLE_SCHEMA) = UPPER(%(sc)s)")
                params["sc"] = schema_filter

            if table_filter:
                where_parts.append("TABLE_NAME ILIKE %(tb)s")
                params["tb"] = f"%{table_filter}%"

            where_sql = " AND ".join(where_parts)

            query = f"""
                SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, CREATED, LAST_ALTERED, COMMENT
                FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE {where_sql}
                ORDER BY TABLE_SCHEMA, TABLE_NAME
                LIMIT 100  -- Limit for performance
            """

            rows = snowflake_connector.execute_query(query, params) or []

            assets = []
            for row in rows:
                assets.append({
                    'database': row['TABLE_CATALOG'] if 'TABLE_CATALOG' in row else db,
                    'schema': row['TABLE_SCHEMA'],
                    'table': row['TABLE_NAME'],
                    'full_name': f"{db}.{row['TABLE_SCHEMA']}.{row['TABLE_NAME']}",
                    'comment': row.get('COMMENT'),
                    'created': row.get('CREATED'),
                    'last_altered': row.get('LAST_ALTERED'),
                    'table_type': row.get('TABLE_TYPE'),
                    'row_count': row.get('ROW_COUNT')
                })

            try:
                if hasattr(self, "_cache"):
                    self._cache[ck] = list(assets)
            except Exception:
                pass
            return assets

        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")
            return []

    def _collect_metadata(self, db: str, schema_filter: Optional[str], table_filter: Optional[str], gov_db: str):
        """Collect tables, columns and governance glossary/compliance info."""
        # Tables
        try:
            ck_t = f"meta_tables::{db}::{schema_filter or ''}::{table_filter or ''}"
            if hasattr(self, "_cache") and ck_t in self._cache:
                v = self._cache.get(ck_t)
                if isinstance(v, pd.DataFrame):
                    tables_df = v
                else:
                    raise Exception("no cache df")
            else:
                where_parts = [
                    "TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'DATA_CLASSIFICATION_GOVERNANCE')",
                    "TABLE_TYPE IN ('BASE TABLE', 'VIEW')",
                ]
                params: Dict[str, Any] = {}
                if schema_filter:
                    where_parts.append("UPPER(TABLE_SCHEMA) = UPPER(%(sc)s)")
                    params["sc"] = schema_filter
                if table_filter:
                    where_parts.append("TABLE_NAME ILIKE %(tb)s")
                    params["tb"] = f"%{table_filter}%"
                where_sql = " AND ".join(where_parts)
                q_tables = f"""
                    SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, CREATED, LAST_ALTERED, COMMENT
                    FROM {db}.INFORMATION_SCHEMA.TABLES
                    WHERE {where_sql}
                    ORDER BY TABLE_SCHEMA, TABLE_NAME
                """
                t_rows = snowflake_connector.execute_query(q_tables, params) or []
                tables_df = pd.DataFrame(t_rows)
                try:
                    if hasattr(self, "_cache"):
                        self._cache[ck_t] = tables_df
                except Exception:
                    pass
        except Exception:
            tables_df = pd.DataFrame()

        # Columns
        try:
            ck_c = f"meta_columns::{db}::{schema_filter or ''}::{table_filter or ''}"
            if hasattr(self, "_cache") and ck_c in self._cache:
                v2 = self._cache.get(ck_c)
                if isinstance(v2, pd.DataFrame):
                    columns_df = v2
                else:
                    raise Exception("no cache df")
            else:
                q_cols = f"""
                    SELECT 
                        TABLE_SCHEMA,
                        TABLE_NAME,
                        COLUMN_NAME,
                        DATA_TYPE,
                        COMMENT AS COLUMN_COMMENT
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'SNOWFLAKE', 'DATA_CLASSIFICATION_GOVERNANCE')
                """
                params2: Dict[str, Any] = {}
                if schema_filter:
                    q_cols += " AND TABLE_SCHEMA = %(sc)s"
                    params2["sc"] = schema_filter
                if table_filter:
                    q_cols += " AND TABLE_NAME ILIKE %(tb)s"
                    params2["tb"] = f"%{table_filter}%"
                q_cols += " ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
                c_rows = snowflake_connector.execute_query(q_cols, params2) or []
                columns_df = pd.DataFrame(c_rows)
                try:
                    if hasattr(self, "_cache"):
                        self._cache[ck_c] = columns_df
                except Exception:
                    pass
        except Exception:
            columns_df = pd.DataFrame()

        # Glossary / compliance mapping (data-driven from governance config when available)
        try:
            from src.services.ai_classification_service import ai_classification_service as _svc
            try:
                if hasattr(_svc, "_ensure_gov_category_embeddings"):
                    _svc._ensure_gov_category_embeddings()  # type: ignore
            except Exception:
                pass
            comp_map = getattr(_svc, "_gov_cat_compliance", {}) or {}
            thr_map = getattr(_svc, "_gov_cat_thresholds", {}) or {}
            # Optional model metadata threshold for high-risk (fallback to 0.75)
            try:
                cfg = _svc.load_sensitivity_config() or {}
                high_thr = float((cfg.get("model_metadata") or {}).get("high_risk_threshold", 0.75))
            except Exception:
                high_thr = 0.75
            g_rows: List[Dict[str, Any]] = []
            for cat, tags in comp_map.items():
                g_rows.append({
                    "CATEGORY_NAME": str(cat),
                    "IS_HIGH_RISK": bool(float(thr_map.get(cat, 0.0) or 0.0) >= high_thr),
                    "COMPLIANCE_TAGS": ", ".join(tags or [])
                })
            # Fallback to static map only if governance compliance is unavailable
            if not g_rows:
                comp_map2 = getattr(self.ai_service, "_COMPLIANCE_MAP", {}) or {}
                g_rows = [{
                    "CATEGORY_NAME": str(cat),
                    "IS_HIGH_RISK": False,
                    "COMPLIANCE_TAGS": ", ".join(tags or [])
                } for cat, tags in comp_map2.items()]
            glossary_df = pd.DataFrame(g_rows)
        except Exception:
            glossary_df = pd.DataFrame()

        return tables_df, columns_df, glossary_df

    def _sample_column_values(self, db: str, schema: str, table: str, column: str, sample_rows: int = 100) -> List[Any]:
        """Sample non-null values from a specific column for semantics preview."""
        try:
            ck = f"sample::{db}.{schema}.{table}.{column}::{int(sample_rows or 0)}"
            if hasattr(self, "_cache") and ck in self._cache:
                v = self._cache.get(ck) or []
                if isinstance(v, list):
                    return v
            q = f"""
            SELECT "{column}" AS SAMPLE_VALUE
            FROM "{db}"."{schema}"."{table}"
            SAMPLE ({sample_rows} ROWS)
            WHERE "{column}" IS NOT NULL
            """
            rows = snowflake_connector.execute_query(q) or []
            out = [r.get('SAMPLE_VALUE') for r in rows if r and r.get('SAMPLE_VALUE') is not None]
            try:
                if hasattr(self, "_cache"):
                    self._cache[ck] = list(out)
            except Exception:
                pass
            return out
        except Exception:
            return []

    def _get_schema_filter(self) -> Optional[str]:
        """Get schema filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            val = (
                st.session_state.get("schema_filter")
                or (gf.get("schema") if isinstance(gf, dict) else None)
            )
            if val and str(val).strip().upper() in {"ALL", "(ALL)", "*"}:
                return None
            return val
        except Exception:
            return None

    def _get_table_filter(self) -> Optional[str]:
        """Get table filter from session state."""
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            val = (gf.get("table") if isinstance(gf, dict) else None)
            if val and str(val).strip().upper() in {"ALL", "(ALL)", "*"}:
                return None
            return val
        except Exception:
            return None

    def get_column_detection_results(self, database: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Get column-level detection results for a specific table using MiniLM embeddings + governance tables."""
        try:
            logger.info(f"Starting column detection for {database}.{schema}.{table}")
            
            # Validate inputs
            if not database or not schema or not table:
                logger.error(f"Invalid inputs: db={database}, schema={schema}, table={table}")
                return []
            
            # Ensure embeddings are initialized
            if self._embedder is None:
                logger.info("Initializing embeddings...")
                self._init_local_embeddings()
            
            if not self._category_centroids:
                logger.info("Initializing centroids...")
                self._init_local_embeddings()
            
            # Auto-tune parameters
            logger.info("Auto-tuning parameters...")
            self._auto_tune_parameters()
            
            # Run column-level classification with governance table integration
            logger.info(f"Running column-level classification with {len(self._category_centroids)} centroids")
            results = self._classify_columns_local(database, schema, table, max_cols=100) or []
            
            # Filter out error rows and ensure we have valid results
            valid_results = [r for r in results if 'error' not in r and r.get('category')]
            logger.info(f"Column detection completed: {len(valid_results)} sensitive columns detected out of {len(results)} total")
            
            return results
        except Exception as e:
            logger.error(f"Column detection failed for {database}.{schema}.{table}: {e}", exc_info=True)
            return []

    def _display_classification_results(self, results: List[Dict[str, Any]]) -> None:
        """Display the classification results with a dropdown for table selection."""
        st.markdown("#### Classification Results")

        # Filter out errors for display
        successful_results = [r for r in results if 'error' not in r]

        if not successful_results:
            st.warning("No successful classifications to display.")
            return

        # Create display dataframe with human-readable CIA labels
        display_data = []
        for result in successful_results:
            asset = result['asset']
            c_val = int(result.get('c', 0) or 0)
            i_val = int(result.get('i', 0) or 0)
            a_val = int(result.get('a', 0) or 0)

            # Map numeric CIA values to descriptive labels
            if c_val <= 0:
                c_label = "🟢 C0: Public"
            elif c_val == 1:
                c_label = "🟡 C1: Internal"
            elif c_val == 2:
                c_label = "🟠 C2: Restricted"
            else:
                c_label = "🔴 C3: Confidential"

            if i_val <= 0:
                i_label = "🟢 I0: Low"
            elif i_val == 1:
                i_label = "🟡 I1: Standard"
            elif i_val == 2:
                i_label = "🟠 I2: High"
            else:
                i_label = "🔴 I3: Critical"

            if a_val <= 0:
                a_label = "🟢 A0: Low"
            elif a_val == 1:
                a_label = "🟡 A1: Standard"
            elif a_val == 2:
                a_label = "🟠 A2: High"
            else:
                a_label = "🔴 A3: Critical"
            
            color_map = {
                'Red': '#dc2626',
                'Orange': '#7c2d12',
                'Yellow': '#7a6e00',
                'Green': '#14532d',
                'Gray': '#374151',
            }
            fg = '#ffffff'
            mp = {
                    'Red': '#ffe5e5',
                    'Orange': '#fff0e1',
                    'Yellow': '#fffbe5',
                    'Green': '#e9fbe5',
                    'Gray': '#f5f5f5',
                }
            fg = '#000000'

            def _apply_classification_style(row: pd.Series):
                col_name = 'Classification'
                col = str(row.get('Color', '') or '')
                bg = mp.get(col, '')
                styles = ['' for _ in row.index]
                try:
                    idx = list(row.index).index(col_name)
                    if bg:
                        styles[idx] = f'background-color: {bg}; color: {fg}; font-weight: 600'
                except Exception as e:
                    logger.warning(f"Error applying styles to dataframe: {str(e)}")
                return styles

            try:
                styled = results_df.style.apply(_apply_classification_style, axis=1)
                st.dataframe(styled, width='stretch', hide_index=True)
            except Exception as e:
                st.dataframe(results_df, width='stretch', hide_index=True)
                logger.warning(f"Error applying styles to dataframe: {str(e)}")

        # Dropdown for Table Selection
        st.divider()
        st.markdown("###  Detailed Analysis")
        
        # Create options map: "Database.Schema.Table" -> result object
        options_map = {r['asset']['full_name']: r for r in successful_results}
        options = list(options_map.keys())
        
        col_sel, _ = st.columns([1, 1])
        with col_sel:
            selected_table = st.selectbox(
                "Select a table to view detailed classification:",
                options=options,
                key="classification_result_table_select"
            )
        
        if selected_table:
            result = options_map[selected_table]
            asset = result['asset']
            
            with st.container():
                col1, col2 = st.columns([1, 2])

                with col1:
                    st.markdown(f"**{asset['full_name']}**")
                    st.write(f"**Category:** {result.get('category', 'N/A')}")
                    st.write(f"**Classification:** {result.get('label_emoji', result.get('label', 'N/A'))}")
                    
                    # Display reasoning if available (e.g. column-level drivers)
                    reasoning = result.get('reasoning', [])
                    if reasoning:
                        st.write("**Reasoning:**")
                        for r in reasoning:
                            st.caption(f"• {r}")
                            
                    st.write(f"**Route:** {result.get('route', 'N/A')}")
                    
                    # Display most relevant compliance frameworks
                    compliance_list = result.get('compliance', [])
                    if compliance_list:
                        # Show top compliance frameworks with icons
                        comp_display = []
                        for comp in compliance_list[:3]:  # Show top 3 compliance frameworks
                            comp_icon = '📋'
                            if 'GDPR' in comp.upper():
                                comp_icon = '🇪🇺'
                            elif 'CCPA' in comp.upper():
                                comp_icon = '🇺🇸'
                            elif 'HIPAA' in comp.upper():
                                comp_icon = '🏥'
                            elif 'PCI' in comp.upper():
                                comp_icon = '💳'
                            elif 'SOX' in comp.upper():
                                comp_icon = '📊'
                            comp_display.append(f"{comp_icon} {comp}")
                        st.write(f"**Compliance Frameworks:** {', '.join(comp_display)}")
                    else:
                        st.write(f"**Compliance Frameworks:** None")

                with col2:
                    business_context = result.get('business_context', '')
                    if business_context:
                        st.write("**Business Context:**")
                        st.text_area("Business Context", value=business_context, height=80, disabled=True, key=f"context_{asset['full_name']}", label_visibility="collapsed")

                    validation_issues = result.get('issues', [])
                    if validation_issues:
                        st.write("**Validation Issues:**")
                        for issue in validation_issues:
                            st.error(f"• {issue}")

                    sql_preview = result.get('sql_preview')
                    if sql_preview:
                        st.write("**SQL Preview:**")
                        st.code(sql_preview, language='sql')

                st.divider()

                # --- Edit Classification Section ---
                st.markdown("### ✏️ Edit Classification")
                with st.form(key=f"edit_form_{asset['full_name']}"):
                    ec1, ec2, ec3 = st.columns(3)
                    # Current values
                    cur_c = int(result.get('c', 0) or 0)
                    cur_i = int(result.get('i', 0) or 0)
                    cur_a = int(result.get('a', 0) or 0)
                    cur_lbl = result.get('label', 'Internal')
                    
                    c_opts = [0, 1, 2, 3]
                    c_labels = {0: 'Public', 1: 'Internal', 2: 'Restricted', 3: 'Confidential'}
                    new_c = ec1.selectbox("Confidentiality", options=c_opts, index=cur_c, format_func=lambda x: c_labels.get(x, f"C{x}"), key=f"ec_{asset['full_name']}")

                    i_opts = [0, 1, 2, 3]
                    i_labels = {0: 'Low', 1: 'Standard', 2: 'High', 3: 'Critical'}
                    new_i = ec2.selectbox("Integrity", options=i_opts, index=cur_i, format_func=lambda x: i_labels.get(x, f"I{x}"), key=f"ei_{asset['full_name']}")

                    a_opts = [0, 1, 2, 3]
                    a_labels = {0: 'Low', 1: 'Standard', 2: 'High', 3: 'Critical'}
                    new_a = ec3.selectbox("Availability", options=a_opts, index=cur_a, format_func=lambda x: a_labels.get(x, f"A{x}"), key=f"ea_{asset['full_name']}")
                    
                    lbl_opts = ["Public", "Internal", "Restricted", "Confidential"]
                    try:
                        lbl_idx = lbl_opts.index(cur_lbl)
                    except ValueError:
                        lbl_idx = 1
                    new_label = st.selectbox("Label", options=lbl_opts, index=lbl_idx, key=f"el_{asset['full_name']}")
                    
                    rationale = st.text_area("Rationale (Required)", placeholder="Reason for change...", key=f"er_{asset['full_name']}")
                    
                    if st.form_submit_button("Save Changes"):
                        if not rationale:
                            st.error("Rationale is required.")
                        else:
                            # Recalculate Risk
                            n_risk = "Low"
                            if new_c >= 3 or new_i >= 3 or new_a >= 3:
                                n_risk = "High"
                            elif new_c >= 2 or new_i >= 2 or new_a >= 2:
                                n_risk = "Medium"
                                
                            success, msg = self._update_asset_classification(
                                asset['full_name'], new_c, new_i, new_a, new_label, n_risk, rationale
                            )
                            if success:
                                st.success(msg)
                                # Optionally rerun to refresh view
                                # st.rerun() 
                            else:
                                st.error(msg)
                
                st.divider()
                
                # Column-level detection with automatic loading (full-width display)
                try:
                    table_key = asset['full_name']
                    col_key = f"col_results_{table_key.replace('.', '_')}"
                    col_loading_key = f"col_loading_{table_key.replace('.', '_')}"
                    
                    # Initialize state flags
                    if col_loading_key not in st.session_state:
                        st.session_state[col_loading_key] = False
                    # Pre-populate with results from the current run if available
                    if result.get('columns'):
                        st.session_state[col_key] = result.get('columns')
                    elif col_key not in st.session_state:
                        st.session_state[col_key] = None
                    
                    # Auto-load column detection if not already loaded
                    col_rows = st.session_state.get(col_key)
                    if col_rows is None and not st.session_state[col_loading_key]:
                        st.session_state[col_loading_key] = True
                    
                    # Load column detection if triggered
                    if st.session_state[col_loading_key] and col_rows is None:
                        with st.spinner("🔄 Analyzing columns for sensitive data..."):
                            try:
                                dbn, scn, tbn = table_key.split('.')
                                logger.info(f"Fetching column detection for {dbn}.{scn}.{tbn}")
                                col_rows = self.get_column_detection_results(dbn, scn, tbn)
                                logger.info(f"Raw column detection results: {len(col_rows) if col_rows else 0} rows returned")
                                
                                # Ensure we have a list
                                if col_rows is None:
                                    col_rows = []
                                
                                st.session_state[col_key] = col_rows
                                st.session_state[col_loading_key] = False
                                logger.info(f"✓ Column detection completed: {len(col_rows)} columns analyzed")
                            except Exception as ce:
                                logger.error(f"❌ Column detection error: {ce}", exc_info=True)
                                st.error(f"❌ Column detection failed: {ce}")
                                st.session_state[col_key] = []
                                st.session_state[col_loading_key] = False
                    
                    # Display column results
                    col_rows = st.session_state.get(col_key, [])
                    
                    if col_rows and len(col_rows) > 0:
                        # Filter for display - show only higher-confidence PII / SOX / SOC2 columns
                        col_rows_clean = [
                            r for r in col_rows
                            if 'error' not in r
                            and r.get('category') in {'PII', 'SOX', 'SOC2'}
                            and r.get('confidence_pct', 0) >= 50
                        ]
                        
                        if col_rows_clean and len(col_rows_clean) > 0:
                            st.markdown("#### 📊 Column-Level Classification Results")
                            
                            # Use same emoji mapping as table-level classifications
                            label_emoji_map = {
                                'Confidential': '🟥 Confidential',
                                'Restricted': '🟧 Restricted',
                                'Internal': '🟨 Internal',
                                'Public': '🟩 Public',
                                'Uncertain — review': '⬜ Uncertain — review',
                            }
                            
                            # Create display dataframe with human-readable CIA labels (no confidence column)
                            col_display = []
                            for col in col_rows_clean:
                                raw_label = col.get('label', 'N/A')
                                label_with_emoji = label_emoji_map.get(raw_label, raw_label)
                                raw_cat = col.get('category')
                                # Use robust mapping for display
                                display_cat = self._map_category_to_policy_group(raw_cat)

                                c_val = int(col.get('c', 0) or 0)
                                i_val = int(col.get('i', 0) or 0)
                                a_val = int(col.get('a', 0) or 0)

                                # Map numeric CIA values to descriptive labels (same mapping as table-level)
                                if c_val <= 0:
                                    c_label = "🟢 C0: Public"
                                elif c_val == 1:
                                    c_label = "🟡 C1: Internal"
                                elif c_val == 2:
                                    c_label = "🟠 C2: Restricted"
                                else:
                                    c_label = "🔴 C3: Confidential"

                                if i_val <= 0:
                                    i_label = "🟢 I0: Low"
                                elif i_val == 1:
                                    i_label = "🟡 I1: Standard"
                                elif i_val == 2:
                                    i_label = "🟠 I2: High"
                                else:
                                    i_label = "🔴 I3: Critical"

                                if a_val <= 0:
                                    a_label = "🟢 A0: Low"
                                elif a_val == 1:
                                    a_label = "🟡 A1: Standard"
                                elif a_val == 2:
                                    a_label = "🟠 A2: High"
                                else:
                                    a_label = "🔴 A3: Critical"

                                col_display.append({
                                    "Column": col.get('column', 'N/A'),
                                    "Data Type": col.get('data_type', 'N/A'),
                                    "Category": display_cat if display_cat is not None else 'N/A',
                                    "Label": label_with_emoji,
                                    "Confidentiality": c_label,
                                    "Integrity": i_label,
                                    "Availability": a_label,
                                })
                            
                            if col_display:
                                col_df = pd.DataFrame(col_display)
                                
                                # Color code by label using same scheme as table-level results
                                def _apply_column_label_style(row: pd.Series):
                                    val = str(row.get('Label', '') or '')
                                    bg = ''
                                    if '🟥 Confidential' in val:
                                        bg = '#ffe5e5'  # Red background (light)
                                    elif '🟧 Restricted' in val:
                                        bg = '#fff0e1'  # Orange
                                    elif '🟨 Internal' in val:
                                        bg = '#fffbe5'  # Yellow
                                    elif '🟩 Public' in val:
                                        bg = '#e9fbe5'  # Green
                                    elif '⬜ Uncertain — review' in val:
                                        bg = '#f5f5f5'  # Gray
                                    styles = ['' for _ in row.index]
                                    try:
                                        idx = list(row.index).index('Label')
                                        if bg:
                                            styles[idx] = f'background-color: {bg}; color: #000; font-weight: 600'
                                    except Exception:
                                        pass
                                    return styles
                                
                                styled_df = col_df.style.apply(_apply_column_label_style, axis=1)
                                st.dataframe(styled_df, width='stretch', hide_index=True)
                                
                                # Summary statistics
                                confident = sum(1 for c in col_rows_clean if c.get('confidence_pct', 0) >= 80)
                                likely = sum(1 for c in col_rows_clean if 60 <= c.get('confidence_pct', 0) < 80)
                                uncertain = sum(1 for c in col_rows_clean if c.get('confidence_pct', 0) < 60)
                                
                                st.success(f"✅ Summary: {confident} Confident (≥80%) | {likely} Likely (60-80%) | {uncertain} Uncertain (<60%)")
                            else:
                                st.info("ℹ️ No sensitive columns detected in this table.")
                        else:
                            st.info("ℹ️ Column detection completed - no sensitive columns found.")
                    elif col_rows == []:
                        st.info("ℹ️ Column detection completed - no sensitive columns found.")
                except Exception as e:
                    logger.error(f"Column detection UI error: {e}", exc_info=True)
                    st.error(f"Error displaying column detection: {e}")

        # Summary statistics
        self._display_summary_statistics(successful_results)

    def _display_summary_statistics(self, results: List[Dict[str, Any]]) -> None:
        """Display summary statistics of the classification results."""
        st.markdown("#### Summary Statistics")

        if not results:
            return

        # Calculate statistics
        categories = {}
        routes = {}
        statuses = {}
        confidence_ranges = {'High (≥80%)': 0, 'Medium (60-79%)': 0, 'Low (<60%)': 0}

        for result in results:
            # Categories
            cat = result.get('category', 'Unknown')
            categories[cat] = categories.get(cat, 0) + 1

            # Routes
            route = result.get('route', 'Unknown')
            routes[route] = routes.get(route, 0) + 1

            # Statuses
            status = result.get('application_status', 'Unknown')
            statuses[status] = statuses.get(status, 0) + 1

            # Confidence ranges
            conf = result.get('confidence', 0)
            if conf >= 0.8:
                confidence_ranges['High (≥80%)'] += 1
            elif conf >= 0.6:
                confidence_ranges['Medium (60-79%)'] += 1
            else:
                confidence_ranges['Low (<60%)'] += 1

        # Display in columns
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("**Categories**")
            for cat, count in sorted(categories.items()):
                st.write(f"{cat}: {count}")

        with col2:
            st.markdown("**Routes**")
            for route, count in sorted(routes.items()):
                st.write(f"{route}: {count}")

        with col3:
            st.markdown("**Statuses**")
            for status, count in sorted(statuses.items()):
                st.write(f"{status}: {count}")

        with col4:
            st.markdown("**Confidence**")
            for range_name, count in confidence_ranges.items():
                st.write(f"{range_name}: {count}")

    # ==================================================================================
    # NEW GOVERNANCE-DRIVEN CLASSIFICATION METHODS (100% METADATA DRIVEN)
    # ==================================================================================

    def _get_columns_from_information_schema(self, db: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Fetch columns from information_schema."""
        try:
            return snowflake_connector.execute_query(f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT as COLUMN_COMMENT
                FROM {db}.INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """, (schema, table)) or []
        except Exception as e:
            logger.error(f"Failed to fetch columns for {db}.{schema}.{table}: {e}")
            return []

    def _build_table_context_from_metadata(self, db: str, schema: str, table: str) -> str:
        """Build context using ONLY information_schema metadata"""
        try:
            # Get table metadata
            table_info = snowflake_connector.execute_query(f"""
                SELECT TABLE_NAME, TABLE_TYPE, COMMENT, ROW_COUNT
                FROM {db}.INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            """, (schema, table))
            
            table_data = table_info[0] if table_info else {}
            
            # Get column metadata
            columns = self._get_columns_from_information_schema(db, schema, table)

            # Precompute column and comment strings to avoid nested f-strings
            col_desc_list = [
                "{} ({})".format(col.get("COLUMN_NAME"), col.get("DATA_TYPE"))
                for col in columns
            ]
            columns_str = ", ".join(col_desc_list) if col_desc_list else ""

            comment_desc_list = [
                "{}: {}".format(col.get("COLUMN_NAME"), col.get("COLUMN_COMMENT", "No comment"))
                for col in columns
                if col.get("COLUMN_COMMENT")
            ]
            comments_str = "; ".join(comment_desc_list) if comment_desc_list else ""

            # Build context from metadata only
            context_parts = [
                f"Table: {schema}.{table}",
                f"Type: {table_data.get('TABLE_TYPE', 'UNKNOWN')}",
                f"Description: {table_data.get('COMMENT', 'No description')}",
                f"Columns: {columns_str}",
                f"Column Comments: {comments_str}"
            ]
            
            return " | ".join([part for part in context_parts if part])
            
        except Exception as e:
            logger.error(f"Metadata context building failed for {db}.{schema}.{table}: {e}")
            return f"Table: {schema}.{table}"

    def _semantic_scores_governance_driven(self, text: str) -> Dict[str, float]:
        """
        PHASE 2: Semantic scoring using ONLY governance table centroids
        
        CRITICAL FIXES APPLIED:
        - E5 ASYMMETRIC ENCODING: Uses 'query:' prefix for input text
        - Matches against 'passage:' encoded centroids
        - Explicit vector normalization
        - Embedding caching for performance
        """
        scores = {}
        
        if not text or not self._embedder or not self._category_centroids:
            return scores
        
        try:
            # 1. Check Cache First
            # Use a simple class-level cache key based on text
            cache_key = f"sem_score_{hash(text)}"
            if hasattr(self, '_embedding_cache') and cache_key in self._embedding_cache:
                return self._embedding_cache[cache_key]
            
            # 2. Preprocess and Encode with E5 QUERY Prefix
            # E5 requires 'query:' for the input text when matching against 'passage:' documents
            processed_text = self._preprocess_text_local(text)
            
            # Add 'query:' prefix for E5 models
            if self._embed_backend == 'sentence-transformers':
                query_text = f"query: {processed_text}"
            else:
                query_text = processed_text
            
            # Encode text
            text_embedding = self._embedder.encode([query_text], normalize_embeddings=True)[0]
            
            # CRITICAL: Explicitly re-normalize to ensure unit vector
            text_norm = np.linalg.norm(text_embedding)
            if text_norm == 0:
                return scores
            
            text_embedding = text_embedding / text_norm
            
            # 3. Compare against ALL governance categories
            for category, centroid in self._category_centroids.items():
                if centroid is None:
                    continue
                    
                try:
                    # Centroids are already normalized during creation
                    # Cosine similarity (dot product of normalized vectors)
                    similarity = float(np.dot(text_embedding, centroid))
                    
                    # Convert cosine similarity to confidence score [0, 1]
                    confidence = (similarity + 1.0) / 2.0
                    
                    # Return ALL scores > 0 (filtering happens later)
                    if confidence > 0.0:
                        scores[category] = confidence
                    
                except Exception:
                    continue
            
            # 4. Cache Result
            if not hasattr(self, '_embedding_cache'):
                self._embedding_cache = {}
            
            # Simple LRU-like behavior: clear if too big
            if len(self._embedding_cache) > 1000:
                self._embedding_cache.clear()
                
            self._embedding_cache[cache_key] = scores
            return scores
                    
        except Exception as e:
            logger.error(f"Governance-driven semantic scoring failed: {e}", exc_info=True)
            return scores
            
        logger.debug(f"Semantic scores returned: {len(scores)} categories")
        return scores

    def _pattern_scores_governance_driven(self, text: str) -> Dict[str, float]:
        """
        PHASE 3: Pattern scoring using ONLY SENSITIVE_PATTERNS table
        
        CRITICAL FIX:
        - Uses _category_pattern_metadata (dicts with weights) instead of _category_patterns (strings)
        - Progressive scoring: At least 1 match = 0.5, scaling to 1.0 for 100% coverage
        - Applies SENSITIVITY_WEIGHT from metadata for weighted scoring
        - NO PRE-FILTERING at threshold (return all non-zero scores)
        """
        scores = {}
        
        # CRITICAL FIX: Use pattern metadata (dictionaries) instead of plain strings
        if hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata:
            # Use metadata-driven approach with weights
            for category, pattern_metadata_list in self._category_pattern_metadata.items():
                if not pattern_metadata_list:
                    continue
                    
                total_weighted_score = 0.0
                match_count = 0
                total_patterns = len(pattern_metadata_list)
                matched_patterns = []
                
                for pat_meta in pattern_metadata_list:
                    # CRITICAL: pat_meta is a dictionary with keys: 'pattern', 'weight', 'sensitivity_type'
                    if not isinstance(pat_meta, dict):
                        # Handle legacy string format or connector issues
                        if isinstance(pat_meta, str):
                            pattern_regex = pat_meta
                            pattern_weight = 1.0
                            logger.debug(f"Pattern metadata is a string (legacy format): '{pattern_regex[:50]}...'")
                        else:
                            logger.warning(f"Invalid pattern metadata type for {category}: {type(pat_meta)}")
                            continue
                    else:
                        pattern_regex = pat_meta.get('pattern', '')
                        pattern_weight = float(pat_meta.get('weight', 1.0))
                    
                    if not pattern_regex:
                        continue
                    
                    try:
                        if re.search(pattern_regex, text, re.IGNORECASE):
                            match_count += 1
                            total_weighted_score += pattern_weight
                            matched_patterns.append(pattern_regex[:50])  # Store first 50 chars for debugging
                            logger.debug(f"Pattern match for {category}: {pattern_regex[:50]}...")
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern for {category}: {pattern_regex[:50]}... - {e}")
                        continue
                
                if match_count > 0:
                    # WEIGHTED PROGRESSIVE SCORING:
                    # - Normalize by total possible weight (sum of all pattern weights)
                    # - At least 1 match = 0.50 base + weighted contribution
                    total_possible_weight = sum(float(pm.get('weight', 1.0)) for pm in pattern_metadata_list if isinstance(pm, dict))
                    
                    if total_possible_weight > 0:
                        weighted_coverage = total_weighted_score / total_possible_weight
                        score = 0.5 + (0.5 * weighted_coverage)  # Maps [0,1] coverage to [0.5,1.0] score
                    else:
                        # Fallback to simple coverage if weights are missing
                        coverage = match_count / max(1, total_patterns)
                        score = 0.5 + (0.5 * coverage)
                    
                    # PHASE 3: NO PRE-FILTERING - return all non-zero scores
                    scores[category] = min(1.0, score)
                    logger.debug(
                        f"Pattern: {category} = {score:.3f} ({match_count}/{total_patterns} patterns matched, weighted_score={total_weighted_score:.2f})"
                    )
        
        # FALLBACK: Use simple pattern list if metadata not available
        elif hasattr(self, '_category_patterns') and self._category_patterns:
            logger.warning("Using fallback pattern scoring (no metadata available)")
            for category, patterns in self._category_patterns.items():
                if not patterns:
                    continue
                    
                match_count = 0
                total_patterns = len(patterns)
                
                for pattern in patterns:
                    # CRITICAL: pattern is a string (regex)
                    if not isinstance(pattern, str):
                        continue
                    
                    try:
                        if re.search(pattern, text, re.IGNORECASE):
                            match_count += 1
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern for {category}: {pattern[:50]}... - {e}")
                        continue
                
                if match_count > 0:
                    coverage = match_count / max(1, total_patterns)
                    score = 0.5 + (0.5 * coverage)
                    scores[category] = min(1.0, score)
                    logger.debug(f"Pattern (fallback): {category} = {score:.3f} ({match_count}/{total_patterns} patterns matched)")
        else:
            logger.warning("No pattern data loaded from SENSITIVE_PATTERNS table")
        
        logger.debug(f"Pattern scores returned: {len(scores)} categories")
        return scores

    def _compute_governance_scores(self, text: str) -> Dict[str, float]:
        """
        PHASE 3: Adaptive confidence scoring with governance metadata
        
        CRITICAL FIXES:
        - Default threshold lowered from 0.65 to 0.45
        - Intelligent weight adjustment based on available signals
        - Quality-based calibration for context richness
        - Multiplicative boosting for strong signals
        - NO min-max normalization (preserves absolute confidence)
        """
        scores = {}
        
        # Get component scores (all now return unfiltered scores)
        semantic_scores = self._semantic_scores_governance_driven(text)
        keyword_scores = self._keyword_scores(text)
        pattern_scores = self._pattern_scores_governance_driven(text)
        
        # Context quality assessment
        quality = self._context_quality_metrics(text)
        quality_factor = 1.0
        
        # Boost for rich textual context
        if quality.get('len', 0) > 300 and quality.get('alpha_ratio', 0) > 0.5:
            quality_factor = 1.10  # Rich context → 10% boost
        elif quality.get('too_short', False):
            quality_factor = 0.95  # Limited context → 5% penalty
        
        # Combine all detected categories
        all_categories = set(
            list(semantic_scores.keys()) + 
            list(keyword_scores.keys()) + 
            list(pattern_scores.keys())
        )
        
        logger.debug(f"Combining scores for {len(all_categories)} categories from {len(semantic_scores)} semantic, {len(keyword_scores)} keyword, {len(pattern_scores)} pattern")
        
        for category in all_categories:
            sem_score = semantic_scores.get(category, 0.0)
            kw_score = keyword_scores.get(category, 0.0)
            pat_score = pattern_scores.get(category, 0.0)
            
            # INTELLIGENT WEIGHT ADJUSTMENT based on metadata configuration
            # Retrieve weights from metadata (default to 0.6/0.25/0.15 if not found)
            weights = self._category_scoring_weights.get(category, {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15})
            w_sem = weights['w_sem']
            w_kw = weights['w_kw']
            w_pat = weights['w_pat']
            
            # Dynamic normalization based on available signals
            # If a signal is missing (0.0), we redistribute its weight to the others
            available_weight = 0.0
            score_sum = 0.0
            signal_parts = []
            
            if sem_score > 0:
                available_weight += w_sem
                score_sum += sem_score * w_sem
                signal_parts.append("SEM")
            
            if kw_score > 0:
                available_weight += w_kw
                score_sum += kw_score * w_kw
                signal_parts.append("KW")
                
            if pat_score > 0:
                available_weight += w_pat
                score_sum += pat_score * w_pat
                signal_parts.append("PAT")
                
            if available_weight > 0:
                base_score = score_sum / available_weight
                signal_type = "+".join(signal_parts)
            else:
                continue  # No signals for this category
            
            # Apply quality calibration
            adjusted_score = base_score * quality_factor
            
            # MULTIPLICATIVE BOOSTING for strong signals
            # This amplifies confident detections while preserving relative ordering
            if adjusted_score >= 0.70:
                # Very strong signal → 15-30% boost
                boost_factor = 1.15 + (adjusted_score - 0.70) * 0.5
            elif adjusted_score >= 0.55:
                # Strong signal → 10-15% boost
                boost_factor = 1.10 + (adjusted_score - 0.55) * 0.33
            elif adjusted_score >= 0.40:
                # Moderate signal → 5-10% boost
                boost_factor = 1.05 + (adjusted_score - 0.40) * 0.33
            else:
                # Weak signal → no boost
                boost_factor = 1.0
            
            final_score = min(0.95, adjusted_score * boost_factor)
            
            # ADAPTIVE THRESHOLD from governance (DEFAULT 0.35 - BALANCED: Raised from 0.25 to reduce false positives)
            threshold = self._category_thresholds.get(category, 0.35)
            
            # Only include if above threshold
            if final_score >= threshold:
                scores[category] = final_score
                logger.debug(
                    f"✓ {category}: base={base_score:.3f}, final={final_score:.3f}, threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
            else:
                logger.debug(
                    f"✗ {category}: final={final_score:.3f} < threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
        
        logger.debug(f"Governance scores: {len(scores)} categories passed threshold")
        return scores
        
    def _sample_table_values_batch(self, db: str, schema: str, table: str, columns: List[str], limit: int = 20) -> Dict[str, List[Any]]:
        """
        Batch sample values for ALL columns in a single query to reduce Snowflake costs.
        Returns a dictionary mapping column_name -> list of sample values.
        """
        if not columns:
            return {}
            
        try:
            # Construct a single query to fetch samples for all columns
            # Using LIMIT instead of SAMPLE for better performance on large tables if we just need 'some' data
            # Or use TABLESAMPLE SYSTEM (1) for very large tables
            
            cols_sql = ", ".join([f'"{col}"' for col in columns])
            query = f"""
            SELECT {cols_sql}
            FROM "{db}"."{schema}"."{table}"
            LIMIT {limit}
            """
            
            rows = snowflake_connector.execute_query(query) or []
            
            # Transpose rows to columns
            samples_by_col = {col: [] for col in columns}
            for row in rows:
                for col in columns:
                    val = row.get(col)
                    if val is not None and str(val).strip():
                        samples_by_col[col].append(val)
                        
            return samples_by_col
            
        except Exception as e:
            logger.warning(f"Batch sampling failed for {table}: {e}")
            return {col: [] for col in columns}

    def _classify_column_governance_driven(self, db: str, schema: str, table: str, 
                                         column: Dict[str, Any], 
                                         pre_fetched_samples: List[Any] = None) -> Dict[str, Any]:
        """
        Classify single column using ONLY governance metadata.
        
        CRITICAL REQUIREMENTS:
        1. Retrieve all sensitive columns using metadata from governance tables
        2. Exclude generic columns (product_id, status, etc.)
        3. Match against semantic definitions AND sensitive_patterns governance table
        4. Return only genuinely detected sensitive columns (PII/SOX/SOC2)
        
        ACCURACY ENHANCEMENT: Added context-aware classification that understands:
        1. Table-level context (e.g., ORDER tables → SOX priority)
        2. Smart ID classification (order_id vs customer_id vs product_id)
        3. Category boosting based on semantic table understanding
        """
        
        col_name = column['COLUMN_NAME']
        col_type = column['DATA_TYPE']
        col_comment = column.get('COLUMN_COMMENT', '')
        
        col_lower = col_name.lower()

        # ========================================================================
        # METADATA-DRIVEN APPROACH: Use governance tables for pattern matching
        # ========================================================================
        # Instead of hardcoded patterns, we use patterns from SENSITIVE_PATTERNS table
        # This ensures the system is 100% metadata-driven and can be updated without code changes
        
        # Get sensitive patterns from governance metadata (loaded during initialization)
        # These patterns come from the SENSITIVE_PATTERNS table
        sensitive_patterns_from_governance = set()
        
        def extract_keywords_from_pattern(pattern_str):
            """Helper to extract keywords from a regex pattern string."""
            if not isinstance(pattern_str, str) or not pattern_str:
                return set()
                
            # Remove regex special chars and extract meaningful terms
            return {
                kw for kw in 
                pattern_str.lower()
                .replace('\\b', ' ').replace('\\d', ' ').replace('\\w', ' ')
                .replace('.*', ' ').replace('.+', ' ')
                .replace('[', ' ').replace(']', ' ')
                .replace('(', ' ').replace(')', ' ')
                .replace('|', ' ').replace('?', ' ')
                .replace('*', ' ').replace('+', ' ')
                .split()
                if len(kw) > 2  # Only meaningful keywords
            }
        
        # Check both _category_pattern_metadata and _category_patterns
        patterns_processed = False
        
        # Try _category_pattern_metadata first (preferred format)
        if hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata:
            try:
                for category, patterns in self._category_pattern_metadata.items():
                    pg = self._map_category_to_policy_group(category)
                    if pg in {'PII', 'SOX', 'SOC2'} and patterns:
                        for pattern_item in patterns:
                            pattern_str = ''
                            if isinstance(pattern_item, dict):
                                pattern_str = pattern_item.get('pattern', '')
                            elif isinstance(pattern_item, str):
                                pattern_str = pattern_item
                                
                            if pattern_str:
                                sensitive_patterns_from_governance.update(
                                    extract_keywords_from_pattern(pattern_str)
                                )
                patterns_processed = True
            except Exception as e:
                logger.warning(f"Error processing _category_pattern_metadata: {e}")
        
        # Fall back to _category_patterns if needed
        if not patterns_processed and hasattr(self, '_category_patterns') and self._category_patterns:
            try:
                for category, patterns in self._category_patterns.items():
                    pg = self._map_category_to_policy_group(category)
                    if pg in {'PII', 'SOX', 'SOC2'} and patterns:
                        for pattern_str in patterns:
                            if isinstance(pattern_str, str) and pattern_str:
                                sensitive_patterns_from_governance.update(
                                    extract_keywords_from_pattern(pattern_str)
                                )
            except Exception as e:
                logger.warning(f"Error processing _category_patterns: {e}")
        
        logger.debug(f"Extracted {len(sensitive_patterns_from_governance)} unique keywords from patterns")
        
        # Also get keywords from _category_keywords (loaded from SENSITIVE_KEYWORDS table)
        if hasattr(self, '_category_keywords') and self._category_keywords:
            for category, keywords in self._category_keywords.items():
                # Only include keywords from PII/SOX/SOC2 categories
                pg = self._map_category_to_policy_group(category)
                if pg in {'PII', 'SOX', 'SOC2'}:
                    for kw in keywords:
                        if isinstance(kw, str) and len(kw) > 2:
                            sensitive_patterns_from_governance.add(kw.lower())
        
        # Fallback: If governance tables are empty, use minimal baseline patterns
        if not sensitive_patterns_from_governance:
            logger.warning(f"  ⚠️ No patterns loaded from governance tables - using baseline patterns")
            sensitive_patterns_from_governance = {
                # Minimal PII patterns
                'ssn', 'email', 'phone', 'address', 'name', 'birth', 'passport', 'license',
                'credit_card', 'account_number', 'medical', 'patient',
                # Minimal SOX patterns
                'revenue', 'transaction', 'invoice', 'payment', 'ledger', 'financial',
                'audit', 'sox',
                # Minimal SOC2 patterns
                'password', 'token', 'credential', 'secret', 'key', 'session', 'auth'
            }
        
        # CRITICAL: Check if column name contains ANY sensitive pattern from governance tables
        has_sensitive_pattern = any(pattern in col_lower for pattern in sensitive_patterns_from_governance)
        
        # Additional check: Exclude generic/non-sensitive columns even if they match patterns
        generic_exclusions = [
            'product_id', 'item_id', 'catalog_id', 'category_id', 'sku',
            'warehouse_id', 'location_id', 'department_id', 'store_id',
            'status', 'type', 'code', 'flag', 'mode',
            'created_at', 'updated_at', 'created_date', 'updated_date',
            'description', 'notes', 'comment', 'remarks',
            'quantity', 'count', 'total_items'
        ]
        
        is_generic = any(excl in col_lower for excl in generic_exclusions)
        
        # CRITICAL: Skip column if NO sensitive pattern found OR if it's a generic column
        if not has_sensitive_pattern or is_generic:
            if is_generic:
                logger.debug(f"  ✓ SKIPPED '{col_name}' - Generic/non-sensitive column (excluded)")
            else:
                logger.debug(f"  ✓ SKIPPED '{col_name}' - No sensitive pattern detected (metadata-driven filtering)")
            return None
        
        # If we reach here, column has a sensitive pattern and should be scored
        logger.debug(f"  → PROCESSING '{col_name}' - Sensitive pattern detected from governance metadata")

        # Build context from metadata only
        context_parts = [
            f"Column: {col_name}",
            f"Table: {table}",
            f"Schema: {schema}",
            f"Data Type: {col_type}"
        ]
        
        if col_comment:
            context_parts.append(f"Comment: {col_comment}")
        
        # Use pre-fetched samples if available (Batch Optimization)
        if pre_fetched_samples is not None:
            samples = pre_fetched_samples
        else:
            # Fallback to individual query (legacy)
            samples = self._sample_column_values(db, schema, table, col_name, 20)
            
        if samples:
            sample_text = " ".join([str(s) for s in samples[:3]])
            context_parts.append(f"Samples: {sample_text}")
        
        context = " | ".join(context_parts)
        
        # Compute scores using governance-driven methods only
        scores = self._compute_governance_scores(context)
        
        # === ACCURACY ENHANCEMENT: Context-Aware Adjustments ===
        scores = self._apply_context_aware_adjustments(
            scores, col_name, table, col_type, samples
        )
        
        # === MULTI-LABEL SUPPORT ===
        # Identify ALL categories that meet the threshold, not just the top one
        detected_categories = []
        for cat, score in scores.items():
            # Use category-specific threshold if available, else 0.35 (BALANCED: Raised from 0.25 to reduce false positives)
            thresh = self._category_thresholds.get(cat, 0.35)
            
            # EXCLUDE GENERIC / NON-SENSITIVE CATEGORIES
            # We only want to report truly sensitive categories
            if cat.upper() in ('NON_SENSITIVE', 'GENERAL', 'SYSTEM', 'METADATA', 'UNKNOWN'):
                continue
                
            # Check if it maps to a sensitive policy group
            pg = self._map_category_to_policy_group(cat)
            if pg == 'NON_SENSITIVE':
                continue
            
            # STRICTER validation: Require minimum confidence of 0.70 to reduce false positives
            # This ensures only high-confidence sensitive signals are kept for column-level results
            if score < 0.70:
                continue

            if score >= thresh:
                detected_categories.append({
                    'category': cat,
                    'confidence': score
                })
        
        # Sort by confidence descending
        detected_categories.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Determine primary category (top 1)
        if detected_categories:
            best_category = detected_categories[0]['category']
            confidence = detected_categories[0]['confidence']
        else:
            best_category = 'NON_SENSITIVE'
            confidence = 0.0
        
        # Map to policy group for UI consistency
        policy_group = self._map_category_to_policy_group(best_category) if best_category != 'NON_SENSITIVE' else None

        # Ensure we only treat PII/SOX/SOC2 as sensitive policy groups for column detection
        if policy_group not in {"PII", "SOX", "SOC2"}:
            policy_group = None
        
        # === CRITICAL VALIDATION: Skip Non-Sensitive Columns ===
        # If no detected categories OR best category is NON_SENSITIVE OR no policy group mapping
        # Then this column is NOT sensitive and should be EXCLUDED from results
        if not detected_categories or best_category == 'NON_SENSITIVE' or not policy_group:
            logger.debug(f"  → Column '{col_name}' is NON-SENSITIVE (no valid sensitive categories detected)")
            # Return None to indicate this column should be skipped
            return None
        
        # Additional validation: Ensure confidence is meaningful
        if confidence < 0.70:
            logger.debug(f"  ✓ Column '{col_name}' confidence {confidence:.3f} < 0.70 (too low, skipping)")
            return None
        


        # Create comma-separated string of all detected categories for UI display
        multi_label_str = ", ".join([d['category'] for d in detected_categories]) if detected_categories else best_category

        # Calculate CIA scores based on policy group and category sensitivity
        # Default to Internal (C1, I1, A1)
        # Confidentiality: 0=Public, 1=Internal, 2=Restricted, 3=Confidential
        # Integrity/Availability: 0=Low, 1=Standard, 2=High, 3=Critical
        cia_scores = {'c': 1, 'i': 1, 'a': 1}
        final_label = 'Internal'
        
        cat_upper = best_category.upper()
        
        # 1. Check for Confidential (C3) - Highest Priority
        # SOX (Financial Reporting) is always C3
        if policy_group == 'SOX':
            cia_scores = {'c': 3, 'i': 3, 'a': 3}
            final_label = 'Confidential'
        # Sensitive PII is C3
        elif policy_group == 'PII' and any(x in cat_upper for x in ['SSN', 'TAX', 'PASSPORT', 'CREDIT', 'BANK', 'ACCOUNT', 'FINANCIAL', 'DRIVER', 'LICENSE']):
            cia_scores = {'c': 3, 'i': 3, 'a': 3}
            final_label = 'Confidential'
        # Secrets/Keys are C3
        elif any(x in cat_upper for x in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'AUTH', 'CREDENTIAL']):
            cia_scores = {'c': 3, 'i': 3, 'a': 3}
            final_label = 'Confidential'
            
        # 2. Check for Restricted (C2)
        # Standard PII is C2
        elif policy_group == 'PII':
            cia_scores = {'c': 2, 'i': 2, 'a': 2}
            final_label = 'Restricted'
        # SOC2 is generally C2 (unless it matched secrets above)
        elif policy_group == 'SOC2':
            cia_scores = {'c': 2, 'i': 2, 'a': 2}
            final_label = 'Restricted'
        # Fallback for explicit labels
        elif label == 'Confidential':
            cia_scores = {'c': 3, 'i': 3, 'a': 3}
            final_label = 'Confidential'
        elif label == 'Restricted':
            cia_scores = {'c': 2, 'i': 2, 'a': 2}
            final_label = 'Restricted'
            
        # 3. Check for Public (C0)
        elif label == 'Public':
            cia_scores = {'c': 0, 'i': 0, 'a': 0}
            final_label = 'Public'
            
        # Update label to match policy
        label = final_label
            
        return {
            'schema': schema,
            'table': table,
            'column_name': col_name,
            'data_type': col_type,
            'category': best_category,
            'policy_group': policy_group,  # Expose policy group explicitly
            'confidence': confidence,
            'detected_categories': detected_categories,  # New Multi-Label Field
            'multi_label_category': multi_label_str,     # UI Display Field
            'governance_scores': scores,
            'context_used': context,
            # UI Fields
            'column': col_name,
            'label': label,
            'c': cia_scores['c'], 'i': cia_scores['i'], 'a': cia_scores['a'],
            'confidence_pct': round(confidence * 100, 1)
        }
    
    # ============================================================================
    # SMART CLASSIFICATION OVERRIDE SYSTEM (PATTERN-AWARE)
    # ============================================================================
    
    def _init_address_context_registry(self):
        """
        Initialize the pattern registry for address context detection.
        Centralized configuration that can be extended or loaded from metadata.
        """
        if hasattr(self, '_address_context_registry'):
            return

        # Registry defining context patterns and their scoring implications
        # This distinguishes between Physical (PII) and Network (SOC2) addresses
        self._address_context_registry = {
            "PHYSICAL_ADDRESS": {
                "indicators": [
                    "street", "city", "zip", "postal", "province", "country", 
                    "state", "apt", "suite", "building", "lane", "road", "avenue",
                    "billing_address", "shipping_address", "mailing_address",
                    "residence", "domicile", "geo", "location"
                ],
                "negative_indicators": ["ip", "mac", "host", "email", "url", "link", "web"],
                "actions": {
                    "boost": {"policy_group": "PII", "pattern": "PII_PERSONAL_INFO", "factor": 1.6},
                    "suppress": {"policy_group": "SOC2", "pattern": "SOC2_SECURITY_DATA", "factor": 0.1}
                }
            },
            "NETWORK_ADDRESS": {
                "indicators": [
                    "ip_address", "mac_address", "host", "port", "subnet", 
                    "gateway", "protocol", "dns", "url", "uri", "endpoint",
                    "ipv4", "ipv6"
                ],
                "negative_indicators": ["street", "city", "zip", "postal", "billing", "shipping"],
                "actions": {
                    "boost": {"policy_group": "SOC2", "pattern": "SOC2_SECURITY_DATA", "factor": 1.5},
                    "suppress": {"policy_group": "PII", "pattern": "PII_PERSONAL_INFO", "factor": 0.2}
                }
            }
        }

    def _analyze_address_context(self, col_name: str) -> str:
        """
        Analyze column name to determine if it's a Physical or Network address.
        Returns: 'PHYSICAL_ADDRESS', 'NETWORK_ADDRESS', or 'AMBIGUOUS'
        """
        self._init_address_context_registry()
        col_lower = col_name.lower()
        
        # Score both contexts
        scores = {"PHYSICAL_ADDRESS": 0, "NETWORK_ADDRESS": 0}
        
        for context_type, config in self._address_context_registry.items():
            # Check positive indicators
            for ind in config["indicators"]:
                if ind in col_lower:
                    scores[context_type] += 1
            # Check negative indicators
            for neg in config["negative_indicators"]:
                if neg in col_lower:
                    scores[context_type] -= 1
        
        phys = scores["PHYSICAL_ADDRESS"]
        net = scores["NETWORK_ADDRESS"]
        
        # Determine Context with simple heuristic
        if phys > 0 and phys > net:
            return "PHYSICAL_ADDRESS"
        elif net > 0 and net > phys:
            return "NETWORK_ADDRESS"
        else:
            return "AMBIGUOUS"

    def _apply_smart_address_overrides(self, scores: Dict[str, float], col_name: str) -> Dict[str, float]:
        """
        Apply smart overrides based on detected address context.
        """
        context = self._analyze_address_context(col_name)
        
        if context == "AMBIGUOUS":
            return scores
            
        # Apply actions from registry
        config = self._address_context_registry.get(context)
        if not config:
            return scores
            
        actions = config.get("actions", {})
        
        logger.debug(f"  → Applying smart override for '{col_name}': Detected {context}")
        
        # Apply Boost
        boost = actions.get("boost")
        if boost:
            self._boost_category(scores, boost["policy_group"], boost["pattern"], boost["factor"])
            
        # Apply Suppression
        suppress = actions.get("suppress")
        if suppress:
            self._reduce_category(scores, suppress["policy_group"], suppress["pattern"], suppress["factor"])
            
        return scores

    def _apply_context_aware_adjustments(self, scores: Dict[str, float], 
                                        col_name: str, table: str, 
                                        col_type: str, samples: List) -> Dict[str, float]:
        """
        Apply context-aware adjustments to improve classification accuracy.
        
        Fixes misclassifications like:
        - order_id → SOC2 (wrong) should be SOX
        - product_id → PII (wrong) should be NON_SENSITIVE
        - customer_id → SOC2 (wrong) should be PII
        """
        
        adjusted_scores = scores.copy()
        
        col_lower = col_name.lower()
        table_lower = table.lower()
        
        # === RULE 1: Table Context Boosting ===
        # Identify table domain and boost relevant categories
        
        # Financial/Transactional tables → Boost SOX
        if any(kw in table_lower for kw in ['order', 'transaction', 'payment', 'invoice', 
                                              'billing', 'purchase', 'sale', 'revenue']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.3)
            # Reduce SOC2 for non-security columns in financial tables
            if not any(kw in col_lower for kw in ['password', 'token', 'auth', 'credential', 'session']):
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.7)
        
        # Customer/User tables →s Boost PII
        elif any(kw in table_lower for kw in ['customer', 'user', 'employee', 'person', 'contact']):
            self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.3)
        
        # Security/Auth tables → Boost SOC2
        elif any(kw in table_lower for kw in ['auth', 'security', 'access', 'credential', 'session', 'login']):
            self._boost_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 1.3)
        
        # === RULE 2: Smart ID Classification ===
        # Different types of IDs should map to different categories
        
        if col_lower.endswith('_id') or col_lower.endswith('id'):
            
            # PII IDs: Identify people
            if any(kw in col_lower for kw in ['customer', 'user', 'employee', 'person', 'patient', 
                                               'member', 'subscriber', 'citizen', 'contact']):
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.5)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            
            # SOX IDs: Financial/transactional identifiers
            elif any(kw in col_lower for kw in ['order', 'transaction', 'payment', 'invoice', 
                                                 'account', 'billing', 'purchase', 'sale']):
                self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.5)
            
            # SOC2 IDs: Security/access identifiers
            elif any(kw in col_lower for kw in ['session', 'token', 'auth', 'credential', 
                                                 'access', 'login', 'permission']):
                self._boost_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 1.5)
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            
            # Generic IDs: Product, category, etc. → Likely NON_SENSITIVE
            elif any(kw in col_lower for kw in ['product', 'item', 'category', 'catalog', 
                                                 'inventory', 'sku', 'department', 'store', 'warehouse',
                                                 'location', 'region', 'branch', 'division']):
                # Significantly reduce all sensitive scores for catalog IDs
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.6)
                # Remove all sensitive categories for these generic IDs
                for cat in list(adjusted_scores.keys()):
                    cat_upper = cat.upper()
                    if 'PII' in cat_upper or 'SOX' in cat_upper or 'SOC2' in cat_upper:
                        adjusted_scores.pop(cat, None)
        
        # === RULE 3: Price/Amount Fields → SOX ===
        if any(kw in col_lower for kw in ['price', 'amount', 'total', 'cost', 'fee', 
                                           'charge', 'balance', 'revenue', 'salary', 'wage']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.4)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
        
        # === RULE 4: Quantity/Count Fields → Often NON_SENSITIVE or SOX ===
        if any(kw in col_lower for kw in ['quantity', 'count', 'qty', 'number_of']):
            # Slightly boost SOX if in transactional context
            if any(kw in table_lower for kw in ['order', 'transaction', 'sale']):
                self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.2)
            # Reduce PII/SOC2 for quantity fields
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.5)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.4)
            if any(kw in col_lower for kw in ['billing', 'shipping', 'mailing', 'address']):
                # Likely PII (Address) - boost PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.4)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
            else:
                # Reduce PII for generic status/codes
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)

        # === RULE 8: Generic Metadata Penalties (Status, Date, ID) ===
        # CRITICAL: Overwrite previous boosts for these generic fields to prevent false positives
        
        # Status/Flag/Type -> Strong Penalty
        if any(kw in col_lower for kw in ['status', 'state', 'flag', 'type', 'mode', 'method', 'config', 'setting']):
            # Unless it's a specific financial status like 'payment_status' which might be mild SOX, but usually not critical
            self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.2)
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.1)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.1)

        # Dates (created, updated, etc) -> Moderate Penalty (exclude DOB)
        if any(kw in col_lower for kw in ['date', 'time', 'at', 'on', 'window', 'period']) and not any(kw in col_lower for kw in ['birth', 'dob']):
            self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.4) 
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.1)
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
        
        # IDs (invoice_id, order_id) -> Moderate Penalty (exclude Account/Tax/SSN/User)
        if (col_lower.endswith('_id') or col_lower == 'id' or col_lower.endswith('id')) and not any(kw in col_lower for kw in ['tax', 'ssn', 'account', 'card', 'user', 'customer', 'employee', 'member', 'patient']):
             self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.3)
             self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
             self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.2)
                
        # Boost SOX for financial codes (currency_code, tax_code)
        if any(kw in col_lower for kw in ['currency', 'tax', 'fiscal', 'invoice', 'payment']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.3)

        # === RULE 8: Currency and Financial Key Fields ===
        # Handle currency_key, currency_code, etc.
        if any(kw in col_lower for kw in ['currency', 'iso_code']):
            self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.2)
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.4)
            
        # Special case for financial keys (currency_key, account_key, etc.)
        if any(kw in col_lower for kw in ['_key', '_code']) and any(kw in col_lower for kw in ['currency', 'account', 'ledger', 'financial', 'fiscal']):
            self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.8)  # Strong boost for financial keys
            self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)  # Strongly reduce SOC2
            logger.debug(f"Applied financial key override for {col_name} (BOOST: SOX, REDUCE: SOC2)")
        
        # === RULE 9: Smart Address Context Analysis ===
        # Replaces hardcoded address rules with pattern-aware registry lookup
        # This automatically distinguishes between Physical Addresses (PII) and Network Addresses (SOC2)
        adjusted_scores = self._apply_smart_address_overrides(adjusted_scores, col_name)
        
        # === RULE 10: Name Fields ===
        # Names are strong PII indicators
        if any(kw in col_lower for kw in ['name', 'first_name', 'last_name', 'full_name', 'firstname', 'lastname']):
            # Exception: product_name, company_name, etc. are NOT PII
            if any(kw in col_lower for kw in ['product', 'company', 'business', 'organization', 'vendor', 
                                               'supplier', 'merchant', 'store', 'shop', 'brand', 'category',
                                               'item', 'service', 'package', 'plan']):
                # Not personal names
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
            else:
                # Personal names -> Strong PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.7)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.3)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.3)
        
        # === RULE 11: Description/Notes Fields ===
        # Description fields are usually non-sensitive metadata
        if any(kw in col_lower for kw in ['description', 'desc', 'notes', 'comment', 'remarks', 'memo']):
            # Exception: patient_notes, medical_description -> PII
            if any(kw in col_lower for kw in ['patient', 'medical', 'health', 'diagnosis', 'treatment']):
                # Medical context -> PII
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 1.3)
            else:
                # Generic descriptions -> Reduce all
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.4)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.5)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.4)
        
        # === RULE 12: Vendor/Supplier Fields ===
        # Vendor/supplier data is business data, not PII
        if any(kw in col_lower for kw in ['vendor', 'supplier', 'merchant', 'partner']):
            # Exception: vendor_contact, supplier_email -> Could be PII
            if any(kw in col_lower for kw in ['contact', 'email', 'phone', 'address', 'name']):
                # Contact info -> Keep as is (will be handled by other rules)
                pass
            else:
                # Generic vendor fields (vendor_id, vendor_code) -> Reduce PII
                self._reduce_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 0.3)
                # Boost SOX for vendor financial data
                if any(kw in col_lower for kw in ['id', 'code', 'number', 'account']):
                    self._boost_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 1.2)

        # === RULE 13: STRICT PII ENFORCEMENT (Fix for Misclassification) ===
        # Explicitly force PII for high-confidence PII fields to prevent SOC2/SOX override
        if any(kw in col_lower for kw in ['email', 'birth', 'dob', 'ssn', 'social_security', 'passport', 'license', 'gender', 'ethnicity', 'marital', 'address', 'city', 'state', 'zip', 'postal', 'country']):
            # EXCEPTION: Business/Vendor context is NOT PII
            if not any(kw in col_lower for kw in ['vendor', 'supplier', 'company', 'business', 'office', 'store', 'branch', 'merchant']):
                self._boost_category(adjusted_scores, 'PII', 'PII_PERSONAL_INFO', 2.0)
                self._reduce_category(adjusted_scores, 'SOC2', 'SOC2_SECURITY_DATA', 0.1)
                self._reduce_category(adjusted_scores, 'SOX', 'SOX_FINANCIAL_DATA', 0.1)
        
        # === RULE 5: Filter out very low scores (noise reduction) ===
        # Remove categories with confidence < 0.25 after adjustments
        adjusted_scores = {cat: score for cat, score in adjusted_scores.items() if score >= 0.25}
        
        return adjusted_scores
    
    def _boost_category(self, scores: Dict[str, float], policy_group: str, 
                       category_pattern: str, boost_factor: float):
        """Boost score for categories matching policy group or pattern"""
        for cat in list(scores.keys()):
            # Check metadata mapping first
            mapped_group = self._policy_group_by_category.get(cat.upper())
            
            if mapped_group == policy_group:
                 scores[cat] = min(0.95, scores[cat] * boost_factor)
                 continue
            
            # Fallback to pattern match (legacy/safety)
            cat_upper = cat.upper()
            if policy_group in cat_upper or category_pattern in cat_upper:
                scores[cat] = min(0.95, scores[cat] * boost_factor)
    
    def _reduce_category(self, scores: Dict[str, float], policy_group: str, 
                        category_pattern: str, reduction_factor: float):
        """Reduce score for categories matching policy group or pattern"""
        for cat in list(scores.keys()):
            # Check metadata mapping first
            mapped_group = self._policy_group_by_category.get(cat.upper())
            
            if mapped_group == policy_group:
                 scores[cat] = scores[cat] * reduction_factor
                 continue

            # Fallback to pattern match (legacy/safety)
            cat_upper = cat.upper()
            if policy_group in cat_upper or category_pattern in cat_upper:
                scores[cat] = scores[cat] * reduction_factor

    def _determine_table_category_governance_driven(self, table_scores: Dict[str, float], 
                                                  column_results: List[Dict[str, Any]]) -> Tuple[str, float, List[Dict[str, Any]]]:
        """
        Determine table category using governance rules only, supporting multi-label.
        
        CRITICAL: Only returns categories if table contains parent-level sensitive data 
        related to PII, SOX, or SOC2. Does NOT force or auto-assign categories - returns 
        only genuinely detected ones.
        """
        
        # REQUIREMENT: Only proceed if we have sensitive column evidence
        # This ensures we're not classifying tables without actual sensitive data
        if not column_results:
            logger.info("  → No sensitive columns detected - table is NON_SENSITIVE")
            return 'NON_SENSITIVE', 0.0, []
        
        # Aggregate all potential categories from table scores and column multi-label results
        # CRITICAL FIX: Only consider categories detected in columns. Do NOT include table_scores keys
        # to prevent forcing categories that are not supported by column evidence.
        all_categories = set()
        
        # Map category -> list of column scores
        col_scores_map = {}
        
        for col in column_results:
            # Check all detected categories for this column
            cats = col.get('detected_categories', [])
            if not cats and col.get('category') != 'NON_SENSITIVE':
                # Fallback for legacy/single-label
                cats = [{'category': col['category'], 'confidence': col['confidence']}]
                
            for cat_entry in cats:
                c_name = cat_entry['category']
                c_conf = cat_entry['confidence']
                if c_name == 'NON_SENSITIVE':
                    continue
                
                all_categories.add(c_name)
                if c_name not in col_scores_map:
                    col_scores_map[c_name] = []
                col_scores_map[c_name].append(c_conf)
        
        # CRITICAL: If no categories from columns, table is not sensitive
        if not all_categories:
            logger.info("  → No sensitive categories detected from columns - table is NON_SENSITIVE")
            return 'NON_SENSITIVE', 0.0, []
        
        # Evaluate each category - ONLY include if it's genuinely detected
        detected_categories = []
        
        for category in all_categories:
            table_score = table_scores.get(category, 0.0)
            column_scores = col_scores_map.get(category, [])
            
            # STRICT: Only consider column scores > 0.40 for parent-level detection
            # This ensures we only bubble up high-confidence sensitive findings
            valid_col_scores = [s for s in column_scores if s > 0.40]
            
            # REQUIREMENT: Must have at least ONE high-confidence column detection
            # to consider this category for table-level classification
            if not valid_col_scores:
                logger.debug(f"  → Skipping category '{category}' - no high-confidence column detections")
                continue
            
            if valid_col_scores:
                column_avg = sum(valid_col_scores) / len(valid_col_scores)
                # Progressive coverage boost: More columns = higher confidence
                if len(valid_col_scores) >= 5:
                    coverage_boost = 1.15  # 5+ columns = 15% boost
                elif len(valid_col_scores) >= 3:
                    coverage_boost = 1.10  # 3-4 columns = 10% boost
                else:
                    coverage_boost = 1.05  # 1-2 columns = 5% boost
                
                # Prioritize column evidence over table-level scores
                # This ensures we're driven by actual sensitive data, not just metadata
                combined_score = max(table_score, column_avg * coverage_boost)
            else:
                # No column evidence - skip this category
                continue
            
            combined_score = min(0.99, combined_score)
            
            # Threshold check (using default 0.40 - STRICT: Only genuine detections)
            thresh = self._category_thresholds.get(category, 0.40)
            
            # EXCLUDE GENERIC / NON-SENSITIVE CATEGORIES
            if category.upper() in ('NON_SENSITIVE', 'GENERAL', 'SYSTEM', 'METADATA', 'UNKNOWN'):
                continue
                
            # CRITICAL: Check if it maps to a sensitive policy group (PII/SOX/SOC2)
            # This is the core requirement - only return PII/SOX/SOC2 categories
            pg = self._map_category_to_policy_group(category)
            if pg not in {'PII', 'SOX', 'SOC2'}:
                logger.debug(f"  → Skipping category '{category}' - does not map to PII/SOX/SOC2 (maps to: {pg})")
                continue
            
            # STRICT validation: Require minimum confidence of 0.50 for parent-level classification
            # This ensures only high-quality detections are included
            if combined_score < 0.50:
                logger.debug(f"  → Skipping category '{category}' - confidence {combined_score:.3f} < 0.50")
                continue
            
            if combined_score >= thresh:
                detected_categories.append({
                    'category': category,
                    'confidence': combined_score,
                    'policy_group': pg,  # Track which policy group this belongs to
                    'column_count': len(valid_col_scores)  # Track evidence strength
                })
                logger.info(f"  ✓ Detected parent-level category: {category} ({pg}) - confidence: {combined_score:.3f}, columns: {len(valid_col_scores)}")
        
        # Sort by confidence
        detected_categories.sort(key=lambda x: x['confidence'], reverse=True)
        
        if detected_categories:
            best_category = detected_categories[0]['category']
            best_score = detected_categories[0]['confidence']
            logger.info(f"  → Table classification: {best_category} (confidence: {best_score:.3f}) with {len(detected_categories)} total categories")
        else:
            best_category = 'NON_SENSITIVE'
            best_score = 0.0
            logger.info("  → No parent-level sensitive categories detected - table is NON_SENSITIVE")
        
        # === ADDITIONAL VALIDATION: Detect Non-Sensitive Tables ===
        # Check if this appears to be a catalog/product/reference table
        # by analyzing column composition
        if detected_categories and column_results:
            non_sensitive_indicators = [
                'product', 'item', 'catalog', 'category', 'sku', 'inventory',
                'warehouse', 'location', 'department', 'store', 'brand',
                'type', 'status', 'code', 'description', 'quantity', 'price'
            ]
            
            # Count how many columns match non-sensitive patterns
            total_cols = len(column_results)
            non_sensitive_count = 0
            
            for col in column_results:
                col_name = col.get('column_name', '').lower()
                if any(ind in col_name for ind in non_sensitive_indicators):
                    non_sensitive_count += 1
            
            # If >70% of columns are non-sensitive indicators, likely a catalog table
            if total_cols > 0 and (non_sensitive_count / total_cols) > 0.7:
                logger.info(f"  → Detected likely non-sensitive table: {non_sensitive_count}/{total_cols} columns match catalog patterns")
                # Downgrade to NON_SENSITIVE
                best_category = 'NON_SENSITIVE'
                best_score = 0.0
                detected_categories = []
            
        return best_category, best_score, detected_categories

    def _classify_table_governance_driven(self, db: str, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Complete table classification using ONLY governance metadata"""
        try:
            schema = asset['schema']
            table = asset['table']
            full_name = f"{db}.{schema}.{table}"
            
            logger.info(f"Governance-driven classification for: {full_name}")
            
            # 1. Table-level classification using governance centroids
            table_context = self._build_table_context_from_metadata(db, schema, table)
            table_scores = self._compute_governance_scores(table_context)

            # 2. Column-level classification using governance patterns/keywords
            columns = self._get_columns_from_information_schema(db, schema, table)
            
            # BATCH OPTIMIZATION: Fetch samples for all columns in one query
            col_names = [c['COLUMN_NAME'] for c in columns]
            batch_samples = self._sample_table_values_batch(db, schema, table, col_names, limit=20)
            
            column_results = []
            
            for column in columns:
                col_name = column['COLUMN_NAME']
                # Pass pre-fetched samples to avoid N+1 queries
                col_samples = batch_samples.get(col_name, [])
                
                col_result = self._classify_column_governance_driven(
                    db, schema, table, column, pre_fetched_samples=col_samples
                )
                
                # CRITICAL: Only include sensitive columns (skip None results)
                if col_result is not None:
                    column_results.append(col_result)
            
            # 3. Determine final classification using governance rules
            table_category, confidence, table_detected_categories = self._determine_table_category_governance_driven(
                table_scores, column_results
            )
            
            # Map to policy group for UI
            policy_group = self._map_category_to_policy_group(table_category) if table_category != 'NON_SENSITIVE' else None
            
            # === MULTI-LABEL POLICY GROUPS ===
            # Extract ALL policy groups from detected categories (not just the top one)
            multi_label_policy_groups = []
            policy_group_confidences = {}  # Track confidence per policy group
            
            for detected_cat in table_detected_categories:
                cat_name = detected_cat['category']
                cat_conf = detected_cat['confidence']
                pg = self._map_category_to_policy_group(cat_name)
                
                # Only include PII/SOX/SOC2 policy groups
                if pg in {'PII', 'SOX', 'SOC2'}:
                    if pg not in multi_label_policy_groups:
                        multi_label_policy_groups.append(pg)
                        policy_group_confidences[pg] = cat_conf
                    else:
                        # If policy group already exists, keep the higher confidence
                        policy_group_confidences[pg] = max(policy_group_confidences[pg], cat_conf)
            
            # Sort policy groups by confidence (descending)
            multi_label_policy_groups.sort(key=lambda pg: policy_group_confidences.get(pg, 0), reverse=True)
            
            # Create comma-separated string for UI display
            policy_groups_str = ", ".join(multi_label_policy_groups) if multi_label_policy_groups else (policy_group if policy_group else "NON_SENSITIVE")
            
            # Calculate CIA scores based on policy group and category sensitivity
            # Default to Internal (C1, I1, A1)
            c, i, a = (1, 1, 1)
            label = "Internal"
            
            # Check for Public
            if not multi_label_policy_groups and not policy_group and table_category == 'NON_SENSITIVE':
                c, i, a = (0, 0, 0)
                label = "Public"
            else:
                # 1. Check for Confidential (C3) - Highest Priority
                is_confidential = False
                
                # SOX is always C3
                if 'SOX' in multi_label_policy_groups:
                    is_confidential = True
                
                # Check for Sensitive PII or Secrets in detected categories
                if not is_confidential:
                    for cat in table_detected_categories:
                        cat_upper = cat['category'].upper()
                        # Sensitive PII
                        if 'PII' in multi_label_policy_groups and any(x in cat_upper for x in ['SSN', 'TAX', 'PASSPORT', 'CREDIT', 'BANK', 'ACCOUNT', 'FINANCIAL', 'DRIVER', 'LICENSE']):
                            is_confidential = True
                            break
                        # Secrets/Keys
                        if any(x in cat_upper for x in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'AUTH', 'CREDENTIAL']):
                            is_confidential = True
                            break
                
                if is_confidential:
                    c, i, a = (3, 3, 3)
                    label = "Confidential"
                
                # 2. Check for Restricted (C2)
                elif 'PII' in multi_label_policy_groups or 'SOC2' in multi_label_policy_groups:
                    c, i, a = (2, 2, 2)
                    label = "Restricted"
            
            # Map numeric scores to descriptive labels
            c_labels = {0: 'Public', 1: 'Internal', 2: 'Restricted', 3: 'Confidential'}
            i_labels = {0: 'Low', 1: 'Standard', 2: 'High', 3: 'Critical'}
            a_labels = {0: 'Low', 1: 'Standard', 2: 'High', 3: 'Critical'}
            
            c_label_text = c_labels.get(c, 'Internal')
            i_label_text = i_labels.get(i, 'Standard')
            a_label_text = a_labels.get(a, 'Standard')

            label_emoji_map = {
                'Confidential': '🟥 Confidential',
                'Restricted': '🟧 Restricted',
                'Internal': '🟨 Internal',
                'Public': '🟩 Public',
            }
            color_map = {
                'Confidential': 'Red',
                'Restricted': 'Orange',
                'Internal': 'Yellow',
                'Public': 'Green',
            }
            label_emoji = label_emoji_map.get(label, label)
            color = color_map.get(label, 'Gray')

            # Calculate Overall Risk Level
            # High: Any CIA score is 3 (Confidential/Critical)
            # Medium: Any CIA score is 2 (Restricted/High)
            # Low: All CIA scores are 0 or 1 (Public/Internal/Low/Standard)
            risk_level = "Low"
            if c >= 3 or i >= 3 or a >= 3:
                risk_level = "High"
            elif c >= 2 or i >= 2 or a >= 2:
                risk_level = "Medium"
            
            risk_emoji_map = {
                "High": "🔴 High",
                "Medium": "🟠 Medium",
                "Low": "🟢 Low"
            }
            risk_emoji = risk_emoji_map.get(risk_level, risk_level)

            # Create comma-separated string of top categories for UI display
            multi_label_str = ", ".join([d['category'] for d in table_detected_categories[:3]]) if table_detected_categories else table_category

            return {
                'asset': asset,
                'category': policy_groups_str,
                'primary_policy_group': multi_label_policy_groups[0] if multi_label_policy_groups else policy_group,
                'policy_groups': multi_label_policy_groups,
                'policy_group_confidences': policy_group_confidences,
                'detected_categories': table_detected_categories,
                'multi_label_category': multi_label_str,
                'confidence': confidence,
                'columns': column_results,
                'business_context': table_context,
                'governance_categories_evaluated': list(table_scores.keys()),
                'status': 'COMPLETED',
                # UI Fields
                'confidence_pct': round(confidence * 100, 1),
                'confidence_tier': "Confident" if confidence > 0.75 else "Likely" if confidence > 0.5 else "Uncertain",
                'c': c, 'i': i, 'a': a,
                'c_label': c_label_text,
                'i_label': i_label_text,
                'a_label': a_label_text,
                'label': label,
                'label_emoji': label_emoji,
                'overall_risk': risk_level,
                'risk_emoji': risk_emoji,
                'color': color,
                'validation_status': 'REVIEW_REQUIRED',
                'issues': [],
                'sql_preview': f"-- Proposed Classification for {asset['full_name']}\n-- Category: {policy_groups_str}\n-- CIA: {c_label_text} / {i_label_text} / {a_label_text}\n\nALTER TABLE {asset['full_name']} SET TAG DATA_CLASSIFICATION_TAG = '{label}';\nALTER TABLE {asset['full_name']} SET TAG CONFIDENTIALITY_LEVEL = '{c_label_text}';\nALTER TABLE {asset['full_name']} SET TAG INTEGRITY_LEVEL = '{i_label_text}';\nALTER TABLE {asset['full_name']} SET TAG AVAILABILITY_LEVEL = '{a_label_text}';",
                'reasoning': [f"Detected policy groups: {policy_groups_str}"],
                'compliance': multi_label_policy_groups,
                'route': 'Governance-Driven (Metadata)',
                'multi_label_analysis': {
                    "detected_categories": multi_label_policy_groups,
                    "policy_group_confidences": policy_group_confidences,
                    "reasoning": {pg: f"{policy_group_confidences[pg]:.1%} confidence" for pg in multi_label_policy_groups}
                },
                'column_results': column_results
            }
            
        except Exception as e:
            logger.error(f"Governance-driven classification failed for {asset}: {e}")
            return {
                'asset': asset,
                'error': str(e),
                'status': 'FAILED'
            }

    def _run_governance_driven_pipeline(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simplified pipeline using ONLY governance table data"""
        results = []
        
        # Ensure governance metadata is loaded
        if not self._category_centroids:
            logger.info("Loading governance metadata for classification...")
            self._load_metadata_driven_categories()
        
        # DIAGNOSTIC LOGGING
        logger.info("=" * 80)
        logger.info("GOVERNANCE-DRIVEN PIPELINE DIAGNOSTICS")
        logger.info("=" * 80)
        logger.info(f"Assets to classify: {len(assets)}")
        logger.info(f"Available governance categories: {list(self._category_centroids.keys())}")
        
        # Check governance metadata status
        valid_centroids = len([c for c in self._category_centroids.values() if c is not None])
        logger.info(f"Valid centroids: {valid_centroids}/{len(self._category_centroids)}")
        
        total_keywords = sum(len(kws) for kws in getattr(self, '_category_keywords', {}).values())
        logger.info(f"Total keywords loaded: {total_keywords}")
        
        total_patterns = sum(len(pats) for pats in getattr(self, '_category_patterns', {}).values())
        logger.info(f"Total patterns loaded: {total_patterns}")
        
        policy_map = getattr(self, '_policy_group_by_category', {})
        logger.info(f"Policy mapping: {len(policy_map)} categories → PII/SOX/SOC2")
        if policy_map:
            logger.info(f"  Policy map: {policy_map}")
        else:
            logger.warning("  ⚠️ NO POLICY MAPPING! Categories will not map to PII/SOX/SOC2")
        
        logger.info("-" * 80)
        
        filtered_count = 0
        passed_count = 0
        
        for idx, asset in enumerate(assets, 1):
            asset_name = f"{asset.get('schema')}.{asset.get('table')}"
            logger.info(f"\n[{idx}/{len(assets)}] Classifying: {asset_name}")
            
            result = self._classify_table_governance_driven(db, asset)
            
            # Extract classification results
            cat = result.get('category')
            conf = result.get('confidence', 0.0)
            status = result.get('status')
            error = result.get('error')
            
            logger.info(f"  Result: category={cat}, confidence={conf:.3f}, status={status}")
            
            if error:
                logger.error(f"  ✗ Classification error: {error}")
                filtered_count += 1
                continue
            
            # Check filter criteria
            # Multi-label support: Pass if ANY detected category is sensitive
            # We trust detected_categories because we already filtered out NON_SENSITIVE in the classification step
            detected_cats = result.get('detected_categories', [])
            has_sensitive = len(detected_cats) > 0
            
            # Also respect the confidence threshold
            meets_confidence = conf >= 0.40
            
            logger.info(f"  Filter check:")
            logger.info(f"    • Has sensitive categories: {has_sensitive} (found: {[d['category'] for d in detected_cats]})")
            logger.info(f"    • Confidence >= 0.40: {meets_confidence} (actual: {conf:.3f})")
            
            # Filter for UI
            if has_sensitive and meets_confidence:
                results.append(result)
                passed_count += 1
                logger.info(f"  ✓ PASSED - Added to results")
            else:
                filtered_count += 1
                # Provide specific reason for filtering
                reasons = []
                if not has_sensitive:
                    reasons.append(f"No sensitive categories detected (primary: '{cat}')")
                if not meets_confidence:
                    reasons.append(f"Confidence {conf:.3f} < 0.40")
                
                logger.warning(f"  ✗ FILTERED OUT - {'; '.join(reasons)}")
        
        logger.info("=" * 80)
        logger.info("PIPELINE SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total assets processed: {len(assets)}")
        logger.info(f"Passed filter: {passed_count}")
        logger.info(f"Filtered out: {filtered_count}")
        logger.info(f"Results returned: {len(results)}")
        
        if len(results) == 0:
            logger.error("⚠️ NO ASSETS PASSED FILTER!")
            logger.error("Common causes:")
            logger.error("  1. Governance categories not mapping to PII/SOX/SOC2")
            logger.error("  2. Confidence thresholds too high (check DETECTION_THRESHOLD in governance tables)")
            logger.error("  3. Empty or missing governance metadata (keywords, patterns, descriptions)")
            logger.error("  4. Category mapping logic failing")
            logger.error("")
            logger.error("Run .agent/debug_classification.py for detailed diagnostics")
        
        logger.info("=" * 80)
        
        return results

# Singleton instance
ai_classification_pipeline_service = AIClassificationPipelineService()
