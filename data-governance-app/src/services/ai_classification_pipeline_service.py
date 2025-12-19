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
from collections import OrderedDict
import pandas as pd
import numpy as np  # type: ignore
import re
import time
import uuid  # For generating UUIDs in Python
from concurrent.futures import ThreadPoolExecutor

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:
    SentenceTransformer = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.services.authorization_service import authz
from src.services.ai_assistant_service import ai_assistant_service
from src.services.ai_classification_service import ai_classification_service
from src.services.discovery_service import DiscoveryService
from src.services.semantic_type_detector import semantic_type_detector
# AISensitiveDetectionService import moved to __init__
from src.services.governance_db_resolver import resolve_governance_db
from src.services.tagging_service import tagging_service
# View-based governance rules loader for data-driven classification
try:
    from src.services.governance_rules_loader_v2 import governance_rules_loader
except ImportError:
    governance_rules_loader = None  # type: ignore
    logger.warning("governance_rules_loader_v2 not available - using fallback logic")
try:
    from src.config import settings
except Exception:
    settings = None  # type: ignore

logger = logging.getLogger(__name__)

class SimpleLRUCache(OrderedDict):
    """Simple LRU Cache implementation using OrderedDict."""
    def __init__(self, max_size=1000):
        super().__init__()
        self.max_size = max_size

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.max_size:
            self.popitem(last=False)
            
    def get(self, key, default=None):
        if key in self:
            self.move_to_end(key)
            return super().__getitem__(key)
        return default

class AIClassificationPipelineService:
    """Service for managing the automatic AI classification pipeline functionality."""

    def __init__(self):
        """Initialize the classification pipeline service."""
        self.ai_service = ai_assistant_service
        self.discovery = DiscoveryService()
        
        # Lazy loaded services - moved out of __init__ to improve startup time
        self._sensitive_service = None
        self._keywords_initialized = False # Flag for lazy initialization
        
        # Disable governance glossary usage for semantic context (use only information_schema + config)
        try:
            setattr(self.ai_service, "use_governance_glossary", False)
        except Exception:
            pass
            
        # Local embedding backend (MiniLM) for governance-free detection
        self._embed_backend: str = 'none'
        self._embedder: Any = None
        self._embedding_cache = SimpleLRUCache(max_size=5000)  # Cache for embeddings (User Request #2)
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
        self._cache = SimpleLRUCache(max_size=2000)
        self._embed_cache = SimpleLRUCache(max_size=1000)
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
        
        # ========================================================================
        # VIEW-BASED DATA-DRIVEN CLASSIFICATION (New Architecture)
        # ========================================================================
        # Initialize governance rules loader for view-based classification
        self._rules_loader = governance_rules_loader if governance_rules_loader else None
        
        # View-based rule storage (loaded from Snowflake views)
        self._classification_rules: List[Dict[str, Any]] = []
        self._context_aware_rules: Dict[str, List[Dict[str, Any]]] = {}
        self._tiebreaker_keywords: Dict[str, List[Dict[str, Any]]] = {}
        self._address_context_indicators: List[Dict[str, Any]] = []
        self._exclusion_patterns: List[Dict[str, Any]] = []
        self._policy_group_keywords: Dict[str, List[Dict[str, Any]]] = {}
        self._category_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Flag to indicate if view-based rules are loaded
        self._view_based_rules_loaded: bool = False
        
        # Background Executor
        self._executor = ThreadPoolExecutor(max_workers=1)

        logger.info("AI Classification Pipeline Service initialized (Lightweight Mode)")

    def _get_governance_schema(self) -> str:
        """
        Returns the fully qualified governance schema name.
        Defaults to 'DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE' if not configured.
        """
        return "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"

    @property
    def sensitive_service(self):
        """Lazy initialization of the sensitive detection service."""
        if self._sensitive_service is None:
            try:
                from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
                self._sensitive_service = AISensitiveDetectionService(sample_size=200, min_confidence=0.3, use_ai=True)
                logger.info("AISensitiveDetectionService initialized lazily")
            except Exception as e:
                logger.warning(f"Failed to initialize AISensitiveDetectionService: {e}")
                self._sensitive_service = None
        return self._sensitive_service
        
    def _init_required_keywords(self):
        """Initialize required keywords in a background thread."""
        import threading
        
        def _init():
            try:
                db = self._get_active_database()
                if db:
                    self._ensure_required_keywords_exist(db)
            except Exception as e:
                logger.warning(f"Background initialization of required keywords failed: {e}")
        
        # Start initialization in background
        thread = threading.Thread(target=_init, daemon=True)
        thread.start()

    def _ensure_required_keywords_exist(self, db: str) -> None:
        """Ensure all required sensitive keywords exist in the database."""
        # DISABLED: Automatic population of keywords is now handled via SQL scripts (POPULATE_CORRECT_KEYWORDS.sql)
        # This prevents the application from overriding or cluttering the keywords table with hardcoded defaults.
        if not hasattr(self, '_required_keywords_checked'):
            self._required_keywords_checked = True
            logger.info("Skipping automatic population of required keywords (disabled by configuration)")
        return

    def _generate_context_variants(self, text: str) -> List[str]:
        """Generate multiple variants of the input text to improve semantic matching."""
        variants = [text]
        
        # Add variations with common prefixes/suffixes removed
        if '_' in text:
            variants.extend(text.split('_'))
        if ' ' in text:
            variants.extend(text.split(' '))
            
        # Add variations with common abbreviations
        replacements = [
            ('number', 'num', 'no', 'nr', '#'),
            ('identifier', 'id', 'ident'),
            ('date', 'dt'),
            ('amount', 'amt'),
            ('description', 'desc')
        ]
        
        for group in replacements:
            for term in group:
                if term in text:
                    for alt in group:
                        if alt != term:
                            variants.append(text.replace(term, alt))
        
        # Remove duplicates while preserving order
        seen = set()
        return [x for x in variants if not (x in seen or seen.add(x))]
    
    def _get_cached_embedding(self, text: str) -> np.ndarray:
        """Get or create embedding for a text with caching."""
        if not hasattr(self, '_embedding_cache') or self._embedding_cache is None:
            self._embedding_cache = SimpleLRUCache(max_size=5000)
            
        if text not in self._embedding_cache:
            # Normalize to ensure consistent cosine similarity
            self._embedding_cache[text] = self._embedder.encode(
                [text], 
                normalize_embeddings=True
            )[0]
        return self._embedding_cache[text]

    def _get_keyword_embedding(self, keyword: str) -> np.ndarray:
        """Get or create embedding for a keyword with caching."""
        return self._get_cached_embedding(keyword)
    
    def _deduplicate_matches(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate matches by keeping the highest confidence match per category."""
        if not matches:
            return []
            
        # Group by category
        by_category = {}
        for match in matches:
            cat = match['category']
            if cat not in by_category or by_category[cat]['confidence'] < match['confidence']:
                by_category[cat] = match
                
        # Sort by confidence descending
        return sorted(
            by_category.values(), 
            key=lambda x: x['confidence'], 
            reverse=True
        )
        

        
    def _load_active_governance_keywords(self, db: str) -> List[Dict]:
        """Load active keywords from governance tables once."""
        cache_key = f"active_keywords_{db}"
        
        # Check explicit keyword cache first
        if hasattr(self, '_keyword_cache') and cache_key in self._keyword_cache:
            return self._keyword_cache[cache_key]
            
        gov_db = self._get_governance_database(db)
        if not gov_db:
            return []
        
        query = f"""
            SELECT 
                sc.CATEGORY_NAME,
                sk.KEYWORD_STRING,
                sk.MATCH_TYPE
            FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS sk
            JOIN {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES sc
                ON sk.CATEGORY_ID = sc.CATEGORY_ID
            WHERE sk.IS_ACTIVE = TRUE
              AND sc.IS_ACTIVE = TRUE
              AND sk.MATCH_TYPE IN ('EXACT', 'CONTAINS', 'PARTIAL', 'REGEX')
        """
        
        try:
            rows = snowflake_connector.execute_query(query) or []
            
            keywords = []
            for row in rows:
                category = row.get('CATEGORY_NAME') or row.get('category_name')
                kw_str = row.get('KEYWORD_STRING') or row.get('keyword_string')
                match_type = row.get('MATCH_TYPE') or row.get('match_type')
                
                if category and kw_str:
                    keywords.append({
                        'category': category,
                        'keyword': str(kw_str).strip().lower(),
                        'original_keyword': kw_str,
                        'match_type': str(match_type or 'CONTAINS').upper()
                    })
            
            # Init cache if needed
            if not hasattr(self, '_keyword_cache'):
                self._keyword_cache = {}
            self._keyword_cache[cache_key] = keywords
            
            logger.info(f"Loaded {len(keywords)} active keywords from governance tables")
            return keywords
            
        except Exception as e:
            logger.error(f"Failed to load governance keywords: {e}")
            return []

    def _perform_exact_keyword_matching(self, text: str, active_keywords: List[Dict]) -> List[Dict]:
        """Strict exact/contains keyword matching from governance tables."""
        matches = []
        text_lower = text.lower()
        
        for keyword_data in active_keywords:
            keyword = keyword_data['keyword'] # already lower
            match_type = keyword_data['match_type']
            category = keyword_data['category']
            
            is_match = False
            
            if match_type == 'EXACT':
                # Word boundary exact match
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, text_lower, re.IGNORECASE):
                    is_match = True
            
            elif match_type == 'CONTAINS':
                # Simple substring match
                if keyword in text_lower:
                    is_match = True
            
            elif match_type == 'PARTIAL':
                # Word boundary at start
                pattern = r'\b' + re.escape(keyword)
                if re.search(pattern, text_lower, re.IGNORECASE):
                    is_match = True
            
            elif match_type == 'REGEX':
                # Regex pattern match
                try:
                    if re.search(keyword, text_lower, re.IGNORECASE):
                        is_match = True
                except re.error:
                    continue
            
            if is_match:
                matches.append({
                    'category': category,
                    'confidence': 1.0,  # Exact matches get 100% confidence
                    'match_type': match_type,
                    'keyword_string': keyword_data['original_keyword'],
                    'reason': f"Exact match ({match_type}): '{keyword_data['original_keyword']}'"
                })
        
        return matches

    def _exact_match_keyword_detection(self, db: str, text_context: str, active_rules_df: Optional[pd.DataFrame] = None, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        STRICT: Only check governance tables for Exact/Contains matches.
        Return early if any match found. Semantic search is split into a separate method.
        """
        try:
            # Force refresh if requested by clearing cache
            if force_refresh:
                if hasattr(self, '_keyword_cache'):
                    cache_key = f"active_keywords_{db}"
                    if cache_key in self._keyword_cache:
                        del self._keyword_cache[cache_key]
            
            keywords = self._load_active_governance_keywords(db)
            return self._perform_exact_keyword_matching(text_context, keywords)
        except Exception as e:
            logger.error(f"Error in exact match detection: {e}")
            return []

    def _generate_semantic_variants(self, text_context: str) -> List[str]:
        """Generate semantic variants for a given text context."""
        enhanced_context = f"column name: {text_context}"
        return [
            enhanced_context,
            enhanced_context.replace('number', 'no').replace('num', 'no'),
            enhanced_context.replace('social', 'ssn').replace('security', 'sec'),
            enhanced_context.replace('id', 'identifier').replace('num', 'number'),
        ]

    def _perform_semantic_classification(self, db: str, text_context: str, precomputed_embeddings: Optional[Dict[str, np.ndarray]] = None) -> List[Dict[str, Any]]:
        """
        Perform semantic classification using embeddings.
        This is Priority 2 - only called if Exact/Contains detection fails.
        """
        matches = []
        try:
            gov_db = self._get_governance_database(db)
            if not gov_db: return []
            
            cache_key = f'_gov_rules_cache_{gov_db}'
            if not hasattr(self, cache_key):
                # Trigger load via exact match if not loaded (rare case)
                self._exact_match_keyword_detection(db, "init_check")
            
            rules_data = getattr(self, cache_key, {})
            semantic_candidates = rules_data.get('semantic_candidates', [])

            if semantic_candidates and self._embedder and self._embed_backend == 'sentence-transformers':
                context_variants = self._generate_semantic_variants(text_context)
                
                max_scores = {}
                for variant in context_variants:
                    query_text = f"query: {variant}"
                    
                    # Use precomputed embedding if available, otherwise use cache
                    if precomputed_embeddings and query_text in precomputed_embeddings:
                        ctx_embedding = precomputed_embeddings[query_text]
                    else:
                        ctx_embedding = self._get_cached_embedding(query_text)
                
                for cand in semantic_candidates:
                    if 'embedding' not in cand or cand['embedding'] is None: 
                        continue
                        
                        score = float(np.dot(cand['embedding'], ctx_embedding))
                        
                        # Dynamic threshold
                        threshold = 0.82
                        if len(cand['keyword']) <= 3: threshold = 0.90
                        elif len(cand['keyword']) >= 10: threshold = 0.78
                        
                        if score > threshold:
                            if cand['keyword'] not in max_scores or score > max_scores[cand['keyword']]['score']:
                                max_scores[cand['keyword']] = {
                                    'score': score,
                                    'candidate': cand
                                }

                for kw, info in max_scores.items():
                    cand = info['candidate']
                    matches.append({
                        'category': cand['category'],
                        'confidence': info['score'],
                        'reason': f"Semantic match ({info['score']:.2f}): '{cand['keyword']}'",
                        'keyword_string': cand['keyword'],
                        'match_type': cand['match_type']
                    })

            # Deduplicate
            final_matches = []
            seen = {}
            for m in matches:
                if m['category'] not in seen or m['confidence'] > seen[m['category']]['confidence']:
                    seen[m['category']] = m
            final_matches = list(seen.values())
            final_matches.sort(key=lambda x: x['confidence'], reverse=True)
            
            return final_matches

        except Exception as e:
            logger.error(f"Error in semantic classification: {e}")
            return []

    def render_classification_pipeline(self) -> None:
        """Render the Automatic AI Classification Dashboard."""

        # Initialize metadata if needed
        if not self._embed_ready or not self._category_centroids:
            with st.spinner("Loading governance metadata..."):
                self._init_local_embeddings()

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

        # Layout for filters and actions
        f_col1, f_col2 = st.columns([3, 1])
        
        # 1. Category Filter in first column
        with f_col1:
            # Safe access to Category column even if df is empty
            if not df_results.empty and "Category" in df_results.columns:
                available_categories = sorted([str(c) for c in df_results["Category"].unique() if pd.notna(c) and str(c).strip() != ''])
            else:
                available_categories = []
                
            selected_categories = st.multiselect(
                "Filter by Category",
                options=available_categories,
                placeholder="All Categories (Select to filter)",
                help="Filter the results by specific sensitive categories (e.g., PII, SOX)."
            )
        
        # 2. Run Scan Button in second column
        with f_col2:
            if st.button("🚀 Run New Scan", type="primary", use_container_width=True):
                db = self._get_active_database()
                gov_db = self._get_governance_database(db) if db else None
                if db:
                    # Run pipeline and process all tables
                    self._run_classification_pipeline(db, gov_db)
                    # Flag that we need to save results
                    st.session_state["results_unsaved"] = True
                    st.rerun()
                else:
                    st.error("Please select a database first.")

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
        view_mode = "Table View"
        
        mask = pd.Series(True, index=df_results.index)
        
        # Local Filter: Category
        # Placed before global filters so they work together
        available_categories = sorted([str(c) for c in df_results["Category"].unique() if pd.notna(c) and str(c).strip() != ''])
        
        if selected_categories:
            mask = mask & df_results["Category"].isin(selected_categories)
        
        # Apply Global Filters
        global_filters = st.session_state.get("global_filters", {})
        global_schema = global_filters.get("schema")
        
        # Apply Schema Filter if present
        if global_schema and str(global_schema).strip().upper() not in {'', 'NONE', '(NONE)', 'NULL', 'ALL', '[]'}:
            # Handle potential list of schemas or single schema
            if isinstance(global_schema, list):
                if len(global_schema) > 0:
                    mask = mask & df_results["Schema"].isin(global_schema)
            else:
                mask = mask & (df_results["Schema"] == global_schema)
        
        df_filtered = df_results[mask].copy()

        # Log the filtered DataFrame for inspection
        logger.info(f"df_filtered columns: {df_filtered.columns.tolist()}")
        logger.info(f"df_filtered head:\n{df_filtered.head().to_string()}")

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
        
        # --- Risk Level Calculation ---
        # Critical: Contains any column with a high combined risk score
        # This is more reliable than string matching on a potentially missing 'Sensitivity' column
        # Weights: Confidential=3.0, Restricted/High=2.0, Internal/Medium=1.0, Public/Low=0.5
        def get_enhanced_sensitivity_weight(row):
            # Check 'Sensitivity' column first
            sensitivity = str(row.get('Sensitivity', '')).lower()
            if "confidential" in sensitivity: return 3.0
            if "restricted" in sensitivity or "high" in sensitivity: return 2.0
            if "internal" in sensitivity or "medium" in sensitivity: return 1.0

            # Fallback to 'Classification' column if 'Sensitivity' is not conclusive
            classification = str(row.get('Classification', '')).lower()
            if "confidential" in classification: return 3.0
            if "restricted" in classification or "high" in classification: return 2.0
            if "internal" in classification or "medium" in classification: return 1.0

            return 0.5  # Default low weight

        df_risk = df_filtered.copy()

        # Log the risk DataFrame for inspection
        logger.info(f"df_risk columns: {df_risk.columns.tolist()}")
        logger.info(f"df_risk head:\n{df_risk.head().to_string()}")
        
        # Calculate risk weights and aggregate per table
        df_risk['Risk_Weight'] = df_risk.apply(get_enhanced_sensitivity_weight, axis=1)
        
        # Also consider CIA scores if available
        if 'Confidentiality' in df_risk.columns and 'Integrity' in df_risk.columns and 'Availability' in df_risk.columns:
            # Convert string CIA to numeric (handling potential dashes or non-numeric)
            df_risk['C'] = pd.to_numeric(df_risk['Confidentiality'], errors='coerce').fillna(0)
            df_risk['I'] = pd.to_numeric(df_risk['Integrity'], errors='coerce').fillna(0)
            df_risk['A'] = pd.to_numeric(df_risk['Availability'], errors='coerce').fillna(0)
            
            # Calculate a composite CIA score (weighted sum)
            df_risk['CIA_Score'] = (df_risk['C'] * 1.5) + df_risk['I'] + (df_risk['A'] * 0.5)
            
            # Scale CIA score to be comparable with sensitivity weight
            max_cia_score = 10.0  # 3*1.5 + 3 + 3*0.5 = 9, rounded to 10 for headroom
            df_risk['CIA_Weight'] = (df_risk['CIA_Score'] / max_cia_score) * 3.0
            
            # Combine sensitivity weight and CIA weight
            df_risk['Combined_Risk'] = (df_risk['Risk_Weight'] * 0.6) + (df_risk['CIA_Weight'] * 0.4)
        else:
            # Fallback to just sensitivity weight if CIA not available
            df_risk['Combined_Risk'] = df_risk['Risk_Weight']
        
        # Aggregate risk scores per table
        table_risk_agg = df_risk.groupby('Table').agg({
            'Combined_Risk': 'max',  # Use max risk score for the table
            'Column': 'count',       # Count of columns in the table
            'Risk_Weight': 'sum'     # Sum of sensitivity weights
        }).reset_index()
        
        # Define risk classification rules with improved documentation and logging
        cat_series = df_risk['Category'].astype(str).str.upper() if 'Category' in df_risk.columns else pd.Series([''] * len(df_risk), index=df_risk.index)
        comp_series = df_risk['Compliance'].astype(str).str.upper() if 'Compliance' in df_risk.columns else pd.Series([''] * len(df_risk), index=df_risk.index)
        sens_series = df_risk['Sensitivity'].astype(str).str.upper() if 'Sensitivity' in df_risk.columns else pd.Series([''] * len(df_risk), index=df_risk.index)
        conf_series = df_risk['Confidentiality'].astype(str).str.upper() if 'Confidentiality' in df_risk.columns else pd.Series([''] * len(df_risk), index=df_risk.index)

        # Critical Risk: Any column that is PII, SOX, or Highly Confidential (C3)
        critical_col_mask = (
            cat_series.str.contains('PII', na=False) |
            comp_series.str.contains('SOX', na=False) |
            (conf_series.str.contains('3', na=False) & sens_series.str.contains('CONFIDENTIAL|RESTRICTED', na=False, regex=True))
        )
        
        # High Risk: SOC2, Restricted, or Medium-High Confidentiality (C2)
        # Only include columns that aren't already critical
        high_risk_col_mask = (
            comp_series.str.contains('SOC2', na=False) |
            (conf_series.str.contains('2', na=False) & ~critical_col_mask) |
            (sens_series.str.contains('RESTRICTED|MEDIUM|HIGH', na=False, regex=True) & ~critical_col_mask)
        )
        
        # Map columns to their risk levels
        df_risk['Risk_Level'] = 'Low'
        df_risk.loc[critical_col_mask, 'Risk_Level'] = 'Critical'
        df_risk.loc[high_risk_col_mask & ~critical_col_mask, 'Risk_Level'] = 'High'
        
        # Get unique tables by risk level
        critical_tables = set(df_risk[df_risk['Risk_Level'] == 'Critical']['Table'].unique())
        high_risk_tables = set(df_risk[df_risk['Risk_Level'] == 'High']['Table'].unique()) - critical_tables
        
        # Calculate column counts for each risk level
        critical_col_count = int(critical_col_mask.sum())
        high_risk_col_count = int(high_risk_col_mask.sum())
        
        # Calculate table counts
        critical_table_count = len(critical_tables)
        high_table_count = len(high_risk_tables)
        
        # Log the classification results for debugging
        logger.info(f"Risk Classification Summary:")
        logger.info(f"- Critical Tables: {critical_table_count} tables, {critical_col_count} columns")
        logger.info(f"- High Risk Tables: {high_table_count} tables, {high_risk_col_count} columns")

        # Initialize top_tables with default empty DataFrame
        top_tables = pd.DataFrame(columns=['Risk Score', 'Sensitive Columns'])

        # If we have data, calculate top tables
        if not table_risk_agg.empty:
            # Sort by risk score in descending order and get top 10
            top_tables = table_risk_agg.sort_values('Combined_Risk', ascending=False).head(10)
            # Select and rename columns for display
            top_tables = top_tables[['Combined_Risk', 'Column']]
            top_tables.columns = ['Risk Score', 'Sensitive Columns']

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
                delta=f"{high_risk_col_count} columns",
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
            
            if critical_col_count > 0 or high_risk_col_count > 0:
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
                # Handle comma-separated values (e.g. from multi-label columns)
                processed_items = set()
                for item in items:
                    # Filter out None/empty
                    if not item: continue
                    for sub_item in str(item).split(','):
                        clean_item = sub_item.strip().upper()
                        if clean_item and clean_item not in ('NONE', 'UNKNOWN', 'NAN'):
                            processed_items.add(clean_item)
                
                # Sort for consistent display order: PII, SOX, SOC2
                sorted_items = sorted(list(processed_items), key=lambda x: (
                    0 if 'PII' in x else 
                    1 if 'SOX' in x else 
                    2 if 'SOC2' in x else 3, 
                    x
                ))
                
                for item_upper in sorted_items:
                    if 'PII' in item_upper:
                        badges.append('🟣 PII')
                    elif 'SOX' in item_upper:
                        badges.append('🟢 SOX')
                    elif 'SOC2' in item_upper:
                        badges.append('🔵 SOC2')
                    else:
                        badges.append(item_upper)
                
                return ' | '.join(badges) if badges else '-'
            
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
                grouped[['Schema', 'Table', 'Sensitive Cols', 'Category', 'Confidentiality', 'Integrity', 'Availability']],
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
                # Clear previous input state if exists to ensure "normal" fresh start
                for k in ["kw_input_main", "kw_cat_main", "kw_match_main", "kw_weight_main"]:
                    if k in st.session_state:
                        del st.session_state[k]
            
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
                
                # ========================================================================
                # FETCH ALL COLUMNS FROM INFORMATION_SCHEMA (Once, shared by all sections)
                # ========================================================================
                # This ensures we check EVERY column in the actual table, not just old results
                all_table_columns = []
                db = self._get_active_database()
                
                if db:
                    try:
                        # Parse table name to extract schema and table
                        table_parts = selected_table.split('.')
                        if len(table_parts) == 3:
                            db_name = table_parts[0]
                            schema_name = table_parts[1]
                            table_name = table_parts[2]
                        elif len(table_parts) == 2:
                            db_name = db
                            schema_name = table_parts[0]
                            table_name = table_parts[1]
                        else:
                            # Single name - need to infer schema
                            db_name = db
                            if not table_details.empty and 'Table' in table_details.columns:
                                full_table = table_details['Table'].iloc[0]
                                if '.' in full_table:
                                    parts = full_table.split('.')
                                    schema_name = parts[-2] if len(parts) >= 2 else 'PUBLIC'
                                else:
                                    schema_name = 'PUBLIC'
                            else:
                                schema_name = 'PUBLIC'
                            table_name = selected_table
                        
                        # Query INFORMATION_SCHEMA for ALL columns
                        columns_query = f"""
                            SELECT COLUMN_NAME, DATA_TYPE
                            FROM {db_name}.INFORMATION_SCHEMA.COLUMNS
                            WHERE TABLE_SCHEMA = '{schema_name}'
                              AND TABLE_NAME = '{table_name}'
                            ORDER BY ORDINAL_POSITION
                        """
                        
                        logger.info(f"Fetching ALL columns for {schema_name}.{table_name} from INFORMATION_SCHEMA")
                        columns_result = snowflake_connector.execute_query(columns_query)
                        
                        if columns_result and len(columns_result) > 0:
                            all_table_columns = [row['COLUMN_NAME'] for row in columns_result]
                            logger.info(f"✅ Successfully fetched {len(all_table_columns)} columns from INFORMATION_SCHEMA")
                        else:
                            logger.warning(f"⚠️ INFORMATION_SCHEMA returned no columns for {schema_name}.{table_name}")
                            # Fallback to table_details
                            if not table_details.empty and 'Column' in table_details.columns:
                                all_table_columns = table_details['Column'].unique().tolist()
                                logger.warning(f"Falling back to {len(all_table_columns)} columns from classification history")
                            else:
                                all_table_columns = []
                                logger.error("No columns available from any source!")
                    
                    except Exception as e:
                        logger.error(f"❌ Failed to fetch columns from INFORMATION_SCHEMA: {e}")
                        logger.exception("Full error details:")
                        # Fallback to table_details
                        if not table_details.empty and 'Column' in table_details.columns:
                            all_table_columns = table_details['Column'].unique().tolist()
                            logger.warning(f"Falling back to {len(all_table_columns)} columns from classification history")
                        else:
                            all_table_columns = []
                            logger.error("No columns available from any source!")
                else:
                    logger.error("No database connection available")
                    # Fallback to table_details
                    if not table_details.empty and 'Column' in table_details.columns:
                        all_table_columns = table_details['Column'].unique().tolist()
                        logger.warning(f"No DB connection - using {len(all_table_columns)} columns from classification history")
                    else:
                        all_table_columns = []
                
                # Display column fetch status for transparency
                if all_table_columns:
                    st.caption(f"📊 Analyzing {len(all_table_columns)} columns from {selected_table}")
                else:
                    st.warning("⚠️ No columns found for this table. The table may not exist or you may not have access.")
                
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


                # Inline Editing for Drill-Down
                # Fetch Active Classification Rules (Logic moved up to populate dropdowns)
                rules_df = pd.DataFrame()
                try:
                    schema_fqn = self._resolve_governance_schema()
                    
                    # First, verify the schema and tables exist
                    try:
                        check_query = f"SHOW TABLES LIKE 'SENSITIVITY_CATEGORIES' IN SCHEMA {schema_fqn}"
                        check_result = snowflake_connector.execute_query(check_query)
                        if not check_result:
                            logger.warning(f"SENSITIVITY_CATEGORIES table not found in {schema_fqn}")
                            st.warning(f"⚠️ Governance tables not found in schema: {schema_fqn}")
                            st.info("💡 Run 'Refresh governance (seed/update)' button to create the required tables.")
                            rules_df = pd.DataFrame()  # Empty dataframe
                            raise ValueError("Governance tables not found")
                    except ValueError:
                        raise  # Re-raise to skip the main query
                    except Exception as check_err:
                        logger.warning(f"Could not verify table existence: {check_err}")
                        # Continue anyway - the main query will fail if tables don't exist
                    
                    query = f"""
                        SELECT 
                            sc.category_id,
                            sc.category_name,
                            sk.keyword_string,
                            sk.match_type
                        FROM {schema_fqn}.SENSITIVITY_CATEGORIES sc
                        LEFT JOIN {schema_fqn}.SENSITIVE_KEYWORDS sk
                            ON sc.category_id = sk.category_id
                        WHERE sc.IS_ACTIVE = TRUE
                          AND sk.IS_ACTIVE = TRUE
                    """
                    
                    logger.info(f"Executing Active Rules query with schema: {schema_fqn}")
                    logger.debug(f"Full query: {query}")
                    
                    rules_data = snowflake_connector.execute_query(query)
                    
                    if rules_data:
                        rules_df = pd.DataFrame(rules_data)
                        # Ensure columns are standardized for _exact_match_keyword_detection
                        # It expects: CATEGORY/CATEGORY_NAME, KEYWORD/KEYWORD_STRING, MATCH_TYPE
                        rules_df.rename(columns={
                            'CATEGORY_NAME': 'Category', 
                            'KEYWORD_STRING': 'Keyword',
                            'MATCH_TYPE': 'Match Type'
                        }, inplace=True)
                except ValueError:
                    # Already handled above with user message
                    pass
                except Exception as e:
                    logger.error(f"Failed to fetch active rules: {e}")
                    logger.error(f"Schema FQN used: {schema_fqn if 'schema_fqn' in locals() else 'NOT SET'}")
                    logger.error(f"Query attempted: {query if 'query' in locals() else 'NOT GENERATED'}")
                    
                    # Show error to user with helpful context
                    st.error(f"❌ Failed to load Active Classification Rules from {schema_fqn if 'schema_fqn' in locals() else 'Unknown Schema'}")
                    
                    # Provide detailed troubleshooting
                    with st.expander("🔍 Troubleshooting Details", expanded=True):
                        st.markdown(f"**Error:** `{str(e)}`")
                        st.markdown(f"**Looking for table:** `{schema_fqn if 'schema_fqn' in locals() else 'Unknown'}.SENSITIVITY_CATEGORIES`")
                        
                        # Check if it's a table not found error
                        error_str = str(e).lower()
                        if 'does not exist' in error_str or 'not found' in error_str or 'invalid' in error_str:
                            st.markdown("### ⚠️ Table Not Found")
                            st.markdown("**Possible causes:**")
                            st.markdown("1. **Wrong Database Selected:** The table exists in a different database")
                            st.markdown("2. **Schema Not Created:** The `DATA_CLASSIFICATION_GOVERNANCE` schema doesn't exist")
                            st.markdown("3. **Table Not Created:** The `SENSITIVITY_CATEGORIES` table hasn't been created yet")
                            
                            st.markdown("### 🔧 Solutions:")
                            st.markdown("**Option 1: Check Your Database Selection**")
                            st.code(f"Current: {schema_fqn if 'schema_fqn' in locals() else 'Unknown'}")
                            st.markdown("- Use the **Global Filters** sidebar to select the correct database")
                            st.markdown("- Make sure you select the database that contains your governance tables")
                            
                            st.markdown("**Option 2: Verify Table Location in Snowflake**")
                            st.code("""
-- Run this in Snowflake to find your table:
SHOW TABLES LIKE 'SENSITIVITY_CATEGORIES' IN ACCOUNT;

-- Or check a specific database:
SHOW TABLES LIKE 'SENSITIVITY_CATEGORIES' IN DATABASE <YOUR_DATABASE>;
                            """)
                            
                            st.markdown("**Option 3: Create Governance Tables**")
                            st.markdown("If the tables don't exist, click the **'Refresh governance (seed/update)'** button to create them.")
                        else:
                            st.markdown("**Unexpected error - please check:**")
                            st.markdown("- Database permissions")
                            st.markdown("- Network connectivity")
                            st.markdown("- Snowflake session validity")
                    
                    rules_df = pd.DataFrame()  # Empty dataframe to prevent further errors

                # Inline Editing for Drill-Down
                base_categories = sorted(list(self._category_thresholds.keys())) if self._category_thresholds else ["PII", "SOX", "SOC2", "INTERNAL"]
                
                # ========================================================================
                # CRITICAL UPDATE: Use same detection logic as "Detected Columns" section
                # ========================================================================
                # Instead of using old classification results from df_filtered,
                # run real-time detection using _exact_match_keyword_detection()
                # This ensures Table Drill-Down shows the SAME results as Detected Columns
                
                # Get the database for detection
                db = self._get_active_database()
                
                # ========================================================================
                # CRITICAL FIX: Fetch ALL Columns from Snowflake (Not Just Old Results)
                # ========================================================================
                # Problem: If we only loop through `table_details['Column']`, we miss columns
                # that weren't in previous classification results
                # Solution: Query INFORMATION_SCHEMA to get COMPLETE column list
                
                # Initialize identifiers
                schema_name = "PUBLIC"
                table_name = selected_table
                all_column_names = []
                
                try:
                    # Parse table identifiers robustly
                    # Handle DB.SCHEMA.TABLE or SCHEMA.TABLE or TABLE
                    parts = selected_table.split('.')
                    if len(parts) >= 3:
                        schema_name = parts[-2]
                        table_name = parts[-1]
                    elif len(parts) == 2:
                        schema_name = parts[0]
                        table_name = parts[1]
                    elif not table_details.empty:
                        # Try to get from existing data if available
                        if 'Schema' in table_details.columns:
                             val = str(table_details['Schema'].iloc[0])
                             if val and val.lower() != 'unknown':
                                 schema_name = val
                        elif 'Table' in table_details.columns:
                             t_val = str(table_details['Table'].iloc[0])
                             if '.' in t_val:
                                 schema_name = t_val.split('.')[1]
                    
                    # Query Snowflake for ALL columns in this table
                    columns_query = f"""
                        SELECT COLUMN_NAME, DATA_TYPE, COMMENT
                        FROM {db}.INFORMATION_SCHEMA.COLUMNS
                        WHERE TABLE_SCHEMA = '{schema_name}'
                          AND TABLE_NAME = '{table_name}'
                        ORDER BY ORDINAL_POSITION
                    """
                    logger.info(f"Fetching ALL columns for {schema_name}.{table_name}")
                    columns_result = snowflake_connector.execute_query(columns_query)
                    
                    if columns_result:
                        all_column_names = [row['COLUMN_NAME'] for row in columns_result]
                        logger.info(f"Found {len(all_column_names)} columns in {table_name}")
                    else:
                        logger.warning(f"No columns found for {table_name}, falling back to table_details")
                        all_column_names = table_details['Column'].unique().tolist()
                except Exception as e:
                    logger.error(f"Failed to fetch columns from INFORMATION_SCHEMA: {e}")
                    logger.warning("Falling back to columns from table_details")
                    all_column_names = table_details['Column'].unique().tolist()
                
                # Build fresh detection results for this table
                fresh_table_details = []
                
                if db and not rules_df.empty and all_column_names:
                    # For each column in the ACTUAL TABLE (not just old results), run detection
                    # For each column in the ACTUAL TABLE (not just old results), run detection
                    for col_name in all_column_names:
                        # Run keyword detection for this column (same logic as Detected Columns)
                        # OPTIMIZATION: Do not pass active_rules_df here, rely on internal caching
                        # inside _exact_match_keyword_detection to avoid re-processing rules for every column.
                        matches = self._exact_match_keyword_detection(db, col_name)
                        
                        if matches:
                            # Aggregate all categories for this column
                            categories = [match['category'] for match in matches]
                            match_types = [match['match_type'] for match in matches]
                            confidences = [match['confidence'] for match in matches]
                            
                            # MULTI-CATEGORY SUPPORT: Show ALL categories (comma-separated)
                            # This matches the behavior of "Detected Columns (Multi-Category)" section
                            all_categories = ', '.join(sorted(set(categories)))
                            
                            # Map to policy group for compliance
                            policy_groups = [self._map_category_to_policy_group(cat) for cat in categories]
                            unique_policy_groups = sorted(set([pg for pg in policy_groups if pg and pg != 'NON_SENSITIVE']))
                            compliance = ', '.join(unique_policy_groups) if unique_policy_groups else 'None'
                            
                            # Determine sensitivity based on policy groups
                            if 'PII' in unique_policy_groups or 'SOX' in unique_policy_groups:
                                sensitivity = 'CRITICAL'
                            elif 'SOC2' in unique_policy_groups:
                                sensitivity = 'HIGH'
                            else:
                                sensitivity = 'MEDIUM'
                            
                            # CIA values based on sensitivity
                            if sensitivity == 'CRITICAL':
                                c, i, a = 3, 3, 3
                            elif sensitivity == 'HIGH':
                                c, i, a = 2, 2, 2
                            else:
                                c, i, a = 1, 1, 1
                            
                            fresh_table_details.append({
                                'Schema': schema_name,
                                'Table': table_name,
                                'Column': col_name,
                                'All Categories': all_categories,  # Read-only: ALL detected categories
                                'Primary Category': categories[0] if categories else 'Unknown',  # Editable: for keyword management
                                'Sensitivity': sensitivity,
                                'Compliance': compliance,
                                'Confidentiality': c,
                                'Integrity': i,
                                'Availability': a
                            })
                        else:
                            # Column not detected as sensitive
                            # Check if it exists in original data for fallback values
                            original_row = table_details[table_details['Column'] == col_name]
                            if not original_row.empty:
                                # Use original data
                                orig_cat = original_row.iloc[0].get('Category', 'NON_SENSITIVE')
                                fresh_table_details.append({
                                    'Schema': schema_name,
                                    'Table': table_name,
                                    'Column': col_name,
                                    'All Categories': orig_cat,
                                    'Primary Category': orig_cat,
                                    'Sensitivity': original_row.iloc[0].get('Sensitivity', 'LOW'),
                                    'Compliance': original_row.iloc[0].get('Compliance', 'None'),
                                    'Confidentiality': original_row.iloc[0].get('Confidentiality', 1),
                                    'Integrity': original_row.iloc[0].get('Integrity', 1),
                                    'Availability': original_row.iloc[0].get('Availability', 1)
                                })
                            else:
                                # New column not in old results - add with default values
                                fresh_table_details.append({
                                    'Schema': schema_name,
                                    'Table': table_name,
                                    'Column': col_name,
                                    'All Categories': 'NON_SENSITIVE',
                                    'Primary Category': 'NON_SENSITIVE',
                                    'Sensitivity': 'LOW',
                                    'Compliance': 'None',
                                    'Confidentiality': 1,
                                    'Integrity': 1,
                                    'Availability': 1
                                })
                
                # Create fresh DataFrame with detection results
                if fresh_table_details:
                    table_details = pd.DataFrame(fresh_table_details)
                else:
                    # Fallback to original data if detection failed
                    logger.warning(f"No fresh detection results for {selected_table}, using original data")
                    # Ensure the new columns exist in fallback
                    if 'All Categories' not in table_details.columns:
                        table_details['All Categories'] = table_details.get('Category', 'Unknown')
                    if 'Primary Category' not in table_details.columns:
                        table_details['Primary Category'] = table_details.get('Category', 'Unknown')
                
                # Get current values from the table
                current_values = table_details["Primary Category"].dropna().unique().tolist()
                
                # Get categories from Active Rules (DB)
                # Handle both uppercase (from Snowflake) and renamed columns
                if not rules_df.empty:
                    if 'CATEGORY' in rules_df.columns:
                        db_categories = sorted(rules_df["CATEGORY"].unique().tolist())
                    elif 'Category' in rules_df.columns:
                        db_categories = sorted(rules_df["Category"].unique().tolist())
                    else:
                        db_categories = []
                else:
                    db_categories = []
                
                # Combine all sources for the dropdown options
                # Parse all individual categories from 'All Categories' column to ensure they are options
                detected_cats_set = set()
                for cats_str in table_details['All Categories'].dropna():
                    for c in str(cats_str).split(','):
                        c_clean = c.strip()
                        if c_clean:
                            detected_cats_set.add(c_clean)
                            
                extended_options = sorted(list(set(base_categories + db_categories + [str(x) for x in current_values if x] + list(detected_cats_set))))

                # Apply formatting AFTER creating fresh data
                table_details['Compliance'] = table_details['Compliance'].apply(drill_badge_compliance)
                table_details['Sensitivity'] = table_details['Sensitivity'].apply(drill_badge_sensitivity)
                table_details['Confidentiality'] = table_details['Confidentiality'].apply(format_confidentiality_val)
                table_details['Integrity'] = table_details['Integrity'].apply(format_integrity_val)
                table_details['Availability'] = table_details['Availability'].apply(format_availability_val)

                # Display table details in a data editor

                edited_df = st.data_editor(
                    table_details[['Column', 'All Categories', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability']],
                    use_container_width=True,
                    hide_index=True,
                    key="drill_down_editor",
                    # Disable direct editing in the grid to encourage using the cleaner form
                    disabled=['Column', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability'],
                    column_config={
                        "All Categories": st.column_config.TextColumn(
                            "Active Categories",
                            help="Current categories detected or assigned. Edit directly to update.",
                            width="large"
                        )
                    }
                )

                # -------------------------------------------------------------------------
                # INLINE EDITING CONFIRMATION FLOW
                # -------------------------------------------------------------------------
                if not edited_df.equals(table_details[['Column', 'All Categories', 'Sensitivity', 'Confidentiality', 'Integrity', 'Availability']]):
                    # Identify changes
                    try:
                        # Find changed rows by index (assuming index alignment is preserved)
                        diff_indices = []
                        for idx in edited_df.index:
                            old_cats = str(table_details.loc[idx, 'All Categories']).strip()
                            new_cats = str(edited_df.loc[idx, 'All Categories']).strip()
                            if old_cats != new_cats:
                                diff_indices.append(idx)
                        
                        if diff_indices:
                            st.markdown("### 📝 Unsaved Changes")
                            
                            for idx in diff_indices:
                                row_col = edited_df.loc[idx, 'Column']
                                old_val = str(table_details.loc[idx, 'All Categories'])
                                new_val = str(edited_df.loc[idx, 'All Categories'])
                                
                                # Show confirm/cancel for this specific row change
                                c_conf1, c_conf2, c_conf3 = st.columns([3, 1, 1])
                                with c_conf1:
                                    st.info(f"**{row_col}**: `{old_val}` ➔ `{new_val}`")
                                with c_conf2:
                                    if st.button("✅", key=f"btn_conf_row_{idx}", help="Confirm and Save Changes"):
                                        try:
                                            with st.spinner(f"Saving changes for {row_col}..."):
                                                # Parse lists
                                                old_list = set([x.strip() for x in old_val.split(',') if x.strip()])
                                                new_list = set([x.strip() for x in new_val.split(',') if x.strip()])
                                                
                                                to_add = new_list - old_list
                                                to_remove = old_list - new_list
                                                
                                                audit_logs = []
                                                # ADD
                                                for cat in to_add:
                                                    if self.upsert_sensitive_keyword(row_col, cat, "CONTAINS"):
                                                        audit_logs.append(f"Added **{cat}**")
                                                # REMOVE
                                                for cat in to_remove:
                                                    if self.delete_sensitive_keyword(row_col, cat):
                                                        audit_logs.append(f"Removed **{cat}**")
                                                
                                                if audit_logs:
                                                    st.success(f"Updated {row_col}!")
                                                    for alg in audit_logs:
                                                        st.caption(f"✅ {alg}")
                                                    time.sleep(1)
                                                    st.rerun()
                                                else:
                                                    st.warning("No valid changes applied (check valid categories).")
                                        except Exception as row_err:
                                            logger.error(f"Error processing row change: {row_err} - Row data: {row_col}")
                                            st.error(f"Error processing row change: {row_err}")

                                with c_conf3:
                                    if st.button("", key=f"btn_canc_row_{idx}", help="Cancel Changes"):
                                        st.rerun()
                                        
                    except Exception as e:
                        st.error(f"Error processing changes: {e}")


                # Add Keyword Button (Drill-Down View)
                if st.button(" Add Keyword", key="btn_add_kw_drill_btm"):
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
                    c1, c2, c3, c4, c5 = st.columns([1,1,1,1,2])
                    with c1:
                        t_class = st.selectbox("Classification", ["Public", "Internal", "Restricted", "Confidential"], index=def_class_ix, key="tag_class")
                    with c2:
                        t_conf = st.selectbox("Confidentiality (C)", ["0", "1", "2", "3"], index=def_c_ix, key="tag_conf")
                    with c3:
                        t_int = st.selectbox("Integrity (I)", ["0", "1", "2", "3"], index=def_i_ix, key="tag_int")
                    with c4:
                        t_avail = st.selectbox("Availability (A)", ["0", "1", "2", "3"], index=def_a_ix, key="tag_avail")
                    with c5:
                        compliance_frameworks = st.multiselect("Compliance Frameworks", 
                            ["PII", "SOX", "SOC2"],
                            default=[],
                            key="tag_compliance")
                        
                    tags_to_apply = {
                        "DATA_CLASSIFICATION": t_class,
                        "CONFIDENTIALITY_LEVEL": f"C{t_conf}",
                        "INTEGRITY_LEVEL": f"I{t_int}",
                        "AVAILABILITY_LEVEL": f"A{t_avail}"
                    }
                    
                    # Add compliance frameworks if any selected
                    if compliance_frameworks:
                        tags_to_apply["COMPLIANCE_FRAMEWORKS"] = ",".join(compliance_frameworks)

                with tag_tab1:
                    if st.button("Generate SQL", key="btn_gen_sql"):
                        schema_name = table_details['Schema'].iloc[0] if not table_details.empty else "TEST_DATA"
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
                        schema_name = table_details['Schema'].iloc[0] if not table_details.empty else "TEST_DATA"
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


    def _check_keyword_exists(self, keyword: str) -> bool:
        """Check if a keyword exists in the SENSITIVE_KEYWORDS table.
        
        Args:
            keyword: The keyword to check
            
        Returns:
            bool: True if the keyword exists, False otherwise
        """
        try:
            schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
            gov_db = resolve_governance_db()
            if gov_db:
                schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
            
            # Check if keyword exists in any category
            result = snowflake_connector.execute_query(
                f"""
                SELECT 1 
                FROM {schema_fqn}.SENSITIVE_KEYWORDS 
                WHERE LOWER(KEYWORD_STRING) = LOWER(%(k)s)
                LIMIT 1
                """,
                {"k": keyword}
            )
            
            return bool(result and len(result) > 0)
            
        except Exception as e:
            logger.error(f"Error checking if keyword exists: {e}")
            return False

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
                categories = sorted(list(self._category_thresholds.keys())) if self._category_thresholds else ["PII", "SOX", "SOC2", "INTERNAL"]
                target_category = st.selectbox("Category", categories, key=f"kw_cat_{context_key}")
            with c3:
                match_type = st.selectbox("Match Type", ["CONTAINS", "EXACT"], key=f"kw_match_{context_key}")
            with c4:
                st.write("")
                st.write("")
                st.write("")

            # Add sensitivity weight slider
            sensitivity_weight = st.slider(
                "Sensitivity Weight", 
                min_value=0.0, 
                max_value=10.0, 
                value=0.8, 
                step=0.1,
                help="Higher values indicate more sensitive data (0.0 = lowest, 10.0 = highest)",
                key=f"kw_weight_{context_key}"
            )

            col_act1, col_act2 = st.columns([1, 4])
            with col_act1:
                # CONFIRM ACTION: upsert/save
                # User Request: "Enable keyword addition only upon clicking 'Add Keywords'" -> explicit label
                btn_label = "Add Keyword" if current_action == 'add' else "Update Keyword"
                if st.button(btn_label, key=f"btn_save_{context_key}", type="primary", help="Confirm"):
                    if new_keyword and target_category:
                        with st.spinner("Saving..."):
                            # ALWAYS use upsert - updates if exists, inserts if not
                            success = self.upsert_sensitive_keyword(
                                keyword=new_keyword, 
                                category_name=target_category, 
                                match_type=match_type,
                                sensitivity_weight=sensitivity_weight
                            )
                                
                            if success:
                                st.success(f"✅ Successfully saved '{new_keyword}' (Weight: {sensitivity_weight})!")
                                st.session_state[action_key] = None
                                st.rerun()
                            else:
                                st.error("❌ Failed to save keyword. Check logs for details.")
                    else:
                        st.warning("⚠️ Please enter a keyword and select a category.")
            
            with col_act2:
                # CANCEL ACTION: clear state
                if st.button("❌", key=f"btn_cancel_final_{context_key}", help="Cancel"):
                    st.session_state[action_key] = None
                    st.rerun()
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
                    logger.info(f"ℹ️ Auto-selected database: {db}")
                    return db
        except Exception as e:
            logger.error(f"Could not list databases: {e}")

        # FINAL FALLBACK
        logger.error("=" * 80)
        logger.error("CRITICAL: NO DATABASE CONFIGURED!")
        logger.error("Please set a database using Global Filters or settings")
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
        
        # 0. Check for Background Job Status
        if "classification_future" in st.session_state:
            future = st.session_state["classification_future"]
            if not future.done():
                st.info("🔄 Classification is running in background... You can continue using other tabs.")
                if st.button("Check Status"):
                    st.rerun()
                return
            else:
                # Job Finished
                try:
                    new_results = future.result()
                    
                    # Merge with existing history to keep "Full View"
                    try:
                        # Fetch old results from DB (or session if available/preferred)
                        # We use DB history as the stable baseline
                        history_df = self._fetch_classification_history()
                        combined_results = []
                        
                        # Set of new keys (schema.table) to avoid duplicates
                        new_keys = set()
                        if new_results:
                            for r in new_results:
                                k = f"{r.get('schema')}.{r.get('table')}"
                                new_keys.add(k)
                                combined_results.append(r)
                        
                        # Add valid historical records that weren't re-scanned
                        if not history_df.empty:
                            # Convert DF back to list of dicts for consistency
                            # Using a simplified conversion - real conversion logic mirrors _convert_results_to_dataframe in reverse?
                            # Actually, st.session_state["pipeline_results"] expects list of dicts with granular info (column_results, etc).
                            # The history DF is flattened. This is tricky.
                            # If we overwrite session_state with flattened DF rows, the UI might break if it expects rich objects.
                            # HOWEVER, render_classification_pipeline calls _convert_results_to_dataframe on the session state results!
                            # So session_state should store RICH result objects.
                            # The DB history does NOT contain Full rich objects (e.g. embeddings, raw matches).
                            # It only contains what was saved.
                            
                            # Tradeoff: 
                            # If we want the FULL view, we should probably just rely on the fact that
                            # when we save the new results (which happens in the UI next step), 
                            # the next fetch from DB will get everything.
                            # BUT the user wants to see it NOW.
                            
                            # OPTION A: We only show what we just scanned (Incremental View). 
                            # User saves -> Page reloads -> Full View from DB.
                            # This is safer than hacking a merge of incompatible types.
                            # Let's stick to standard behavior: "Pipeline completed...".
                            # The "Save" button will save THESE results.
                            # Once saved, the main dashboard reloads from DB and shows merged view.
                            
                            # WAIT, if we only show partial results, the dashboard might look empty-ish.
                            # But that's technically correct for "Here is what I just found".
                            # Then you save it.
                            pass
                            
                        # Update Session State
                        st.session_state["pipeline_results"] = new_results
                        
                    except Exception as merge_err:
                         logger.warning(f"Result merge warning: {merge_err}")
                         st.session_state["pipeline_results"] = new_results

                    results = new_results
                    successful = len([r for r in results if 'error' not in r])
                    failed = len([r for r in results if 'error' in r])
                    st.success(f"Pipeline completed! Successfully classified {successful} assets. Failed: {failed}")
                except Exception as e:
                    st.error(f"Background classification failed: {e}")
                
                # Cleanup
                del st.session_state["classification_future"]
                # Reset force_full_rescan flag
                if "force_full_rescan" in st.session_state:
                    del st.session_state["force_full_rescan"]
                return

        # Ensure required keywords are initialized (lazy trigger)
        if not self._keywords_initialized:
            self._init_required_keywords()
            self._keywords_initialized = True

        # Validate database
        if not db or db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            st.error("Invalid database selected. Please choose a valid database from Global Filters.")
            return

        # Validate governance database
        if gov_db and gov_db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN'):
            gov_db = db  # fallback to main db

        # 2. Start New Job Logic
        
        # Prefer live metadata for discovery, but classification will be governance-free
        try:
            self.ai_service.use_snowflake = True
        except Exception:
            pass

        # Initialize local MiniLM (or fallback) embeddings and category centroids
        with st.spinner("Initializing pipeline resources..."):
            self._init_local_embeddings()

        # Optimization #4: Warehouse Sizing
        try:
            snowflake_connector.execute_non_query("USE WAREHOUSE COMPUTE_WH") 
        except Exception:
            pass

        try:
            self._auto_tune_parameters()
        except Exception:
            pass

        # Step 1b: Local discovery list for this run (preview)
        assets = self._discover_assets(db)
        if not assets:
            st.warning("No tables found in the selected database.")
            return

        # Process all discovered assets
        assets_to_classify = assets
        st.info(f"🔎 Scan: Processing {len(assets)} tables from the database.")
            
        # Step 2: Submit Background Task
        try:
            cfg = self._load_dynamic_config()
        except Exception:
            cfg = {}
        try:
            max_assets = int(cfg.get("max_assets_per_run", 30) or 30)
        except Exception:
            max_assets = 30
            
        # Enforce max limit on the incremental batch
        assets_to_classify = assets_to_classify[:max_assets]
        
        # Submit to Background Executor
        future = self._executor.submit(self._classify_assets_local, db=db, assets=assets_to_classify)
        st.session_state["classification_future"] = future
        st.info("🚀 Classification started in background! You can navigate away or wait here.")
        if st.button("Refresh Status"):
            st.rerun()
        return






    def _init_local_embeddings(self) -> None:
        """
        Initialize embeddings and load ALL classification metadata from governance tables.
        This is the main entry point for metadata-driven classification.
        """
        try:
            if not hasattr(self, "_embed_cache") or self._embed_cache is None:
                self._embed_cache = SimpleLRUCache(max_size=1000)
            self._embed_ready = False
            
            # Initialize SentenceTransformer embeddings
            if SentenceTransformer is not None:
                try:
                    logger.info("Initializing SentenceTransformer embeddings (all-MiniLM-L6-v2) for Logic Optimization...")
                    # Optimization #3: Switch to smaller model
                    self._model_name = 'sentence-transformers/all-MiniLM-L6-v2'
                    self._embedder = SentenceTransformer(self._model_name)
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

        # Load ALL metadata from governance views (100% data-driven)
        self._load_view_based_governance_rules()

    def _load_view_based_governance_rules(self, force_reload: bool = False) -> None:
        """
        Load ALL classification rules from Snowflake views.
        
        This method loads rules from the following views:
        - VW_CLASSIFICATION_RULES: Base keyword and pattern rules
        - VW_CONTEXT_AWARE_RULES: Context-aware adjustment rules
        - VW_TIEBREAKER_KEYWORDS: Intelligent tiebreaking keywords
        - VW_ADDRESS_CONTEXT_INDICATORS: Physical vs network address detection
        - VW_EXCLUSION_PATTERNS: Non-sensitive field patterns
        - VW_POLICY_GROUP_KEYWORDS: Keywords grouped by policy group
        - VW_CATEGORY_METADATA: Complete category metadata
        
        All rules are derived dynamically from SENSITIVITY_CATEGORIES,
        SENSITIVE_KEYWORDS, and SENSITIVE_PATTERNS tables.
        
        Implements session-based caching to prevent repeated Snowflake queries.
        """
        # Session cache key
        cache_key = "_governance_rules_cache_v2"
        
        # 1. Try to load from cache
        if not force_reload and cache_key in st.session_state:
            try:
                cached_data = st.session_state[cache_key]
                logger.info("Loading governance rules from session cache...")
                
                self._classification_rules = cached_data.get('classification_rules', [])
                self._context_aware_rules = cached_data.get('context_aware_rules', {})
                self._tiebreaker_keywords = cached_data.get('tiebreaker_keywords', {})
                self._address_context_indicators = cached_data.get('address_context_indicators', [])
                self._exclusion_patterns = cached_data.get('exclusion_patterns', [])
                self._policy_group_keywords = cached_data.get('policy_group_keywords', {})
                self._category_metadata = cached_data.get('category_metadata', {})
                
                self._view_based_rules_loaded = True
                
                # Re-run legacy updates and centroids generation (fast in-memory operations)
                # This ensures any transient state like embeddings (if re-init) is consistent
                self._update_legacy_structures_from_views()
                self._generate_centroids_from_view_data()
                logger.info("✓ Governance rules restored from cache")
                return
            except Exception as e:
                logger.warning(f"Failed to restore from cache: {e}. Reloading from DB.")
        
        if not self._rules_loader:
            # Fallback: load directly from governance views when loader is unavailable
            try:
                self._load_view_based_governance_rules_direct()
                return
            except Exception as _e:
                logger.warning(f"Governance rules loader not available and direct view load failed: {_e}")
                return
        
        try:
            logger.info("Loading view-based governance rules from Snowflake...")
            
            # Load all rules from views
            self._classification_rules = self._rules_loader.load_classification_rules()
            self._context_aware_rules = self._rules_loader.load_context_aware_rules()
            self._tiebreaker_keywords = self._rules_loader.load_tiebreaker_keywords()
            self._address_context_indicators = self._rules_loader.load_address_context_indicators()
            self._exclusion_patterns = self._rules_loader.load_exclusion_patterns()
            self._policy_group_keywords = self._rules_loader.load_policy_group_keywords()
            self._category_metadata = self._rules_loader.load_category_metadata()
            
            # Mark as loaded
            self._view_based_rules_loaded = True
            
            # Log summary
            logger.info(f"✓ Loaded {len(self._classification_rules)} classification rules")
            logger.info(f"✓ Loaded {sum(len(v) for v in self._context_aware_rules.values())} context-aware rules across {len(self._context_aware_rules)} types")
            logger.info(f"✓ Loaded {sum(len(v) for v in self._tiebreaker_keywords.values())} tiebreaker keywords across {len(self._tiebreaker_keywords)} policy groups")
            logger.info(f"✓ Loaded {len(self._address_context_indicators)} address context indicators")
            logger.info(f"✓ Loaded {len(self._exclusion_patterns)} exclusion patterns")
            logger.info(f"✓ Loaded {sum(len(v) for v in self._policy_group_keywords.values())} policy group keywords")
            logger.info(f"✓ Loaded {len(self._category_metadata)} category metadata records")
            
            # Cache the results
            st.session_state[cache_key] = {
                'classification_rules': self._classification_rules,
                'context_aware_rules': self._context_aware_rules,
                'tiebreaker_keywords': self._tiebreaker_keywords,
                'address_context_indicators': self._address_context_indicators,
                'exclusion_patterns': self._exclusion_patterns,
                'policy_group_keywords': self._policy_group_keywords,
                'category_metadata': self._category_metadata
            }
            
            # Update legacy data structures for backward compatibility
            self._update_legacy_structures_from_views()
            
            # Generate centroids for semantic search
            self._generate_centroids_from_view_data()
            
        except Exception as e:
            logger.error(f"Failed to load view-based governance rules: {e}")
            logger.exception(e)
            self._view_based_rules_loaded = False

    def _update_legacy_structures_from_views(self) -> None:
        """
        Update legacy data structures from view-based rules for backward compatibility.
        
        This ensures existing code that relies on the old structure continues to work
        while we transition to the new view-based architecture.
        """
        try:
            # Initialize legacy structures
            self._category_keywords = {}
            self._category_patterns = {}
            self._category_keyword_metadata = {}
            self._category_pattern_metadata = {}
            self._category_ids = {}

            # Populate keywords and patterns from classification rules
            for rule in self._classification_rules:
                cat_name = rule.get('CATEGORY_NAME', '').strip()
                if not cat_name:
                    continue
                
                # Initialize lists if needed
                if cat_name not in self._category_keywords:
                    self._category_keywords[cat_name] = []
                    self._category_keyword_metadata[cat_name] = []
                if cat_name not in self._category_patterns:
                    self._category_patterns[cat_name] = []
                    self._category_pattern_metadata[cat_name] = []
                
                rule_type = rule.get('RULE_TYPE', '').upper()
                pattern = rule.get('RULE_PATTERN', '').strip()
                weight = float(rule.get('RULE_WEIGHT', 1.0))
                
                if rule_type == 'KEYWORD':
                    kw = pattern.lower()
                    if kw:
                        self._category_keywords[cat_name].append(kw)
                        self._category_keyword_metadata[cat_name].append({
                            'keyword': kw,
                            'weight': weight,
                            'match_type': rule.get('MATCH_TYPE', 'CONTAINS').upper(),
                            'sensitivity_type': 'STANDARD',
                            'score': weight,
                        })
                elif rule_type == 'PATTERN':
                    if pattern:
                        self._category_patterns[cat_name].append(pattern)
                        self._category_pattern_metadata[cat_name].append({
                            'pattern': pattern,
                            'weight': weight,
                            'sensitivity_type': 'STANDARD',
                        })

            # Update category metadata from views
            for cat_name, metadata in self._category_metadata.items():
                # Update thresholds
                self._category_thresholds[cat_name] = metadata.get('detection_threshold', 0.5)
                
                # Update scoring weights (normalize keys to w_sem/w_kw/w_pat)
                self._category_scoring_weights[cat_name] = {
                    'w_sem': float(metadata.get('weight_embedding', 0.6)),
                    'w_kw': float(metadata.get('weight_keyword', 0.25)),
                    'w_pat': float(metadata.get('weight_pattern', 0.15)),
                }
                
                # Update multi-label flag
                self._category_multi_label[cat_name] = metadata.get('multi_label', True)
                
                # Update policy group mapping
                policy_group = metadata.get('policy_group', '')
                if policy_group:
                    self._policy_group_by_category[cat_name] = policy_group
                    
                # Update category IDs
                if metadata.get('category_id'):
                    self._category_ids[cat_name] = metadata.get('category_id')
            
            # Update business glossary from policy group keywords
            for policy_group, keywords in self._policy_group_keywords.items():
                for kw_data in keywords:
                    keyword = kw_data.get('keyword', '')
                    category = kw_data.get('category', policy_group)
                    if keyword and category:
                        self._business_glossary_map[keyword.lower()] = category.upper()
            
            logger.debug("Updated legacy data structures from view-based rules")
            
        except Exception as e:
            logger.warning(f"Failed to update legacy structures from views: {e}")

    def _synthetic_centroid(self, text: str) -> Any:
        """
        Generate a synthetic (deterministic) centroid when SentenceTransformer is not available.
        
        This creates a simple hash-based pseudo-vector that provides consistent results
        for the same input text. It's used as a fallback when the embedding model fails
        to load (e.g., due to missing dependencies or memory constraints).
        
        Args:
            text: The text to generate a centroid for (category name + keywords)
            
        Returns:
            A numpy array representing the synthetic centroid, or None if numpy unavailable
        """
        try:
            if np is None:
                return None
            
            # Generate a deterministic pseudo-vector based on text hash
            # This ensures consistent results for the same category
            import hashlib
            
            text_hash = hashlib.md5(text.encode()).hexdigest()
            
            # Create a 384-dimensional vector (matching E5-Large output size)
            # Each dimension is derived from the hash in a deterministic way
            vector_dim = 384
            synthetic_vec = np.zeros(vector_dim, dtype=np.float32)
            
            # Use characters from the hash to populate the vector
            for i in range(vector_dim):
                char_idx = i % len(text_hash)
                char_val = int(text_hash[char_idx], 16)  # 0-15
                
                # Map to [-1, 1] range with some variation
                synthetic_vec[i] = (char_val - 7.5) / 7.5 * 0.5
                
                # Add text-length based offset for uniqueness
                synthetic_vec[i] += (i % 10 - 5) / 50.0
            
            # Normalize to unit length
            norm = float(np.linalg.norm(synthetic_vec))
            if norm > 0:
                synthetic_vec = synthetic_vec / norm
            
            return synthetic_vec
            
        except Exception as e:
            logger.debug(f"Synthetic centroid generation failed: {e}")
            return None

    def _generate_centroids_from_view_data(self) -> None:
        """
        Generate category centroids from loaded view-based data.
        This is required for the semantic search (E5-Large) to work.
        """
        try:
            logger.info("Generating category centroids from view-based data...")
            centroids: Dict[str, Any] = {}
            tokens_out: Dict[str, List[str]] = {}
            
            for cat_name, metadata in self._category_metadata.items():
                description = metadata.get('description', '')
                
                # Get keywords and patterns for this category
                kws = self._category_keywords.get(cat_name, [])
                pats = self._category_patterns.get(cat_name, [])
                
                # Generate tokens
                combined_text = f"{description} {' '.join(kws[:50])}"
                if not description:
                    combined_text = f"{cat_name} {' '.join(kws[:50])} {' '.join(pats[:20])}"
                
                try:
                    toks = self._generate_category_tokens(cat_name, combined_text)
                    tokens_out[cat_name] = toks or []
                except Exception:
                    tokens_out[cat_name] = []
                
                # Generate centroid
                try:
                    if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                        base_def = description if description else cat_name
                        if kws:
                            base_def += f" This includes: {', '.join(kws[:15])}."
                        if pats:
                            base_def += f" Patterns: {', '.join(pats[:10])}."
                        
                        passage_text = f"passage: {base_def}"
                        
                        # Optimization: Use Cached Embedding instead of re-encoding
                        centroid_vec = self._get_cached_embedding(passage_text)
                        
                        norm = float(np.linalg.norm(centroid_vec) or 0.0)
                        if norm > 0:
                            centroid_vec = centroid_vec / norm
                            centroids[cat_name] = centroid_vec
                        else:
                            centroids[cat_name] = None
                    else:
                        # Synthetic centroid fallback
                        sc = self._synthetic_centroid(f"{cat_name} {' '.join(kws[:50])} {' '.join(pats[:20])}")
                        centroids[cat_name] = sc
                except Exception as e:
                    logger.warning(f"Failed to generate centroid for {cat_name}: {e}")
                    centroids[cat_name] = None

            self._category_centroids = centroids
            self._category_tokens = tokens_out
            
            # Update stats
            try:
                st.session_state["_pipe_cat_count"] = len([c for c in self._category_centroids.values() if c is not None])
                st.session_state["_pipe_tok_count"] = sum(len(v) for v in self._category_tokens.values())
            except Exception:
                pass
                
            logger.info(f"✓ Generated centroids for {len(centroids)} categories")
            
        except Exception as e:
            logger.error(f"Failed to generate centroids: {e}")

    def _resolve_governance_schema(self) -> str:
        """
        Resolve the fully-qualified governance schema to <DB>.DATA_CLASSIFICATION_GOVERNANCE.
        DB priority:
        1) Global Filters / session_state (selected_governance_db, governance_db, selected_database, database)
        2) resolve_governance_db()
        3) CURRENT_DATABASE()
        Returns schema FQN string.
        """
        schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
        db_candidate = None
        # 1) Try Streamlit Global Filters (session_state)
        try:
            ss = getattr(st, 'session_state', {})
            if isinstance(ss, dict):
                db_candidate = (
                    ss.get('selected_governance_db') or
                    (ss.get('global_filters') or {}).get('governance_db') or
                    ss.get('governance_db') or
                    ss.get('selected_database') or
                    ss.get('database') or
                    ss.get('db')
                )
        except Exception:
            pass
        # 2) Fallback to resolver
        if not db_candidate:
            try:
                db_candidate = resolve_governance_db()
            except Exception:
                db_candidate = None
        # 3) Fallback to CURRENT_DATABASE()
        if not db_candidate:
            try:
                row = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB")
                if row:
                    r0 = row[0]
                    if isinstance(r0, dict):
                        db_candidate = r0.get('DB')
                    else:
                        db_candidate = r0[0]
            except Exception:
                db_candidate = None
        if not db_candidate or str(db_candidate).strip().upper() in {'', 'NONE', '(NONE)', 'NULL', 'UNKNOWN'}:
             db_candidate = None
        
        # Build FQN and attempt to USE DATABASE
        if db_candidate:
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {db_candidate}")
                logger.info(f"✅ Using database: {db_candidate}")
            except Exception as e:
                logger.warning(f"⚠️ Could not USE DATABASE {db_candidate}: {e}")
                pass
            schema_fqn = f"{db_candidate}.DATA_CLASSIFICATION_GOVERNANCE"
        else:
            # No database found - provide helpful error
            logger.error("❌ Could not resolve governance database!")
            logger.error("Please ensure:")
            logger.error("  1. A database is selected in Global Filters")
            logger.error("  2. The database contains DATA_CLASSIFICATION_GOVERNANCE schema")
            logger.error("  3. The SENSITIVITY_CATEGORIES table exists in that schema")
            
            # Try to list available databases for debugging
            try:
                dbs = snowflake_connector.execute_query("SHOW DATABASES")
                db_names = [d.get('name') or d.get('NAME') for d in dbs if d]
                logger.info(f"Available databases: {db_names}")
            except Exception:
                pass
                
        # Store for diagnostics
        try:
            st.session_state["_pipe_schema_fqn"] = schema_fqn
            logger.info(f"📍 Resolved governance schema: {schema_fqn}")
        except Exception:
            pass
        return schema_fqn


    def _map_category_to_policy_group(self, category_name: str) -> str:
        """
        Map category name to its policy group (PII/SOX/SOC2).
        
        This method is CRITICAL for the keyword validation layer to work correctly.
        It determines which policy group a category belongs to so that
        misclassified keywords can be corrected.
        
        Args:
            category_name: Name of the sensitivity category
            
        Returns:
            Policy group name (PII, SOX, SOC2) or empty string if not found
        """
        try:
            cat_upper = category_name.upper()
            
            # Option 1: Check the loaded mapping from governance tables
            # This is populated during _load_view_based_governance_rules_direct()
            if hasattr(self, '_policy_group_by_category') and self._policy_group_by_category:
                policy_group = self._policy_group_by_category.get(cat_upper, '')
                if policy_group:
                    logger.debug(f"Mapped category '{category_name}' to policy group '{policy_group}' via _policy_group_by_category")
                    return policy_group.upper()
            
            # Option 2: Check category metadata (loaded from VW_CATEGORY_METADATA)
            if hasattr(self, '_category_metadata') and self._category_metadata:
                metadata = self._category_metadata.get(cat_upper, {})
                policy_group = metadata.get('policy_group', '')
                if policy_group:
                    logger.debug(f"Mapped category '{category_name}' to policy group '{policy_group}' via _category_metadata")
                    return policy_group.upper()
            
            # Option 3: Direct match - assume category name IS the policy group
            # This works for categories named 'PII', 'SOX', 'SOC2'
            if cat_upper in {'PII', 'SOX', 'SOC2'}:
                logger.debug(f"Mapped category '{category_name}' to policy group '{cat_upper}' via direct match")
                return cat_upper
            
            # Option 4: Check if category name CONTAINS policy group
            # Handles cases like 'PII_SENSITIVE', 'SOX_FINANCIAL', etc.
            for pg in ['PII', 'SOX', 'SOC2']:
                if pg in cat_upper:
                    logger.debug(f"Mapped category '{category_name}' to policy group '{pg}' via substring match")
                    return pg
            
            logger.warning(f"Could not map category '{category_name}' to any policy group (PII/SOX/SOC2)")
            return ''
            
        except Exception as e:
            logger.error(f"Error mapping category '{category_name}' to policy group: {e}")
            return ''

    def _load_view_based_governance_rules_direct(self) -> None:
        """Directly load governance rules from Snowflake VW_* views when a rules loader is not provided."""
        # Resolve governance schema
        schema_fqn = self._resolve_governance_schema()
        try:
            st.session_state["_pipe_view_loader"] = "direct"
            st.session_state["_pipe_schema_fqn"] = schema_fqn
        except Exception:
            pass

        # Fetch category metadata
        meta_rows = []
        try:
            meta_rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    CATEGORY_ID,
                    CATEGORY_NAME,
                    COALESCE(DESCRIPTION,'') AS DESCRIPTION,
                    COALESCE(DETECTION_THRESHOLD,0.45) AS DETECTION_THRESHOLD,
                    COALESCE(WEIGHT_EMBEDDING,0.60) AS WEIGHT_EMBEDDING,
                    COALESCE(WEIGHT_KEYWORD,0.25) AS WEIGHT_KEYWORD,
                    COALESCE(WEIGHT_PATTERN,0.15) AS WEIGHT_PATTERN,
                    COALESCE(MULTI_LABEL,TRUE) AS MULTI_LABEL,
                    POLICY_GROUP
                FROM {schema_fqn}.VW_CATEGORY_METADATA
                """
            ) or []
        except Exception:
            meta_rows = []

        # Fetch flat rules (keywords/patterns)
        rules_rows = []
        try:
            rules_rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    CATEGORY_NAME,
                    RULE_TYPE,
                    RULE_PATTERN,
                    COALESCE(RULE_WEIGHT,1.0) AS RULE_WEIGHT,
                    COALESCE(MATCH_TYPE,'CONTAINS') AS MATCH_TYPE
                FROM {schema_fqn}.VW_CLASSIFICATION_RULES
                """
            ) or []
        except Exception:
            rules_rows = []

        # Diagnostics
        try:
            st.session_state["_pipe_meta_rows"] = len(meta_rows)
            st.session_state["_pipe_rules_rows"] = len(rules_rows)
        except Exception:
            pass

        # Build metadata structures
        meta: Dict[str, Dict[str, Any]] = {}
        category_descriptions: Dict[str, str] = {}
        category_ids: Dict[str, Any] = {}
        self._category_thresholds = {}
        self._category_default_thresholds = {}
        self._category_weights = {}
        self._policy_group_by_category = {}
        self._category_scoring_weights = {}
        self._category_multi_label = {}
        self._category_colors = {}

        for r in meta_rows:
            if not isinstance(r, dict):
                continue
            name = str(r.get("CATEGORY_NAME") or "").strip()
            desc = str(r.get("DESCRIPTION") or "").strip()
            if not name:
                continue
            meta[name] = {
                'category_id': r.get('CATEGORY_ID'),
                'description': desc,
                'detection_threshold': float(r.get('DETECTION_THRESHOLD') or 0.45),
                'weight_embedding': float(r.get('WEIGHT_EMBEDDING') or 0.60),
                'weight_keyword': float(r.get('WEIGHT_KEYWORD') or 0.25),
                'weight_pattern': float(r.get('WEIGHT_PATTERN') or 0.15),
                'multi_label': bool(r.get('MULTI_LABEL', True)),
                'policy_group': r.get('POLICY_GROUP'),
            }
            category_descriptions[name] = desc
            category_ids[name] = r.get('CATEGORY_ID')
            self._category_thresholds[name] = float(r.get('DETECTION_THRESHOLD') or 0.45)
            self._category_default_thresholds[name] = float(r.get('DETECTION_THRESHOLD') or 0.45)
            self._category_weights[name] = 1.0
            pg = str(r.get('POLICY_GROUP') or '').upper()
            if pg:
                self._policy_group_by_category[name.upper()] = pg
            self._category_scoring_weights[name] = {
                'w_sem': float(r.get('WEIGHT_EMBEDDING') or 0.60),
                'w_kw': float(r.get('WEIGHT_KEYWORD') or 0.25),
                'w_pat': float(r.get('WEIGHT_PATTERN') or 0.15),
            }
            self._category_multi_label[name] = bool(r.get('MULTI_LABEL', True))
            if pg == 'PII':
                self._category_colors[name.upper()] = "#FF5733"
            elif pg == 'SOX':
                self._category_colors[name.upper()] = "#FFA500"
            elif pg == 'SOC2':
                self._category_colors[name.upper()] = "#4169E1"
            else:
                self._category_colors[name.upper()] = "#808080"

        # Group rules
        keywords_by_category: Dict[str, List[str]] = {c: [] for c in category_descriptions.keys()}
        keyword_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {c: [] for c in category_descriptions.keys()}
        patterns_by_category: Dict[str, List[str]] = {c: [] for c in category_descriptions.keys()}
        pattern_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {c: [] for c in category_descriptions.keys()}

        for rr in rules_rows:
            try:
                rtype = str(rr.get('RULE_TYPE') or '').upper()
                cat = str(rr.get('CATEGORY_NAME') or '').strip()
                if not cat or cat not in keywords_by_category:
                    continue
                if rtype == 'KEYWORD':
                    kw = str(rr.get('RULE_PATTERN') or '').strip().lower()
                    if kw:
                        keywords_by_category[cat].append(kw)
                        keyword_metadata_by_category[cat].append({
                            'keyword': kw,
                            'weight': float(rr.get('RULE_WEIGHT', 1.0)),
                            'match_type': str(rr.get('MATCH_TYPE', 'CONTAINS')).upper(),
                            'sensitivity_type': 'STANDARD',
                            'score': float(rr.get('RULE_WEIGHT', 1.0)),
                        })
                elif rtype == 'PATTERN':
                    pat = str(rr.get('RULE_PATTERN') or '').strip()
                    if pat:
                        patterns_by_category[cat].append(pat)
                        pattern_metadata_by_category[cat].append({
                            'pattern': pat,
                            'weight': float(rr.get('RULE_WEIGHT', 1.0)),
                            'sensitivity_type': 'STANDARD',
                        })
            except Exception:
                continue

        # ========================================================================
        # [REMOVED] KEYWORD VALIDATION (Relies on Database Only)
        # ========================================================================


        # Build centroids and tokens
        centroids: Dict[str, Any] = {}
        tokens_out: Dict[str, List[str]] = {}
        for cat_name, description in category_descriptions.items():
            kws = keywords_by_category.get(cat_name, [])
            pats = patterns_by_category.get(cat_name, [])
            combined_text = f"{description} {' '.join(kws[:50])}"
            if not description:
                # Fallback text from name + keywords + patterns
                combined_text = f"{cat_name} {' '.join(kws[:50])} {' '.join(pats[:20])}"
            try:
                toks = self._generate_category_tokens(cat_name, combined_text)
                tokens_out[cat_name] = toks or []
            except Exception:
                tokens_out[cat_name] = []
            try:
                if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                    base_def = description if description else cat_name
                    if kws:
                        base_def += f" This includes: {', '.join(kws[:15])}."
                    if pats:
                        base_def += f" Patterns: {', '.join(pats[:10])}."
                    # CRITICAL FIX: Add 'passage:' prefix for E5 asymmetric encoding
                    # This must match the 'query:' prefix used in _semantic_scores_governance_driven
                    passage_text = f"passage: {base_def}"
                    centroid_vec = self._embedder.encode([passage_text], normalize_embeddings=True)[0]
                    norm = float(np.linalg.norm(centroid_vec) or 0.0)
                    if norm > 0:
                        centroid_vec = centroid_vec / norm
                        centroids[cat_name] = centroid_vec
                    else:
                        centroids[cat_name] = None
                else:
                    # Synthetic centroid fallback
                    sc = self._synthetic_centroid(f"{cat_name} {' '.join(kws[:50])} {' '.join(pats[:20])}")
                    centroids[cat_name] = sc
            except Exception:
                centroids[cat_name] = None

        self._category_centroids = centroids
        self._category_tokens = tokens_out
        self._category_patterns = patterns_by_category
        self._category_keywords = keywords_by_category
        self._category_keyword_metadata = keyword_metadata_by_category
        self._category_pattern_metadata = pattern_metadata_by_category
        self._category_ids = category_ids
        self._category_metadata = meta

        try:
            st.session_state["_pipe_cat_count"] = len([c for c in self._category_centroids.values() if c is not None])
            st.session_state["_pipe_tok_count"] = sum(len(v) for v in self._category_tokens.values())
        except Exception:
            pass
        self._view_based_rules_loaded = True

        # If no centroids but embedder active, keep keyword-only scoring as safety (handled elsewhere)
        return

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
            # Always use DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"

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
            # Always use DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"

            # Get current user for audit
            try:
                ident = authz.get_current_identity()
                user = ident.user or "Unknown"
            except Exception:
                user = "Unknown"
            
            final_details = f"[User: {user}] {details}"
            
            # Escape single quotes for SQL
            safe_details = final_details.replace("'", "''")
            safe_keyword = keyword.replace("'", "''")
            
            # Generate UUID in Python
            audit_id = str(uuid.uuid4())
            query = f"""
                INSERT INTO {schema_fqn}.CLASSIFICATION_AUDIT 
                (ID, RESOURCE_ID, ACTION, DETAILS, CREATED_AT)
                VALUES ('{audit_id}', '{safe_keyword}', '{action}', '{safe_details}', CURRENT_TIMESTAMP())
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


            # Always use DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"

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
            
            # Generate UUID in Python
            keyword_id = str(uuid.uuid4())
            query = f"""
                INSERT INTO {schema_fqn}.SENSITIVE_KEYWORDS 
                (KEYWORD_ID, CATEGORY_ID, KEYWORD_STRING, MATCH_TYPE, SENSITIVITY_WEIGHT, IS_ACTIVE, CREATED_BY)
                VALUES ('{keyword_id}', '{category_id}', '{safe_keyword}', '{safe_match_type}', 0.8, TRUE, CURRENT_USER())
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

    def upsert_sensitive_keyword(self, keyword: str, category_name: str, match_type: str = 'CONTAINS', sensitivity_weight: float = 0.8) -> bool:
        """
        Upsert a sensitive keyword (Insert if new, Update if exists).
        
        Args:
            keyword: The keyword string to upsert
            category_name: The category name (e.g., 'PII', 'SOX', 'SOC2')
            match_type: Match type ('EXACT', 'CONTAINS', 'FUZZY', 'REGEX')
            sensitivity_weight: Sensitivity weight (0.0 to 10.0)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"🔄 [UPSERT] Starting upsert for keyword='{keyword}', category='{category_name}', match_type='{match_type}', sensitivity_weight={sensitivity_weight}")
            
            # Step 1: ALWAYS use DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"
            logger.info(f"📍 [UPSERT] Using schema: {schema_fqn}")

            # Step 2: Get or Create Category ID
            category_id = self.get_category_id_by_name(category_name)
            if not category_id:
                logger.info(f"🆕 [UPSERT] Category '{category_name}' not found. Creating new category...")
                category_id = str(uuid.uuid4())
                try:
                    # Insert new category
                    q_ins_cat = f"""
                        INSERT INTO {schema_fqn}.SENSITIVITY_CATEGORIES
                        (CATEGORY_ID, CATEGORY_NAME, SENSITIVITY_LEVEL, DESCRIPTION, CREATED_BY, CREATED_AT)
                        VALUES ('{category_id}', '{category_name}', 'Confidential', 'Auto-created via UI', CURRENT_USER(), CURRENT_TIMESTAMP())
                    """
                    snowflake_connector.execute_non_query(q_ins_cat)
                    logger.info(f"✅ [UPSERT] Created category '{category_name}' (ID: {category_id})")
                except Exception as e:
                    logger.error(f"❌ [UPSERT] Failed to create category '{category_name}': {e}")
                    return False
            
            logger.info(f"✅ [UPSERT] Found/Created category_id={category_id} for category='{category_name}'")

            # Step 3: Check if keyword exists
            logger.info(f"🔍 [UPSERT] Checking if keyword '{keyword}' exists for category_id={category_id}...")
            
            existing = snowflake_connector.execute_query(
                f"SELECT KEYWORD_ID, VERSION_NUMBER FROM {schema_fqn}.SENSITIVE_KEYWORDS WHERE LOWER(KEYWORD_STRING) = LOWER(%(k)s) AND CATEGORY_ID = %(c)s",
                {"k": keyword, "c": category_id}
            )
            
            # Step 4: Escape special characters
            safe_keyword = keyword.replace("'", "''")
            safe_match_type = match_type.replace("'", "''")

            if existing and len(existing) > 0:
                # UPDATE path
                existing_record = existing[0]
                keyword_id = existing_record.get('KEYWORD_ID')
                current_version = existing_record.get('VERSION_NUMBER', 1)
                new_version = current_version + 1
                
                logger.info(f"📝 [UPSERT] Keyword EXISTS (keyword_id={keyword_id}, version={current_version})")
                logger.info(f"🔧 [UPSERT] Executing UPDATE...")
                
                # UPDATE using ONLY SENSITIVITY_WEIGHT
                query = f"""
                    UPDATE {schema_fqn}.SENSITIVE_KEYWORDS 
                    SET 
                        MATCH_TYPE = '{safe_match_type}',
                        SENSITIVITY_WEIGHT = {sensitivity_weight},
                        IS_ACTIVE = TRUE,
                        UPDATED_BY = CURRENT_USER(),
                        UPDATED_AT = CURRENT_TIMESTAMP(),
                        VERSION_NUMBER = {new_version}
                    WHERE KEYWORD_ID = '{keyword_id}'
                """
                
                logger.info(f"📋 [UPSERT] Query: {query[:150]}...")
                
                try:
                    snowflake_connector.execute_non_query(query)
                    logger.info(f"✅ [UPSERT] UPDATE successful! Version {current_version} → {new_version}")
                except Exception as update_error:
                    logger.error(f"❌ [UPSERT] UPDATE failed: {update_error}")
                    # Try without UPDATED_BY column (fallback)
                    query_fallback = f"""
                        UPDATE {schema_fqn}.SENSITIVE_KEYWORDS 
                        SET 
                            MATCH_TYPE = '{safe_match_type}',
                            SENSITIVITY_WEIGHT = {sensitivity_weight},
                            IS_ACTIVE = TRUE,
                            UPDATED_AT = CURRENT_TIMESTAMP(),
                            VERSION_NUMBER = {new_version}
                        WHERE KEYWORD_ID = '{keyword_id}'
                    """
                    logger.info(f"🔄 [UPSERT] Trying fallback UPDATE without UPDATED_BY...")
                    snowflake_connector.execute_non_query(query_fallback)
                    logger.info(f"✅ [UPSERT] Fallback UPDATE successful!")
                
                # Audit
                self._log_keyword_audit("UPDATE_KEYWORD", keyword, category_name, 
                    f"Updated keyword '{keyword}' in category '{category_name}' with match_type={match_type}, sensitivity_weight={sensitivity_weight}")
            else:
                # INSERT path
                logger.info(f"➕ [UPSERT] Keyword does NOT exist. Executing INSERT...")
                
                # INSERT using ONLY SENSITIVITY_WEIGHT
                # Generate UUID in Python
                keyword_id = str(uuid.uuid4())
                query = f"""
                    INSERT INTO {schema_fqn}.SENSITIVE_KEYWORDS 
                    (
                        KEYWORD_ID, 
                        CATEGORY_ID, 
                        KEYWORD_STRING, 
                        MATCH_TYPE, 
                        SENSITIVITY_WEIGHT,
                        IS_ACTIVE,
                        CREATED_BY,
                        CREATED_AT,
                        VERSION_NUMBER
                    )
                    VALUES (
                        '{keyword_id}', 
                        '{category_id}', 
                        '{safe_keyword}', 
                        '{safe_match_type}', 
                        {sensitivity_weight},
                        TRUE,
                        CURRENT_USER(),
                        CURRENT_TIMESTAMP(),
                        1
                    )
                """
                
                logger.info(f"📋 [UPSERT] Query: {query[:150]}...")
                snowflake_connector.execute_non_query(query)
                logger.info(f"✅ [UPSERT] INSERT successful!")
                
                # Audit
                self._log_keyword_audit("ADD_KEYWORD", keyword, category_name, 
                    f"Added keyword '{keyword}' to category '{category_name}' via upsert with match_type={match_type}, sensitivity_weight={sensitivity_weight}")

            # Step 5: Refresh cache
            logger.info(f"🔄 [UPSERT] Refreshing local cache...")
            self._load_metadata_driven_categories()
            logger.info(f"✅ [UPSERT] Cache refreshed!")
            
            # Step 6: Sync Results Table
            self._sync_column_classification_result(keyword)
            
            logger.info(f"🎉 [UPSERT] COMPLETE! Keyword '{keyword}' successfully upserted to category '{category_name}'")
            return True
            
        except Exception as e:
            logger.error(f"❌ [UPSERT] FAILED with exception: {e}")
            import traceback
            logger.error(f"📋 [UPSERT] Full traceback:\n{traceback.format_exc()}")
            return False

    def delete_sensitive_keyword(self, keyword: str, category_name: str) -> bool:
        """
        Soft-delete a sensitive keyword for a specific category (set IS_ACTIVE=FALSE).
        """
        try:
            logger.info(f"🗑️ [DELETE] Deleting keyword='{keyword}' for category='{category_name}'")
            category_id = self.get_category_id_by_name(category_name)
            if not category_id:
                logger.error(f"❌ [DELETE] Category '{category_name}' not found!")
                return False
            
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"
            
            # Audit intent
            self._log_keyword_audit("DELETE_KEYWORD", keyword, category_name, 
                f"Deactivated keyword '{keyword}' for category '{category_name}'")
            
            query = f"""
                UPDATE {schema_fqn}.SENSITIVE_KEYWORDS
                SET 
                    IS_ACTIVE = FALSE,
                    UPDATED_BY = CURRENT_USER(),
                    UPDATED_AT = CURRENT_TIMESTAMP()
                WHERE LOWER(KEYWORD_STRING) = LOWER(%(k)s) 
                  AND CATEGORY_ID = %(c)s
                  AND IS_ACTIVE = TRUE
            """
            snowflake_connector.execute_non_query(query, {"k": keyword, "c": category_id})
            logger.info(f"✅ [DELETE] Keyword '{keyword}' deactivated for category '{category_name}'")
            
            # Sync Results Table
            self._sync_column_classification_result(keyword)
            
            return True
        except Exception as e:
            logger.error(f"❌ [DELETE] Failed: {e}")
            return False

    def _sync_column_classification_result(self, col_name: str) -> None:
        """
        Synchronize the CLASSIFICATION_AI_RESULTS table for a specific column name
        based on the current active keywords in SENSITIVE_KEYWORDS.
        
        This ensures that when a global rule is added/removed for a column name,
        the results table reflects the new set of categories immediately.
        """
        try:
            schema_fqn = "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"
            safe_col = col_name.replace("'", "''")
            
            # 1. Get all active categories for this column name
            q_cats = f"""
                SELECT sc.CATEGORY_NAME
                FROM {schema_fqn}.SENSITIVE_KEYWORDS sk
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID
                WHERE sk.IS_ACTIVE = TRUE
                  AND LOWER(sk.KEYWORD_STRING) = LOWER('{safe_col}')
                ORDER BY sc.CATEGORY_NAME
            """
            rows = snowflake_connector.execute_query(q_cats) or []
            active_cats = [r['CATEGORY_NAME'] for r in rows if r.get('CATEGORY_NAME')]
            
            # 2. Update CLASSIFICATION_AI_RESULTS
            if active_cats:
                # Construct data for update
                new_cat_str = ', '.join(sorted(set(active_cats)))
                
                # Derive policy group (simple logic: take highest priority)
                policy = 'None'
                for c in active_cats:
                    pg = self._map_category_to_policy_group(c)
                    if pg and pg != 'None':
                        policy = pg
                        break # Take first specific one
                
                # Update Query
                update_q = f"""
                    UPDATE {schema_fqn}.CLASSIFICATION_AI_RESULTS
                    SET 
                        AI_CATEGORY = '{new_cat_str}',
                        FINAL_CONFIDENCE = 1.0,
                        DETAILS = PARSE_JSON('{{"manual_override": true, "sync_update": true, "detected_categories": {[{{"category": c, "confidence": 1.0}} for c in active_cats]}}}')
                    WHERE LOWER(COLUMN_NAME) = LOWER('{safe_col}')
                """
                # Note: The JSON construction in f-string needs careful escaping of braces
                # Fix JSON escaping:
                json_str = '[' + ', '.join([f'{{"category": "{c}", "confidence": 1.0}}' for c in active_cats]) + ']'
                update_q = f"""
                    UPDATE {schema_fqn}.CLASSIFICATION_AI_RESULTS
                    SET 
                        AI_CATEGORY = '{new_cat_str}',
                        FINAL_CONFIDENCE = 1.0,
                        DETAILS = PARSE_JSON('{{"manual_override": true, "sync_update": true, "detected_categories": {json_str} }}')
                    WHERE LOWER(COLUMN_NAME) = LOWER('{safe_col}')
                """
                
                snowflake_connector.execute_non_query(update_q)
                logger.info(f"✅ [SYNC] Updated CLASSIFICATION_AI_RESULTS for '{col_name}' to '{new_cat_str}'")
            else:
                # If no active categories remain, revert to NON_SENSITIVE??
                # Or just leave it? Usually if we delete the last rule, it should probably become NON_SENSITIVE?
                # Let's set it to NON_SENSITIVE to be safe/clean.
                update_q = f"""
                    UPDATE {schema_fqn}.CLASSIFICATION_AI_RESULTS
                    SET 
                        AI_CATEGORY = 'NON_SENSITIVE',
                        FINAL_CONFIDENCE = 0.0,
                        DETAILS = PARSE_JSON('{{"manual_override": true, "sync_update": true, "reason": "all_keywords_removed"}}')
                    WHERE LOWER(COLUMN_NAME) = LOWER('{safe_col}')
                """
                snowflake_connector.execute_non_query(update_q)
                logger.info(f"✅ [SYNC] Keyword rules removed for '{col_name}'. Reverted to NON_SENSITIVE in results.")

        except Exception as e:
            logger.warning(f"⚠️ [SYNC] Failed to sync results for '{col_name}': {e}")

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

    def _should_exclude_column(self, column_name: str) -> Tuple[bool, str]:
        """
        Check if a column should be excluded from classification.
        
        Args:
            column_name: Name of the column to check
            
        Returns:
            Tuple of (should_exclude: bool, reason: str)
        """
        if not column_name:
            return (False, "")
            
        col_lower = column_name.lower().strip()
        
        # Check if exclusion patterns are loaded
        if not hasattr(self, '_exclusion_patterns') or not self._exclusion_patterns:
            return (False, "")
        
        # Check exact matches first (faster)
        if col_lower in self._exclusion_patterns.get('exact', []):
            return (True, f"Exact match exclusion: '{column_name}'")
        
        # Check regex patterns
        for pattern_info in self._exclusion_patterns.get('regex', []):
            if isinstance(pattern_info, dict):
                pattern = pattern_info.get('pattern', '')
                reason = pattern_info.get('reason', 'Regex exclusion')
            else:
                # Fallback for simple string patterns
                pattern = str(pattern_info)
                reason = 'Regex exclusion'
            
            if pattern:
                try:
                    if re.search(pattern, col_lower, re.IGNORECASE):
                        return (True, f"{reason} (pattern: {pattern})")
                except Exception as e:
                    logger.warning(f"Invalid exclusion regex pattern '{pattern}': {e}")
                    continue
        
        return (False, "")

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
        
        # ========================================================================
        # PREFERRED PATH: Load from dynamic VIEWS via governance_rules_loader_v2
        # ========================================================================
        try:
            if self._rules_loader is not None:
                logger.info("Attempting view-based rule loading via governance_rules_loader_v2 ...")
                meta = self._rules_loader.load_category_metadata(force_refresh=False) or {}
                rules = self._rules_loader.load_classification_rules(force_refresh=False) or []
                # Fallback: if loader returns nothing, try direct view loading
                if not meta or not rules:
                    logger.warning("Rules loader returned empty results; attempting direct VW_* view loading...")
                    try:
                        self._load_view_based_governance_rules_direct()
                        # If direct load resulted in any centroids, stop here
                        try:
                            _vc = len([c for c in getattr(self, "_category_centroids", {}).values() if c is not None])
                            if _vc > 0:
                                logger.info(f"Direct view loading succeeded with {_vc} centroids. Skipping table-based fallback.")
                                return
                        except Exception:
                            pass
                    except Exception as _e:
                        logger.warning(f"Direct view loading failed: {_e}")
                if meta and rules:
                    # Build category structures from metadata view
                    self._category_thresholds = {}
                    self._category_default_thresholds = {}
                    self._category_weights = {}
                    self._policy_group_by_category = {}
                    self._category_scoring_weights = {}  # New: stores embedding/keyword/pattern weights
                    self._category_multi_label = {}      # New: stores multi-label flag
                    self._category_colors = {}
                    category_descriptions: Dict[str, str] = {}
                    category_ids: Dict[str, Any] = {}

                    for cat_name_u, m in meta.items():
                        try:
                            cat_name = str(cat_name_u).strip()
                            if not cat_name:
                                continue
                            desc = str(m.get('description') or '').strip()
                            if not desc:
                                logger.error(f"CRITICAL: Category '{cat_name}' has EMPTY DESCRIPTION in VW_CATEGORY_METADATA, skipping")
                                continue
                            category_descriptions[cat_name] = desc
                            category_ids[cat_name] = m.get('category_id')
                            self._category_thresholds[cat_name] = float(m.get('detection_threshold', 0.45))
                            self._category_default_thresholds[cat_name] = float(m.get('detection_threshold', 0.45))
                            self._category_weights[cat_name] = 1.0
                            pg = str(m.get('policy_group') or '').upper()
                            if pg:
                                self._policy_group_by_category[cat_name.upper()] = pg
                            self._category_scoring_weights[cat_name] = {
                                'w_sem': float(m.get('weight_embedding', 0.60)),
                                'w_kw': float(m.get('weight_keyword', 0.25)),
                                'w_pat': float(m.get('weight_pattern', 0.15)),
                            }
                            self._category_multi_label[cat_name] = bool(m.get('multi_label', True))
                            # derive colors from policy group
                            if pg == 'PII':
                                self._category_colors[cat_name.upper()] = "#FF5733"
                            elif pg == 'SOX':
                                self._category_colors[cat_name.upper()] = "#FFA500"
                            elif pg == 'SOC2':
                                self._category_colors[cat_name.upper()] = "#4169E1"
                            else:
                                self._category_colors[cat_name.upper()] = "#808080"
                        except Exception as e:
                            logger.debug(f"Error processing metadata for {cat_name_u}: {e}")
                            continue

                    # Group rules into keywords and patterns by category
                    keywords_by_category: Dict[str, List[str]] = {c: [] for c in category_descriptions.keys()}
                    keyword_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {c: [] for c in category_descriptions.keys()}
                    patterns_by_category: Dict[str, List[str]] = {c: [] for c in category_descriptions.keys()}
                    pattern_metadata_by_category: Dict[str, List[Dict[str, Any]]] = {c: [] for c in category_descriptions.keys()}

                    for r in rules:
                        try:
                            rtype = str(r.get('RULE_TYPE') or '').upper()
                            cat = str(r.get('CATEGORY_NAME') or '').strip()
                            if not cat or cat not in keywords_by_category:
                                continue
                            if rtype == 'KEYWORD':
                                kw = str(r.get('RULE_PATTERN') or '').strip().lower()
                                if kw:
                                    keywords_by_category[cat].append(kw)
                                    keyword_metadata_by_category[cat].append({
                                        'keyword': kw,
                                        'weight': float(r.get('RULE_WEIGHT', 1.0)),
                                        'match_type': str(r.get('MATCH_TYPE', 'CONTAINS')).upper(),
                                        'sensitivity_type': 'STANDARD',
                                        'score': float(r.get('RULE_WEIGHT', 1.0)),
                                    })
                            elif rtype == 'PATTERN':
                                pat = str(r.get('RULE_PATTERN') or '').strip()
                                if pat:
                                    patterns_by_category[cat].append(pat)
                                    pattern_metadata_by_category[cat].append({
                                        'pattern': pat,
                                        'weight': float(r.get('RULE_WEIGHT', 1.0)),
                                        'sensitivity_type': 'STANDARD',
                                    })
                        except Exception:
                            continue

                    # ========================================================================
                    # CRITICAL FIX: Validate and correct keyword mappings (view-based path)
                    # ========================================================================
                    keywords_by_category, keyword_metadata_by_category = self._validate_and_correct_keyword_mappings(
                        keywords_by_category, 
                        keyword_metadata_by_category
                    )

                    # Build centroids/tokens using the same logic as the table path
                    centroids: Dict[str, Any] = {}
                    tokens_out: Dict[str, List[str]] = {}
                    logger.info(f"Building centroids from view-based rules for {len(category_descriptions)} categories...")
                    logger.info(f"Embedder available: {self._embedder is not None}")
                    logger.info(f"NumPy available: {np is not None}")
                    logger.info(f"Backend: {self._embed_backend}")

                    for cat_name, description in category_descriptions.items():
                        logger.info(f"\n  Processing category: {cat_name}")
                        logger.info(f"    Description: '{description[:100]}...'")
                        kws = keywords_by_category.get(cat_name, [])
                        combined_text = f"{description} {' '.join(kws[:50])}"
                        logger.info(f"    Keywords available: {len(kws)}")
                        logger.info(f"    Combined text length: {len(combined_text)} chars")
                        try:
                            toks = self._generate_category_tokens(cat_name, combined_text)
                            tokens_out[cat_name] = toks or []
                        except Exception as e:
                            logger.debug(f"Token generation failed for {cat_name}: {e}")
                            tokens_out[cat_name] = []

                        try:
                            if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                                category_definition = f"{description}"
                                if kws:
                                    category_definition += f" This includes: {', '.join(kws[:15])}."
                                passage_text = f"passage: {category_definition}"
                                centroid_vec = self._embedder.encode([passage_text], normalize_embeddings=True)[0]
                                norm = float(np.linalg.norm(centroid_vec) or 0.0)
                                if norm > 0:
                                    centroid_vec = centroid_vec / norm
                                    centroids[cat_name] = centroid_vec
                                else:
                                    centroids[cat_name] = None
                            else:
                                centroids[cat_name] = None
                        except Exception as e:
                            logger.debug(f"Centroid build failed for {cat_name}: {e}")
                            centroids[cat_name] = None

                    # Store results
                    self._category_centroids = centroids
                    self._category_tokens = tokens_out
                    self._category_patterns = patterns_by_category
                    self._category_keywords = keywords_by_category
                    self._category_keyword_metadata = keyword_metadata_by_category
                    self._category_pattern_metadata = pattern_metadata_by_category
                    self._category_ids = category_ids

                    # If embedder is active but no centroids built, try second-pass using only descriptions
                    try:
                        valid_centroids = len([c for c in self._category_centroids.values() if c is not None])
                        if (self._embedder is not None and self._embed_backend == 'sentence-transformers' and valid_centroids == 0):
                            logger.warning("Embedder active but no centroids built from view-based rules; retrying with descriptions only...")
                            centroids2: Dict[str, Any] = {}
                            for cat_name, description in category_descriptions.items():
                                try:
                                    passage_text = f"passage: {description}" if 'e5' in str(getattr(self, '_model_name', '')).lower() else description
                                    vec = self._embedder.encode([passage_text], normalize_embeddings=True)[0]
                                    norm = float(np.linalg.norm(vec) or 0.0)
                                    centroids2[cat_name] = (vec / norm) if norm > 0 else None
                                except Exception as e:
                                    logger.debug(f"Second-pass centroid build failed for {cat_name}: {e}")
                                    centroids2[cat_name] = None
                            self._category_centroids = centroids2
                            valid_centroids = len([c for c in self._category_centroids.values() if c is not None])
                            logger.info(f"Second-pass centroid build complete: {valid_centroids} valid centroids")
                        # If still zero, mark embeddings not ready and prefer keyword-only weighting
                        if valid_centroids == 0:
                            logger.error("CRITICAL: Embedder active but no category centroids are available. Switching to keyword-only scoring.")
                            self._embed_ready = False
                            try:
                                self._using_fallback_categories = True
                            except Exception:
                                pass
                            # Adjust global defaults as a safety net; category-specific weights remain
                            self._w_sem = 0.0
                            self._w_kw = 1.0
                    except Exception:
                        pass

                    logger.info("View-based rule loading complete. Using governance views for classification.")
                    # Load auxiliary rule sets from views for advanced scoring/tiebreaking
                    try:
                        self._context_aware_rules = self._rules_loader.load_context_aware_rules(force_refresh=False) or {}
                        self._tiebreaker_keywords = self._rules_loader.load_tiebreaker_keywords(force_refresh=False) or {}
                        self._address_context_indicators = self._rules_loader.load_address_context_indicators(force_refresh=False) or []
                        self._exclusion_patterns = self._rules_loader.load_exclusion_patterns(force_refresh=False) or []
                        self._policy_group_keywords = self._rules_loader.load_policy_group_keywords(force_refresh=False) or {}
                        self._category_metadata = meta
                        self._view_based_rules_loaded = True
                    except Exception as e:
                        logger.warning(f"Failed loading auxiliary view-based rules: {e}")
                    try:
                        st.session_state["_pipe_cat_count"] = len([c for c in centroids.values() if c is not None])
                        st.session_state["_pipe_tok_count"] = sum(len(v) for v in tokens_out.values())
                    except Exception:
                        pass
                    # Early return; skip table-based path
                    return
        except Exception as e:
            logger.warning(f"View-based rule loading failed or not available, falling back to tables: {e}")

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
            # JOIN query to fetch category + keyword info directly
            keywords_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    sc.CATEGORY_ID, 
                    sc.CATEGORY_NAME, 
                    sc.DESCRIPTION, 
                    sc.DETECTION_THRESHOLD, 
                    sc.WEIGHT_EMBEDDING, 
                    sc.WEIGHT_KEYWORD, 
                    sc.WEIGHT_PATTERN, 
                    sc.MULTI_LABEL, 
                    sc.POLICY_GROUP, 
                    sk.KEYWORD_STRING, 
                    sk.MATCH_TYPE, 
                    COALESCE(sk.SENSITIVITY_WEIGHT, 1.0) AS KEYWORD_WEIGHT, 
                    sk.IS_ACTIVE
                FROM {schema_fqn}.SENSITIVITY_CATEGORIES sc 
                LEFT JOIN {schema_fqn}.SENSITIVE_KEYWORDS sk 
                  ON sc.CATEGORY_ID = sk.CATEGORY_ID 
                WHERE sc.IS_ACTIVE = TRUE
                ORDER BY sc.CATEGORY_NAME, sk.KEYWORD_STRING
                """
            ) or []
            
            for row in keywords_data:
                if not isinstance(row, dict):
                    continue
                    
                cat_name = str(row.get("CATEGORY_NAME") or "").strip()
                keyword = str(row.get("KEYWORD_STRING") or "").strip().lower()
                
                # Update category metadata if not already set (or to ensure consistency)
                if cat_name not in category_descriptions:
                    # In case we found a category not in VW_CATEGORY_METADATA (unlikely but possible)
                    category_descriptions[cat_name] = str(row.get("DESCRIPTION") or "")
                    keywords_by_category[cat_name] = []
                    keyword_metadata_by_category[cat_name] = []
                
                if keyword and row.get("IS_ACTIVE", True) is not False:
                    # Add to simple list
                    keywords_by_category[cat_name].append(keyword)
                    
                    # Store full metadata for classification logic
                    keyword_metadata_by_category[cat_name].append({
                        'keyword': keyword,
                        'weight': float(row.get("KEYWORD_WEIGHT") or 1.0),
                        'match_type': str(row.get("MATCH_TYPE") or "EXACT").upper(),
                        'sensitivity_type': 'STANDARD',
                        'score': float(row.get("KEYWORD_WEIGHT") or 1.0)
                    })

            total_keywords = sum(len(kws) for kws in keywords_by_category.values())
            logger.info(f"✓ Loaded {total_keywords} keywords from SENSITIVE_KEYWORDS via JOIN")
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
        # STEP 3.5: Load EXCLUSION_PATTERNS (UUIDs, System IDs, etc.)
        # ========================================================================
        self._exclusion_patterns = {
            'exact': [],  # Exact column name matches
            'regex': []   # Regex patterns
        }
        
        try:
            exclusions_data = snowflake_connector.execute_query(
                f"""
                SELECT 
                    PATTERN_TYPE,
                    PATTERN_VALUE,
                    EXCLUSION_REASON
                FROM {schema_fqn}.EXCLUSION_PATTERNS
                WHERE COALESCE(IS_ACTIVE, true)
                ORDER BY PATTERN_TYPE, PATTERN_VALUE
                """
            ) or []
            
            logger.info(f"Retrieved {len(exclusions_data)} exclusion patterns")
            
            for excl in exclusions_data:
                if not isinstance(excl, dict):
                    continue
                    
                pattern_type = str(excl.get("PATTERN_TYPE") or "").upper()
                pattern_value = str(excl.get("PATTERN_VALUE") or "").strip()
                reason = str(excl.get("EXCLUSION_REASON") or "")
                
                if not pattern_value:
                    continue
                
                if pattern_type == 'COLUMN_NAME':
                    self._exclusion_patterns['exact'].append(pattern_value.lower())
                elif pattern_type == 'REGEX':
                    self._exclusion_patterns['regex'].append({
                        'pattern': pattern_value,
                        'reason': reason
                    })
            
            logger.info(f"✓ Loaded {len(self._exclusion_patterns['exact'])} exact exclusions, "
                       f"{len(self._exclusion_patterns['regex'])} regex exclusions")
                       
        except Exception as e:
            logger.warning(f"⚠ Failed to load EXCLUSION_PATTERNS (table may not exist): {e}")
            logger.warning("Continuing without exclusions - will classify all columns")
            # Provide default exclusions for common system columns
            self._exclusion_patterns = {
                'exact': ['id', 'uuid', 'guid', 'created_by', 'updated_by', 
                         'created_at', 'updated_at', 'deleted_at', 'version'],
                'regex': [
                    {'pattern': r'^.*_id$', 'reason': 'Ends with _id'},
                    {'pattern': r'^.*_uuid$', 'reason': 'Ends with _uuid'},
                    {'pattern': r'^.*_guid$', 'reason': 'Ends with _guid'}
                ]
            }
            logger.info(f"Using default exclusions: {len(self._exclusion_patterns['exact'])} exact, "
                       f"{len(self._exclusion_patterns['regex'])} regex")
        
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
        
        STRICT MODE: No hardcoded fallbacks. 
        If governance tables are empty, classification will intentionally find nothing.
        """
        logger.warning("=" * 80)
        logger.warning("BASELINE FALLBACK CATEGORIES DISABLED (STRICT GOVERNANCE MODE)")
        logger.warning("Governance tables must be populated for detection to work.")
        logger.warning("=" * 80)
        
        self._category_keywords = {}
        self._category_patterns = {}
        self._category_thresholds = {}
        self._policy_group_by_category = {
            'PII': ['insurance_id', 'beneficiary', 'condition', 'disease',
                   'medical_record', 'mrn', 'blood_group', 'vaccine', 'health_condition'],
            'patterns': [],
            'threshold': 0.40,
            'policy_group': 'PII'
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
                    'match_type': 'CONTAINS',
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

    def _get_exact_keyword_match(self, text: str) -> Tuple[Optional[str], Optional[float], Optional[str]]:
        """
        Check for exact keyword matches from the governance table.
        
        Args:
            text: Text to check for exact keyword matches
            
        Returns:
            Tuple of (matched_category, confidence, matched_keyword) if found, else (None, None, None)
        """
        if not text or not hasattr(self, '_category_keyword_metadata') or not self._category_keyword_metadata:
            return None, None, None
            
        text_lower = text.lower().strip()
        
        # First check for exact matches in keyword metadata
        for category, keyword_list in self._category_keyword_metadata.items():
            if not keyword_list:
                continue
                
            for kw_meta in keyword_list:
                if not isinstance(kw_meta, dict):
                    continue
                    
                keyword = kw_meta.get('keyword', '').lower()
                match_type = kw_meta.get('match_type', 'PARTIAL').upper()
                
                # Only process exact matches
                if match_type != 'EXACT':
                    continue
                    
                if keyword == text_lower:
                    # Found an exact match, return with high confidence
                    confidence = float(kw_meta.get('weight', 1.0))
                    return category, confidence, keyword
        
        # If we get here, no exact match was found
        return None, None, None

    def _keyword_scores_with_matches(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        scores: Dict[str, float] = {}
        matched: Dict[str, List[str]] = {}
        t = (text or '').lower()

        # [REMOVED] Hardcoded overrides. Trusting governance tables below.


        if not hasattr(self, '_category_keyword_metadata') or not self._category_keyword_metadata:
            logger.warning("No category keyword metadata loaded from governance tables")
            return scores, matched

        for category, keyword_list in self._category_keyword_metadata.items():
            if not keyword_list:
                continue

            total_weighted_score = 0.0
            match_count = 0
            cat_matches: List[str] = []
            contribs: List[float] = []

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
                        if re.search(r'(?:^|[^a-zA-Z0-9])' + re.escape(keyword) + r'(?:$|[^a-zA-Z0-9])', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                        elif re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 1.0
                    elif match_type == 'CONTAINS':
                        if keyword in t:
                            matched_flag = True
                            match_quality = 0.9
                    elif match_type == 'PARTIAL':
                        # IMPROVED: Use word boundary matching for PARTIAL to prevent false positives
                        # For keywords < 6 chars, require exact word match to avoid matching substrings
                        # For longer keywords, allow word-boundary prefix matching
                        try:
                            if len(keyword) < 6:
                                # Short keywords must match as complete words (e.g., "pin" won't match "spinning")
                                pattern = r'\b' + re.escape(keyword) + r'\b'
                                if re.search(pattern, t, re.IGNORECASE):
                                    matched_flag = True
                                    match_quality = 0.85
                            else:
                                # Longer keywords can match with word boundary at start
                                # This allows "password" to match "password_hash" but not "mypassword"
                                pattern = r'\b' + re.escape(keyword)
                                if re.search(pattern, t, re.IGNORECASE):
                                    matched_flag = True
                                    match_quality = 0.8
                        except Exception:
                            # Fallback to simple substring if regex fails
                            if keyword in t:
                                matched_flag = True
                                match_quality = 0.7
                    elif match_type == 'REGEX':
                        if re.search(keyword, t, re.IGNORECASE):
                            matched_flag = True
                            match_quality = 0.9
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
                    contribution = max(0.0, min(1.0, float(base_score) * float(weight) * float(match_quality)))
                    total_weighted_score += contribution
                    contribs.append(contribution)
                    cat_matches.append(keyword)
                    logger.debug(f"    Keyword match: '{keyword}' ({match_type})   score={contribution:.3f}")

            if match_count > 0:
                threshold = getattr(self, '_category_thresholds', {}).get(category, 0.30)
                category_weight = getattr(self, '_category_weights', {}).get(category, 1.0)
                prob_not = 1.0
                for c in contribs:
                    prob_not *= (1.0 - c)
                combined = 1.0 - prob_not
                final_score = min(1.0, combined * category_weight)

                if final_score >= threshold:
                    scores[category] = final_score
                    matched[category] = cat_matches
                    logger.debug(f"    Keyword score: {category} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                else:
                    logger.debug(f"    Below threshold: {category} = {final_score:.2f} < {threshold:.2f}")

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
                        # Get all detected categories if available, otherwise use primary category
                        if col.get('detected_categories'):
                            # Get unique categories while preserving order
                            categories = []
                            seen = set()
                            for d in col['detected_categories']:
                                cat = d.get('category')
                                if cat and cat not in seen:
                                    categories.append(cat)
                                    seen.add(cat)
                            category = ', '.join(categories)
                            rationale = f"Detected: {category}"
                        else:
                            category = col.get('category', 'Unknown')
                            rationale = ""
                            
                        # Derive compliance name if missing
                        policy_group = col.get('policy_group')
                        if not policy_group:
                            # Use first category for policy group mapping if multiple categories exist
                            primary_category = category.split(',')[0].strip()
                            policy_group = self._map_category_to_policy_group(primary_category) or 'None'
                            
                        # Get sensitivity name from label if available, else fallback to primary category
                        sensitivity = col.get('label') or category.split(',')[0].strip()
                        
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
                    
                    try:
                        # Handle AI_CATEGORY extraction
                        row_data['ai_category'] = str(row.get('AI_CATEGORY', '') or '').strip() or 'Unknown'
                    except Exception as e:
                        logger.debug(f"Error getting AI_CATEGORY: {e}")
                        row_data['ai_category'] = 'Unknown'

                    # CRITICAL FIX: Extract multi-category info from DETAILS if available
                    # This ensures the Table View matches the Drill-Down view for columns with multiple categories
                    try:
                        details_raw = row.get('DETAILS')
                        multi_categories = []
                        if details_raw:
                            if isinstance(details_raw, str):
                                import json
                                try:
                                    details_json = json.loads(details_raw)
                                    multi_categories = details_json.get('detected_categories', [])
                                except Exception:
                                    pass
                            elif isinstance(details_raw, dict):
                                multi_categories = details_raw.get('detected_categories', [])
                        
                        if multi_categories and isinstance(multi_categories, list) and len(multi_categories) > 0:
                            # Use comma-separated list of all detected categories
                            categories_extracted = []
                            for c in multi_categories:
                                if isinstance(c, dict):
                                    cat_val = c.get('category')
                                    if cat_val:
                                        categories_extracted.append(str(cat_val))
                                elif isinstance(c, str):
                                    categories_extracted.append(c)
                                    
                            display_category = ', '.join(sorted(set(categories_extracted)))
                            if display_category:
                                row_data['ai_category'] = display_category
                    except Exception as e:
                        logger.debug(f"Error extracting multi-categories: {e}")
                    
                    try:
                        row_data['compliance_name'] = str(row.get('COMPLIANCE_NAME', '') or '').strip()
                    except Exception as e:
                        logger.debug(f"Error getting COMPLIANCE_NAME: {e}")
                        row_data['compliance_name'] = ''
                    
                    # If no compliance name OR if it looks like a default, try to derive from AI_CATEGORY
                    current_comp = row_data['compliance_name'].upper()
                    if not current_comp or current_comp in ('NONE', 'NULL', 'INTERNAL', 'RESTRICTED', 'CONFIDENTIAL'):
                        try:
                            derived_comp = self._map_category_to_policy_group(row_data['ai_category'])
                            if derived_comp and derived_comp not in ('NON_SENSITIVE', 'INTERNAL'):
                                row_data['compliance_name'] = derived_comp
                        except Exception as e:
                            logger.debug(f"Error mapping category to policy group: {e}")
                            if not row_data['compliance_name']:
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
                        confidence_val = row.get('FINAL_CONFIDENCE', 0.0)
                        if confidence_val is not None:
                            result['Confidence'] = float(confidence_val) * 100
                        else:
                            result['Confidence'] = 0.0
                    except (ValueError, TypeError):
                        result['Confidence'] = 0.0

                    data.append(result)
                    processed_rows += 1
                except Exception as e:
                    logger.error(f"Error processing row: {row} - {e}", exc_info=True)
                    skipped_rows += 1
                    continue  # Move to the next row

            logger.info(f"Successfully processed {processed_rows} rows, skipped {skipped_rows} rows.")
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
        """Ensure CLASSIFICATION_AI_RESULTS has all required columns per the latest schema."""
        try:
            # Check existing columns
            check_query = f"SELECT COLUMN_NAME FROM {gov_db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'DATA_CLASSIFICATION_GOVERNANCE' AND TABLE_NAME = 'CLASSIFICATION_AI_RESULTS'"
            rows = snowflake_connector.execute_query(check_query) or []
            existing_cols = {str(r.get('COLUMN_NAME', '')).upper() for r in rows}
            
            # List of required columns and their types/defaults
            required_columns = [
                ('SCHEMA_NAME', 'VARCHAR(255)'),
                ('SENSITIVITY_CATEGORY_ID', 'VARCHAR(200)'),
                ('DETAILS', 'VARIANT'),
                ('REGEX_CONFIDENCE', 'FLOAT'),
                ('KEYWORD_CONFIDENCE', 'FLOAT'),
                ('ML_CONFIDENCE', 'FLOAT'),
                ('SEMANTIC_CONFIDENCE', 'FLOAT'),
                ('SEMANTIC_CATEGORY', 'VARCHAR(16777216)'),
                ('MODEL_VERSION', 'VARCHAR(16777216)'),
                ('CREATED_AT', 'TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP()'),
                ('UPDATED_AT', 'TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP()')
            ]
            
            for col_name, col_def in required_columns:
                if col_name not in existing_cols:
                    logger.info(f"Adding missing column {col_name} to CLASSIFICATION_AI_RESULTS")
                    try:
                        snowflake_connector.execute_query(f"ALTER TABLE {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS ADD COLUMN {col_name} {col_def}")
                    except Exception as alter_err:
                        logger.warning(f"Failed to add column {col_name}: {alter_err}")

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
        
        # Get category IDs map for intfloat/e5-large-v2
        cat_ids = getattr(self, '_category_ids', {})
        model_version = getattr(self, '_model_name', 'intfloat/e5-large-v2')
        
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
                column = col.get('column_name', '')
                category = col.get('category', 'Unknown')
                final_conf = float(col.get('confidence', 0.0))
                
                # Derive granular confidence scores based on match type logic
                match_type = col.get('match_type', 'UNKNOWN').upper()
                regex_conf = 0.0
                keyword_conf = 0.0
                semantic_conf = 0.0
                ml_conf = 0.0
                semantic_cat = None
                
                if match_type in ('EXACT', 'CONTAINS', 'REGEX'):
                    regex_conf = 1.0
                    keyword_conf = 1.0
                elif match_type in ('SEMANTIC', 'PARTIAL'):
                    semantic_conf = final_conf
                    semantic_cat = category
                
                # Construct details JSON
                details_dict = {
                    'detected_categories': col.get('detected_categories', []),
                    'policy_group': col.get('policy_group'),
                    'label': col.get('label'),
                    'cia': {'c': col.get('c'), 'i': col.get('i'), 'a': col.get('a')},
                    'match_type': match_type
                }
                import json
                details = json.dumps(details_dict)
                
                cat_id = str(cat_ids.get(category, ''))
                
                # Param keys
                k_prefix = f"p{p_idx}_"
                
                values.append(f"""
                    (%({k_prefix}s)s, %({k_prefix}t)s, %({k_prefix}c)s, %({k_prefix}cat)s, 
                     %({k_prefix}rc)s, %({k_prefix}kc)s, %({k_prefix}mc)s, %({k_prefix}sc)s, 
                     %({k_prefix}fc)s, %({k_prefix}scat)s, %({k_prefix}mv)s, 
                     %({k_prefix}det)s, %({k_prefix}cid)s)
                """)
                
                params[f"{k_prefix}s"] = schema
                params[f"{k_prefix}t"] = table
                params[f"{k_prefix}c"] = column
                params[f"{k_prefix}cat"] = category
                params[f"{k_prefix}rc"] = regex_conf
                params[f"{k_prefix}kc"] = keyword_conf
                params[f"{k_prefix}mc"] = ml_conf
                params[f"{k_prefix}sc"] = semantic_conf
                params[f"{k_prefix}fc"] = final_conf
                params[f"{k_prefix}scat"] = semantic_cat
                params[f"{k_prefix}mv"] = model_version
                params[f"{k_prefix}det"] = details
                params[f"{k_prefix}cid"] = cat_id
            
            if not values:
                continue
                
            values_str = ", ".join(values)
            
            query = f"""
            MERGE INTO {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AI_RESULTS AS target
            USING (SELECT * FROM VALUES {values_str}) AS source(
                SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, 
                REGEX_CONFIDENCE, KEYWORD_CONFIDENCE, ML_CONFIDENCE, SEMANTIC_CONFIDENCE, 
                FINAL_CONFIDENCE, SEMANTIC_CATEGORY, MODEL_VERSION, 
                DETAILS, SENSITIVITY_CATEGORY_ID
            )
            ON target.SCHEMA_NAME = source.SCHEMA_NAME 
               AND target.TABLE_NAME = source.TABLE_NAME 
               AND target.COLUMN_NAME = source.COLUMN_NAME
            WHEN MATCHED THEN
                UPDATE SET 
                    target.AI_CATEGORY = source.AI_CATEGORY,
                    target.REGEX_CONFIDENCE = source.REGEX_CONFIDENCE,
                    target.KEYWORD_CONFIDENCE = source.KEYWORD_CONFIDENCE,
                    target.ML_CONFIDENCE = source.ML_CONFIDENCE,
                    target.SEMANTIC_CONFIDENCE = source.SEMANTIC_CONFIDENCE,
                    target.FINAL_CONFIDENCE = source.FINAL_CONFIDENCE,
                    target.SEMANTIC_CATEGORY = source.SEMANTIC_CATEGORY,
                    target.MODEL_VERSION = source.MODEL_VERSION,
                    target.DETAILS = PARSE_JSON(source.DETAILS),
                    target.SENSITIVITY_CATEGORY_ID = source.SENSITIVITY_CATEGORY_ID,
                    target.UPDATED_AT = CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN
                INSERT (
                    SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, AI_CATEGORY, 
                    REGEX_CONFIDENCE, KEYWORD_CONFIDENCE, ML_CONFIDENCE, SEMANTIC_CONFIDENCE, 
                    FINAL_CONFIDENCE, SEMANTIC_CATEGORY, MODEL_VERSION, 
                    DETAILS, SENSITIVITY_CATEGORY_ID, CREATED_AT, UPDATED_AT
                )
                VALUES (
                    source.SCHEMA_NAME, source.TABLE_NAME, source.COLUMN_NAME, source.AI_CATEGORY, 
                    source.REGEX_CONFIDENCE, source.KEYWORD_CONFIDENCE, source.ML_CONFIDENCE, source.SEMANTIC_CONFIDENCE, 
                    source.FINAL_CONFIDENCE, source.SEMANTIC_CATEGORY, source.MODEL_VERSION, 
                    PARSE_JSON(source.DETAILS), source.SENSITIVITY_CATEGORY_ID, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()
                )
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
        if getattr(self, "_tuning_done", False):
            return

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
            self._tuning_done = True
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

        # DIAGNOSTIC: Log the input category
        logger.info(f"🔍 _map_category_to_policy_group: Mapping category '{category}' (upper: '{cat_upper}')")

        # LAYER 1: Metadata-driven policy mapping from governance tables
        try:
            meta_map = getattr(self, "_policy_group_by_category", {}) or {}
            logger.info(f"  Layer 1 - Metadata map has {len(meta_map)} entries")
            if meta_map:
                logger.info(f"  Available metadata mappings: {list(meta_map.keys())[:10]}")
        except Exception as e:
            logger.warning(f"  Layer 1 - Failed to load metadata map: {e}")
            meta_map = {}

        if cat_upper in meta_map:
            mapped = str(meta_map[cat_upper]).strip().upper()
            logger.info(f"  Layer 1 SUCCESS: '{category}' → '{mapped}' (metadata)")
            return mapped
        else:
            logger.info(f"  Layer 1 MISS: '{cat_upper}' not found in metadata map")

        # LAYER 2: Enhanced keyword-based fallback with extensive pattern matching
        logger.debug("  Layer 2 - Trying pattern matching fallback")
        
        # Check for PII patterns
        pii_indicators = ['PII', 'PERSONAL', 'IDENTIFIABLE', 'PRIVATE', 'SENSITIVE', 'CUSTOMER', 'PERSON', 'NAME', 'EMAIL', 'PHONE', 'ADDRESS', 'SSN', 'SOCIAL']
        if any(indicator in cat_upper for indicator in pii_indicators):
            logger.info(f"  Layer 2 SUCCESS: '{category}' → 'PII' (pattern match)")
            return "PII"
        
        # Check for SOX patterns
        sox_indicators = ['SOX', 'SARBANES', 'OXLEY', 'FINANCIAL', 'ACCOUNTING', 'AUDIT', 'FISCAL', 'TAX', 'PAYMENT', 'SALARY', 'COMPENSATION']
        if any(indicator in cat_upper for indicator in sox_indicators):
            logger.info(f"  Layer 2 SUCCESS: '{category}' → 'SOX' (pattern match)")
            return "SOX"
        
        # Check for SOC2 patterns
        soc2_indicators = ['SOC2', 'SECURITY', 'AVAILABILITY', 'PROCESSING', 'CONFIDENTIALITY', 'PRIVACY', 'COMPLIANCE']
        if any(indicator in cat_upper for indicator in soc2_indicators):
            logger.info(f"  Layer 2 SUCCESS: '{category}' → 'SOC2' (pattern match)")
            return "SOC2"

        # LAYER 3: Safe default
        logger.info(f"  Layer 3 DEFAULT: '{category}' → 'NON_SENSITIVE' (no mapping)")
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
            cn = str(c.get("COLUMN_NAME") or "UNKNOWN")
            try:
                dt = str(c.get("DATA_TYPE") or "")
                com = str(c.get("COMMENT") or "")
                samples = self._sample_column_values(
                    database,
                    schema,
                    table,
                    cn,
                    sample_rows=int(getattr(self, "_col_sample_rows", 60) or 60)
                )
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
                    "A": int(a_level)
                })
            except Exception:
                pass
        return rows

    def _classify_assets_local(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Governance-driven asset classification"""
        return self._run_governance_driven_pipeline(db, assets)

    def _load_governance_keywords(self) -> Dict[str, Dict[str, Any]]:
        """Load governance keywords and their classification details from the database."""
        keywords = {}
        try:
            query = """
                SELECT
                    k.KEYWORD_STRING,
                    c.CATEGORY_NAME,
                    c.CONFIDENTIALITY_LEVEL AS c,
                    c.INTEGRITY_LEVEL AS i,
                    c.AVAILABILITY_LEVEL AS a
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k
                JOIN DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c ON k.CATEGORY_ID = c.CATEGORY_ID
                WHERE k.IS_ACTIVE = TRUE AND c.IS_ACTIVE = TRUE
            """
            rows = snowflake_connector.execute_query(query) or []
            for row in rows:
                kw = row.get('KEYWORD_STRING')
                if kw:
                    keywords[str(kw).upper()] = {
                        'category_name': row.get('CATEGORY_NAME'),
                        'c': row.get('C'),
                        'i': row.get('I'),
                        'a': row.get('A')
                    }
        except Exception as e:
            logger.error(f"Failed to load governance keywords: {e}")
        
        return keywords

    def _get_all_columns_batch(self, db: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Batch fetch all columns for a table (Optimization #1)."""
        try:
            query = f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT as COLUMN_COMMENT
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """
            return snowflake_connector.execute_query(query, (schema, table)) or []
        except Exception as e:
            logger.error(f"Batch column fetch failed: {e}")
            return []

    def _classify_columns_local(self, db: str, schema: str, table: str, max_cols: int = 50) -> List[Dict[str, Any]]:
        """
        Classify individual columns using governance-driven hybrid scoring.
        Refactored to reuse vectorized pipeline for consistency and performance.
        """
        try:
             asset = {'schema': schema, 'table': table}
             pipeline_results = self._run_governance_driven_pipeline(db, [asset])
             if pipeline_results and len(pipeline_results) > 0:
                 return pipeline_results[0].get('column_results', [])
             return []
        except Exception as e:
            logger.error(f"Local column classification failed: {e}")
            return []

    def _classify_columns_local_DEPRECATED(self, db: str, schema: str, table: str, max_cols: int = 50) -> List[Dict[str, Any]]:
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

            start_time = time.time() # Optimization #6: Monitoring

            # Fetch columns from information_schema
            # Optimization #1: Use Batch Query
            cols = self._get_all_columns_batch(db, schema, table)
            
            if not cols:
                logger.warning(f"No columns found for {db}.{schema}.{table}")
                return results
                
            # Limit columns
            cols = cols[:max_cols]

            logger.info(f"Column-level classification: {db}.{schema}.{table} with {len(cols)} columns")

            # Governance-driven keyword override
            # UPGRADED: Use Unified Detection for Column Names (matches Drill-Down logic)
            # This supports EXACT, CONTAINS, REGEX, and Name-based SEMANTIC matches
            columns_to_process = []
            for col in cols:
                col_name = col['COLUMN_NAME']
                col_data_type = col['DATA_TYPE']
                col_comment = col.get('COMMENT')
                
                # Run the robust detection (same as Drill-Down)
                matches = self._exact_match_keyword_detection(db, col_name)
                
                # If we have a confident match based on name, use it directly
                # This catches SSN, PII, etc. without needing data sampling
                if matches and matches[0]['confidence'] >= 0.8:
                    best = matches[0]
                    cat = best['category']
                    conf = best['confidence']
                    
                    # Determine Sensitivity/Policy Group
                    pg = self._map_category_to_policy_group(cat)
                    
                    # Determine CIA & Label (Replicating logic)
                    if pg == 'PII' or pg == 'SOX': 
                        c, i, a = 3, 3, 3
                        sensitivity = 'CRITICAL'
                    elif pg == 'SOC2': 
                        c, i, a = 2, 2, 2
                        sensitivity = 'HIGH'
                    else: 
                        c, i, a = 1, 1, 1
                        sensitivity = 'MEDIUM'
                        
                    label = self._map_cia_to_label(c, i, a) if hasattr(self, '_map_cia_to_label') else sensitivity

                    results.append({
                        'column': col_name,
                        'data_type': col_data_type,
                        'comment': col_comment,
                        'category': cat,
                        'confidence': conf,
                        'confidence_pct': round(conf * 100.0, 1),
                        'label': label,
                        'c': c, 'i': i, 'a': a,
                        'scores': {m['category']: m['confidence'] for m in matches},
                        'detected_categories': matches,
                        'match_type': best.get('match_type', 'UNKNOWN')
                    })
                    logger.info(f"    ✅ Quick Match: {col_name} -> {cat} ({best.get('match_type')})")
                else:
                    # No confident name match - process deep inspection (sampling)
                    columns_to_process.append(col)
            
            if not columns_to_process:
                logger.info(f"All columns classified by keyword override. Duration: {time.time() - start_time:.2f}s")
                return results

            # Batch sample values
            col_names = [c['COLUMN_NAME'] for c in columns_to_process]
            batch_samples = self._sample_table_values_batch(db, schema, table, col_names, limit=20)

            # Load exclusion patterns from governance view (VW_EXCLUSION_PATTERNS)
            # New structure: Dict[str, Dict] where each exclusion type has 'keywords' list
            exclusion_patterns_dict: Dict[str, Dict[str, Any]] = {}
            try:
                if getattr(self, "_exclusion_patterns", None):
                    exclusion_patterns_dict = dict(self._exclusion_patterns or {})
                elif getattr(self, "_rules_loader", None):
                    exclusion_patterns_dict = self._rules_loader.load_exclusion_patterns() or {}
                    self._exclusion_patterns = dict(exclusion_patterns_dict)  # cache the dict
            except Exception as e:
                logger.debug(f"Failed to load exclusion patterns: {e}")

            # Convert dict structure to list format for compatibility with existing code
            # Each exclusion type becomes a row with its keywords and factors
            exclusion_rows: List[Dict[str, Any]] = []
            for exc_type, exc_data in exclusion_patterns_dict.items():
                try:
                    keywords_list = exc_data.get('keywords', [])
                    exclusion_rows.append({
                        'EXCLUSION_TYPE': exc_type,
                        'REDUCE_PII_FACTOR': exc_data.get('reduce_pii_factor', 1.0),
                        'REDUCE_SOX_FACTOR': exc_data.get('reduce_sox_factor', 1.0),
                        'REDUCE_SOC2_FACTOR': exc_data.get('reduce_soc2_factor', 1.0),
                        'DESCRIPTION': exc_data.get('description', ''),
                        '__PAT_LIST__': [str(kw).lower() for kw in keywords_list if kw]
                    })
                except Exception:
                    continue
            
            logger.debug(f"Loaded {len(exclusion_rows)} exclusion pattern types with {sum(len(r.get('__PAT_LIST__', [])) for r in exclusion_rows)} total keywords")

            def _pattern_hit(name_lc: str, pat: str) -> bool:
                """Return True if the lowercase column name matches the pattern. Supports basic % wildcards."""
                p = pat
                if not p:
                    return False
                if '%' in p or '_' in p:
                    # Simplified LIKE handling
                    if p.startswith('%') and p.endswith('%') and len(p) > 2:
                        core = p.strip('%')
                        return bool(core) and core in name_lc
                    if p.startswith('%') and not p.endswith('%'):
                        core = p[1:]
                        return bool(core) and name_lc.endswith(core)
                    if p.endswith('%') and not p.startswith('%'):
                        core = p[:-1]
                        return bool(core) and name_lc.startswith(core)
                    core = p.replace('%', '')
                    return bool(core) and core in name_lc
                # For plain tokens, prefer word-boundary style containment when possible
                try:
                    return bool(re.search(r'(?:^|[^a-z0-9_])' + re.escape(p) + r'(?:$|[^a-z0-9_])', name_lc)) or (p in name_lc)
                except Exception:
                    return p in name_lc

            def _exclusion_reductions(col_nm: str) -> Dict[str, float]:
                """Compute reduction multipliers per policy group based on matching exclusion patterns.
                Returns multipliers in (0,1], keys: 'PII','SOX','SOC2'."""
                n = (col_nm or '').lower()
                out = {'PII': 1.0, 'SOX': 1.0, 'SOC2': 1.0}
                if not n or not exclusion_rows:
                    return out
                for ex in exclusion_rows:
                    pats = ex.get('__PAT_LIST__', []) or []
                    if not pats:
                        continue
                    try:
                        hit = any(_pattern_hit(n, pat) for pat in pats)
                    except Exception:
                        hit = False
                    if not hit:
                        continue
                    try:
                        # Factors are treated as direct multipliers
                        r_pii = float(ex.get('REDUCE_PII_FACTOR', 1.0) or 1.0)
                        r_sox = float(ex.get('REDUCE_SOX_FACTOR', 1.0) or 1.0)
                        r_soc = float(ex.get('REDUCE_SOC2_FACTOR', 1.0) or 1.0)
                        out['PII'] = min(out['PII'], max(0.0, min(1.0, r_pii)))
                        out['SOX'] = min(out['SOX'], max(0.0, min(1.0, r_sox)))
                        out['SOC2'] = min(out['SOC2'], max(0.0, min(1.0, r_soc)))
                    except Exception:
                        continue
                return out

            # Iterate only over columns needing deep inspection
            for col in columns_to_process:
                try:
                    col_name = col['COLUMN_NAME']
                    col_samples = batch_samples.get(col_name, [])

                    # Compute exclusion reductions (do not hard-exclude at this stage)
                    try:
                        reductions = _exclusion_reductions(col_name)
                    except Exception:
                        reductions = {'PII': 1.0, 'SOX': 1.0, 'SOC2': 1.0}

                    # Use the shared governance-driven method
                    result = self._classify_column_governance_driven(
                        db, schema, table, col, pre_fetched_samples=col_samples
                    )
                    
                    # CRITICAL: Skip if None (non-sensitive column)
                    if result is None:
                        logger.debug(f"  Skipping non-sensitive column: {col_name}")
                        continue

                    # Comment override logic
                    try:
                        comment_str = str(col.get('COLUMN_COMMENT', ''))
                        if ':' in comment_str:
                            comment_cat_str = comment_str.split(':')[0].strip().upper()
                            comment_cats = [c.strip() for c in comment_cat_str.split('/')]
                            
                            data_taxonomy = {'PII', 'FINANCIAL', 'CREDENTIALS', 'HEALTH', 'INTERNAL'}
                            framework_taxonomy = {'GDPR', 'CCPA', 'HIPAA', 'PCI', 'SOX', 'SOC2'}
                            
                            found_cat = None
                            found_frameworks = []

                            for cat in comment_cats:
                                if cat in data_taxonomy:
                                    found_cat = cat
                                elif cat in framework_taxonomy:
                                    found_frameworks.append(cat)

                            if found_cat:
                                result['category'] = found_cat
                                result['confidence'] = 0.99 # Override confidence
                                result['confidence_pct'] = 99.0
                                logger.info(f"    COMMENT OVERRIDE: {col_name} -> {found_cat} (from comment)")
                            if found_frameworks:
                                result['frameworks'] = list(set((result.get('frameworks') or []) + found_frameworks))

                    except Exception as e:
                        logger.warning(f"Comment parsing failed for {col_name}: {e}")

                    # Address-first dominance: if name looks like address parts, force PII
                    try:
                        name_lc = (col_name or '').lower()
                        addr_tokens = [
                            'address', 'addr', 'street', 'st_', 'stname', 'city', 'town', 'state', 'province',
                            'zip', 'zipcode', 'postal', 'postcode', 'country', 'location', 'geo_', 'lat', 'lon',
                            'billing_', 'shipping_', 'mailing_', 'home_', 'delivery_', 'physical_'
                        ]
                        is_address_like = any(tok in name_lc for tok in addr_tokens)
                        # Use policy-group mapping for the detected category to decide dominance
                        try:
                            pg_current = self._map_category_to_policy_group(str(result.get('category','')))
                        except Exception:
                            pg_current = None
                        if is_address_like and pg_current in {'SOX','SOC2'}:
                            prev_cat = result.get('category')
                            prev_conf = float(result.get('confidence', 0.0) or 0.0)
                            result['category'] = 'PII'
                            result['policy_group'] = 'PII'
                            # Boost confidence to ensure dominance in UI
                            result['confidence'] = max(prev_conf, 0.80)
                            result['confidence_pct'] = round(result['confidence'] * 100.0, 1)
                            # Ensure CIA and label are at least Restricted defaults
                            try:
                                c, i, a = self.ai_service.CIA_MAPPING.get('PII', (2,2,2))  # type: ignore
                            except Exception:
                                c, i, a = (2,2,2)
                            result['c'], result['i'], result['a'] = c, i, a
                            if result['confidence'] >= 0.20:
                                result['label'] = 'Restricted' if max(c,i,a) >= 3 else 'Confidential'
                            else:
                                result['label'] = 'Uncertain'
                            logger.info(f"    ⚖️ Address dominance applied: {col_name} {prev_cat}->{result['category']} conf {prev_conf:.2f}->{result['confidence']:.2f}")
                        # Apply exclusion reductions AFTER address dominance; do not reduce PII for address-like
                        # Determine policy group from category
                        cat_upper = str(result.get('category','')).upper()
                        
                        # CRITICAL FIX: Ignore exclusion reductions for high-confidence PII/SSN
                        # This prevents patterns like '%security%' from blocking PII
                        is_strong_pii = False
                        if cat_upper == 'PII':
                            if float(result.get('confidence', 0.0)) >= 0.8:
                                is_strong_pii = True
                                logger.debug(f"    🛡️ PII Protection: Ignoring exclusion reductions for {col_name} ({cat_upper})")

                        if not is_address_like and not is_strong_pii and cat_upper in {'PII','SOX','SOC2'}:
                            try:
                                mult = float(reductions.get(cat_upper, 1.0) or 1.0)
                                if mult < 1.0:
                                    prev_conf2 = float(result.get('confidence', 0.0) or 0.0)
                                    new_conf = max(0.0, min(1.0, prev_conf2 * mult))
                                    result['confidence'] = new_conf
                                    result['confidence_pct'] = round(new_conf * 100.0, 1)
                                    # Recompute label if needed
                                    if new_conf < 0.20:
                                        result['label'] = 'Uncertain'
                                    logger.debug(f"    Exclusion reduction applied: {col_name} {cat_upper} x{mult:.2f} {prev_conf2:.2f}->{new_conf:.2f}")
                            except Exception:
                                pass
                    except Exception:
                        pass
                    
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

                    # UI Display Logic
                    if result.get('multi_label_category') and result.get('detected_categories'):
                        # TRUST GOVERNANCE DETECTION: Use the multi-label string directly
                        # This ensures "PII, SOX" is displayed instead of just "PII"
                        result['category'] = result['multi_label_category']
                        result['raw_category'] = result['multi_label_category']
                    else:
                        # FALLBACK: Normalize category to DATA taxonomy for display
                        try:
                            orig_cat = str(result.get('category') or '')
                            name_lc = str(col.get('COLUMN_NAME') or '').lower()
                            comment_lc = str(col.get('COLUMN_COMMENT') or '').lower()

                            # Map legacy/internal categories to taxonomy
                            legacy_map = {
                                'PERSONAL_DATA': 'PII', 'PERSONAL DATA': 'PII', 'PERSONAL': 'PII', 'PII': 'PII',
                                'FINANCIAL_DATA': 'FINANCIAL', 'FINANCIAL DATA': 'FINANCIAL', 'FINANCIAL': 'FINANCIAL', 'SOX': 'FINANCIAL',
                                'TRADESECRET': 'INTERNAL', 'PROPRIETARY_DATA': 'INTERNAL', 'PROPRIETARY DATA': 'INTERNAL',
                                'REGULATORY_DATA': 'PII', 'REGULATORY DATA': 'PII', 'REGULATORY': 'PII', 'SOC2': 'PII',
                                'INTERNAL_DATA': 'INTERNAL', 'INTERNAL DATA': 'INTERNAL', 'INTERNAL': 'INTERNAL',
                            }
                            display_cat = legacy_map.get(orig_cat.strip().upper(), None) or 'INTERNAL'



                            result['raw_category'] = orig_cat
                            result['category'] = display_cat
                        except Exception:
                            # If anything goes wrong, keep original
                            pass

                    # Debug logging for the result
                    logger.debug(f"Column result - {result.get('column')}: "
                               f"cat={result.get('category')}, (raw={result.get('raw_category', '')}) "
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

            # Optimization: Check batch cache first
            if asset.get('database') and asset.get('schema') and asset.get('table') and hasattr(self, "_cache"):
                ck_meta = f"meta_cols::{asset['database']}::{asset['schema']}::{asset['table']}"
                if ck_meta in self._cache:
                    cols = self._cache[ck_meta]
            
            if not cols:
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
                        f"FROM {asset['full_name']} LIMIT 1"
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
                            f"WHERE \"{cn}\" IS NOT NULL LIMIT 1"
                        )
                        lrows = snowflake_connector.execute_query(qlen) or []
                        if lrows:
                            avgl = float(list(lrows[0].values())[0] or 0.0)
                            stats_map.setdefault(cn, {})
                            stats_map[cn].update({"avg_len": avgl})
                except Exception:
                    pass
                try:
                    limit_n = max(max_vals * 2, 20)
                    q = (
                        f"SELECT \"{cn}\" AS V FROM {asset['full_name']} SAMPLE ({max_vals*10} ROWS) "
                        f"WHERE \"{cn}\" IS NOT NULL LIMIT {limit_n}"
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
                        IS_NULLABLE,
                        CHARACTER_MAXIMUM_LENGTH,
                        COMMENT,
                        ORDINAL_POSITION
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
                
                # Pre-populate granular cache for batch processing
                try:
                    from collections import defaultdict
                    by_table = defaultdict(list)
                    for r in c_rows:
                        # Ensure compatibility with DataFrame structure AND list structure
                        # DataFrame uses keys as columns
                        # Granular cache uses list of dicts
                        s = r.get('TABLE_SCHEMA')
                        t = r.get('TABLE_NAME')
                        if s and t:
                            key = f"{s}.{t}"
                            # Normalize for granular usage:
                            # _batch_fetch expects: COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COMMENT, COLUMN_COMMENT, ORDINAL_POSITION
                            
                            # Create a normalized dict for the cache
                            r_norm = {
                                'COLUMN_NAME': r.get('COLUMN_NAME'),
                                'DATA_TYPE': r.get('DATA_TYPE'),
                                'IS_NULLABLE': r.get('IS_NULLABLE'),
                                'CHARACTER_MAXIMUM_LENGTH': r.get('CHARACTER_MAXIMUM_LENGTH'),
                                'COMMENT': r.get('COMMENT'),
                                'COLUMN_COMMENT': r.get('COMMENT'), # Alias for compatibility
                                'ORDINAL_POSITION': r.get('ORDINAL_POSITION')
                            }
                            by_table[key].append(r_norm)
                            
                        # Ensure 'COLUMN_COMMENT' exists for DataFrame (UI) compatibility
                        if 'COMMENT' in r and 'COLUMN_COMMENT' not in r:
                            r['COLUMN_COMMENT'] = r['COMMENT']
                            
                    # Start populating cache
                    if hasattr(self, "_cache"):
                         for t_key, cols_list in by_table.items():
                             # t_key is schema.table
                             # Split safely
                             parts = t_key.split('.')
                             if len(parts) == 2:
                                 sc, tb = parts
                                 ck_granular = f"meta_cols::{db}::{sc}::{tb}"
                                 self._cache[ck_granular] = cols_list
                                 
                except Exception as e:
                    logger.debug(f"Failed to populate granular cache in _collect_metadata: {e}")

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

    def _apply_results_to_snowflake(self, results: List[Dict[str, Any]]) -> None:
        """
        Apply the classification results to Snowflake using the tagging service.
        Ensures consistency across Guided Workflow, Bulk Upload, and AI Assistant.
        """
        try:
            from src.services.tagging_service import tagging_service
            
            success_count = 0
            fail_count = 0
            total = len(results)
            
            if total == 0:
                st.warning("No results to apply.")
                return

            progress_bar = st.progress(0, text="Applying tags to Snowflake...")
            
            for i, res in enumerate(results):
                try:
                    asset = res.get('asset', {})
                    full_name = asset.get('full_name')
                    if not full_name:
                        continue
                        
                    # 1. Extract Table Level Tags
                    c_val = int(res.get('c', 1))
                    i_val = int(res.get('i', 1))
                    a_val = int(res.get('a', 1))
                    label = res.get('label', 'Internal')
                    
                    table_tags = {
                        "DATA_CLASSIFICATION": label,
                        "CONFIDENTIALITY_LEVEL": str(c_val),
                        "INTEGRITY_LEVEL": str(i_val),
                        "AVAILABILITY_LEVEL": str(a_val)
                    }
                    
                    # Apply to Table
                    tagging_service.apply_tags_to_object(full_name, "TABLE", table_tags)
                    
                    # 2. Extract and Apply Column Level Tags
                    column_results = res.get('column_results', [])
                    for col_res in column_results:
                        col_name = col_res.get('column')
                        if not col_name:
                            continue
                            
                        col_c = int(col_res.get('c', 1))
                        # Default I/A to 1 if not specific for column, or inherit from table? 
                        # Usually columns primarily drive Confidentiality.
                        # Let's use the explicit results if available.
                        col_label = col_res.get('label', 'Internal')
                        
                        col_tags = {
                            "DATA_CLASSIFICATION": col_label,
                            "CONFIDENTIALITY_LEVEL": str(col_c)
                        }
                        
                        tagging_service.apply_tags_to_column(full_name, col_name, col_tags)
                        
                    success_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to apply tags for {res.get('asset', {}).get('full_name')}: {e}")
                    fail_count += 1
                
                progress_bar.progress((i + 1) / total, text=f"Processing {i+1}/{total} assets...")
            
            progress_bar.empty()
            
            if fail_count > 0:
                st.warning(f"Applied tags to {success_count} assets, but {fail_count} failed. Check logs.")
            else:
                st.success(f"✅ Successfully applied tags to all {success_count} assets in Snowflake!")
                
        except Exception as e:
            st.error(f"Failed to initialize tagging process: {e}")

    def _display_classification_results(self, results: List[Dict[str, Any]]) -> None:
        """Display the classification results with a dropdown for table selection."""
        # ACTION BUTTON: Apply to Snowflake
        c_act1, c_act2 = st.columns([2, 5])
        with c_act1:
            if st.button("🚀 Apply All to Snowflake", type="primary", help="Apply these classification results as Snowflake Tags (DATA_CLASSIFICATION, C/I/A Levels)"):
                self._apply_results_to_snowflake(results)
        
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
            
            # Append to display list
            display_data.append({
                "Schema": asset.get('schema', 'N/A'),
                "Table": asset.get('table', 'N/A'),
                "Sensitive Columns": result.get('column_count', 0),
                "Category": result.get('multi_label_category', result.get('category', 'N/A')),
                "Sensitivity": result.get('label', 'N/A'),
                "Confidentiality": c_label,
                "Integrity": i_label,
                "Availability": a_label,
                "Color": result.get('label', 'Internal') # Used for styling
            })

        # Create DataFrame
        if display_data:
            results_df = pd.DataFrame(display_data)

            # Styling Logic
            mp = {
                'Confidential': '#ffe5e5', # Red
                'Restricted': '#fff0e1',   # Orange
                'Internal': '#fffbe5',     # Yellow
                'Public': '#e9fbe5',       # Green
            }
            fg = '#000000'

            def _apply_classification_style(row: pd.Series):
                col_name = 'Sensitivity'
                col = str(row.get('Sensitivity', '') or '')
                bg = mp.get(col, '')
                # Also check if 'Confidential' is in the string for robustness
                if not bg:
                     if 'Confidential' in col: bg = '#ffe5e5'
                     elif 'Restricted' in col: bg = '#fff0e1'
                     elif 'Internal' in col: bg = '#fffbe5'
                     elif 'Public' in col: bg = '#e9fbe5'

                styles = ['' for _ in row.index]
                try:
                    idx = list(row.index).index(col_name)
                    if bg:
                        styles[idx] = f'background-color: {bg}; color: {fg}; font-weight: 600'
                except Exception:
                    pass
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
                    st.write(f"**Category:** {result.get('multi_label_category', result.get('category', 'N/A'))}")
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
                            and r.get('policy_group') in {'PII', 'SOX', 'SOC2'}
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
                                    # Prefer multi-label string if available, otherwise fallback to policy group
                                    "Category": col.get('multi_label_category') if col.get('multi_label_category') else (display_cat if display_cat is not None else 'N/A'),
                                    "Matched Keyword": col.get('matched_keyword', 'N/A'),
                                    "Match Type": col.get('match_type', 'N/A'),
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
                                st.dataframe(styled_df, hide_index=True, width='stretch')
                                
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
            # CRITICAL FIX: E5 requires 'query:' for input text when matching against 'passage:' centroids\r\n            # This backend check MUST match the one used during centroid creation (line ~1859)
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
                self._embedding_cache = SimpleLRUCache(max_size=5000)
                
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
        PHASE 3: Two-Stage Adaptive Confidence Scoring with Governance Metadata
        
        TWO-STAGE CLASSIFICATION LOGIC:
        Stage 1: Attempt exact keyword/pattern matches from governance tables
        Stage 2: If no exact matches found, fall back to semantic search
        
        This ensures that explicit keyword matches from SENSITIVE_KEYWORDS table
        are prioritized over contextual semantic similarity.
        
        CRITICAL FIXES:
        - Default threshold lowered from 0.65 to 0.45
        - Intelligent weight adjustment based on available signals
        - Quality-based calibration for context richness
        - Multiplicative boosting for strong signals
        - NO min-max normalization (preserves absolute confidence)
        """
        scores = {}
        
        # ========================================================================
        # STAGE 1: EXACT KEYWORD/PATTERN MATCHING
        # ========================================================================
        # First, attempt to find exact matches using keywords and patterns from
        # the SENSITIVE_KEYWORDS and SENSITIVE_PATTERNS governance tables
        
        logger.info(f"🔍 STAGE 1: Attempting exact keyword/pattern matches...")
        keyword_scores = self._keyword_scores(text)
        pattern_scores = self._pattern_scores_governance_driven(text)
        
        # Check if we have any exact matches (keyword or pattern)
        exact_match_categories = set(list(keyword_scores.keys()) + list(pattern_scores.keys()))
        has_exact_matches = len(exact_match_categories) > 0
        
        if has_exact_matches:
            logger.info(f"✅ STAGE 1: Found {len(exact_match_categories)} exact matches: {exact_match_categories}")
            logger.info(f"   → Skipping semantic search (exact matches take priority)")
            
            # Use ONLY exact matches - no semantic search needed
            semantic_scores = {}
        else:
            logger.info(f"⚠️ STAGE 1: No exact keyword/pattern matches found")
            logger.info(f"🔍 STAGE 2: Falling back to semantic search...")
            
            # No exact matches - fall back to semantic search
            semantic_scores = self._semantic_scores_governance_driven(text)
            logger.info(f"✅ STAGE 2: Semantic search returned {len(semantic_scores)} categories")
        
        # ========================================================================
        # COMBINE SCORES BASED ON STAGE
        # ========================================================================
        
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
            
            # INTELLIGENT WEIGHT ADJUSTMENT based on whether we have exact matches
            if has_exact_matches:
                # STAGE 1: Exact matches found - prioritize keyword/pattern scores
                # Give 80% weight to exact matches (keyword+pattern), 20% to semantic (if any)
                weights = self._category_scoring_weights.get(category, {'w_sem': 0.20, 'w_kw': 0.50, 'w_pat': 0.30})
                w_sem = 0.20  # Minimal semantic weight when exact matches exist
                w_kw = 0.50   # High keyword weight
                w_pat = 0.30  # High pattern weight
            else:
                # STAGE 2: No exact matches - rely on semantic search
                # Give 80% weight to semantic, 20% to keyword/pattern (if any weak matches)
                weights = self._category_scoring_weights.get(category, {'w_sem': 0.80, 'w_kw': 0.10, 'w_pat': 0.10})
                w_sem = 0.80  # High semantic weight when no exact matches
                w_kw = 0.10   # Minimal keyword weight
                w_pat = 0.10  # Minimal pattern weight
            
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
            
            # ADAPTIVE THRESHOLD from governance (DEFAULT 0.30 - LOWERED for better recall)
            threshold = self._category_thresholds.get(category, 0.30)
            
            # Only include if above threshold
            if final_score >= threshold:
                scores[category] = final_score
                stage_indicator = "EXACT" if has_exact_matches else "SEMANTIC"
                logger.debug(
                    f"✓ {category} [{stage_indicator}]: base={base_score:.3f}, final={final_score:.3f}, threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
            else:
                logger.debug(
                    f"✗ {category}: final={final_score:.3f} < threshold={threshold:.3f} "
                    f"[{signal_type}] (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
                )
        
        stage_used = "EXACT MATCH" if has_exact_matches else "SEMANTIC SEARCH"
        logger.info(f"📊 Classification completed using {stage_used}: {len(scores)} categories passed threshold")
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
                                        pre_fetched_samples: List[Any] = None,
                                        precomputed_embeddings: Optional[Dict[str, np.ndarray]] = None) -> Dict[str, Any]:
        """
        Detects sensitive columns with strict priority:
        1. Exact keyword matching from governance tables (using name, type, comment)
        2. Semantic search only if no exact matches found
        """
        
        col_name = column['COLUMN_NAME']
        data_type = column['DATA_TYPE']
        col_comment = column.get('COLUMN_COMMENT', '')
        
        # 1. Load active governance rules (keywords)
        active_keywords = self._load_active_governance_keywords(db)
        
        # 2. Build search context from ALL available metadata
        search_contexts = [
            col_name.lower(),
            f"{col_name} {data_type}".lower(),
            col_comment.lower() if col_comment else ""
        ]
        
        # PRIORITY 1: Exact keyword matching
        exact_matches = []
        
        for context in search_contexts:
            if context:  # Skip empty contexts
                matches = self._perform_exact_keyword_matching(context, active_keywords)
                if matches:
                    exact_matches.extend(matches)
        
        # If we found exact matches, use them and skip semantic search
        if exact_matches:
            # Deduplicate and pick highest confidence match
            detected_categories = self._deduplicate_matches(exact_matches)
            best_match = detected_categories[0]
            
            # Calculate CIA and Label based on category
            cat_upper = best_match['category'].upper()
            c, i, a = 1, 1, 1
            label = 'Internal'
            
            if any(x in cat_upper for x in ['PII', 'CONFIDENTIAL', 'HIPAA', 'PCI', 'SSN', 'SOCIAL', 'PASSPORT']):
                c, i, a = 3, 2, 2
                label = 'Confidential'
            elif any(x in cat_upper for x in ['SOX', 'FINANCIAL', 'REVENUE', 'SALARY']):
                c, i, a = 2, 3, 2
                label = 'Restricted'
            elif any(x in cat_upper for x in ['RESTRICTED', 'SENSITIVE', 'SOC2', 'GDPR', 'CCPA']):
                c, i, a = 2, 2, 2
                label = 'Restricted'
            elif 'PUBLIC' in cat_upper:
                c, i, a = 0, 0, 0
                label = 'Public'
            
            return {
                'schema': schema,
                'table': table,
                'column_name': col_name,
                'data_type': data_type,
                'category': best_match['category'],
                'confidence': best_match['confidence'],
                'status': 'SENSITIVE',
                'detected_categories': detected_categories,
                'method': 'EXACT_KEYWORD',
                'match_type': best_match['match_type'],
                'matched_keyword': best_match['keyword_string'],
                'policy_group': self._map_category_to_policy_group(best_match['category']),
                # Basic UI fields
                'column': col_name,
                'c': c, 'i': i, 'a': a,
                'label': label,
                'confidence_pct': best_match['confidence'] * 100
            }

        # PRIORITY 2: Semantic search (ONLY if no exact matches)
        # We combine name and comment for semantic context
        semantic_context = f"{col_name}"
        if col_comment:
            semantic_context += f" {col_comment}"
            
        semantic_matches = self._perform_semantic_classification(db, semantic_context, precomputed_embeddings=precomputed_embeddings)
        
        if semantic_matches:
            detected_categories = self._deduplicate_matches(semantic_matches)
            best_semantic = detected_categories[0]
            
            # Filter low confidence semantic matches if needed, but assuming _perform_semantic_classification does it
            if best_semantic['confidence'] >= 0.40:
                # Calculate CIA and Label based on category
                cat_upper = best_semantic['category'].upper()
                c, i, a = 1, 1, 1
                label = 'Internal'
                
                if any(x in cat_upper for x in ['PII', 'CONFIDENTIAL', 'HIPAA', 'PCI', 'SSN', 'SOCIAL', 'PASSPORT']):
                    c, i, a = 3, 2, 2
                    label = 'Confidential'
                elif any(x in cat_upper for x in ['SOX', 'FINANCIAL', 'REVENUE', 'SALARY']):
                    c, i, a = 2, 3, 2
                    label = 'Restricted'
                elif any(x in cat_upper for x in ['RESTRICTED', 'SENSITIVE', 'SOC2', 'GDPR', 'CCPA']):
                    c, i, a = 2, 2, 2
                    label = 'Restricted'
                elif 'PUBLIC' in cat_upper:
                    c, i, a = 0, 0, 0
                    label = 'Public'

                return {
                    'schema': schema,
                    'table': table,
                    'column_name': col_name,
                    'data_type': data_type,
                    'category': best_semantic['category'],
                    'confidence': best_semantic['confidence'],
                    'status': 'SENSITIVE',
                    'detected_categories': detected_categories,
                    'method': 'SEMANTIC',
                    'match_type': best_semantic.get('match_type', 'SEMANTIC'),
                    'matched_keyword': best_semantic.get('keyword_string', 'Semantic Match'),
                    'policy_group': self._map_category_to_policy_group(best_semantic['category']),
                    # Basic UI fields
                    'column': col_name,
                    'c': c, 'i': i, 'a': a,
                    'label': label,
                    'confidence_pct': best_semantic['confidence'] * 100
                }

        # Default to non-sensitive (return None to indicate no sensitive classification)
        return None
    # ============================================================================
    # SMART CLASSIFICATION OVERRIDE SYSTEM (PATTERN-AWARE)
    # ============================================================================
    
    def _init_address_context_registry(self):
        """
        Initialize the pattern registry for address context detection.
        STRICT MODE: Intentionally empty to prevent hardcoded logic.
        Should be populated from metadata if available.
        """
        if hasattr(self, '_address_context_registry'):
            return

        self._address_context_registry = {}

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
        Apply smart overrides based on detected address context if registry is populated.
        """
        # Strict mode: If registry is empty (no metadata), return scores as is
        if not hasattr(self, '_address_context_registry') or not self._address_context_registry:
            return scores

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
        Apply context-aware adjustments using ONLY view-based rules.
        """
        
        adjusted_scores = scores.copy()
        
        # ============================================================================
        # DATA-DRIVEN CONTEXT AWARE ADJUSTMENTS (VW_CONTEXT_AWARE_RULES)
        # ============================================================================
        # Use rules loaded from VW_CONTEXT_AWARE_RULES if available
        if hasattr(self, '_context_aware_rules') and self._context_aware_rules:
            logger.debug(f"  Applying context-aware rules from governance views ({sum(len(v) for v in self._context_aware_rules.values())} rules)")
            
            col_lower = col_name.lower()
            table_lower = table.lower()
            
            # Helper to apply rule action
            def apply_rule_action(rule, match_reason):
                action = rule.get('ACTION_TYPE', '').upper()
                factor = float(rule.get('ACTION_FACTOR', 1.0))
                pg = rule.get('POLICY_GROUP', '')
                
                if action == 'BOOST':
                    self._boost_category(adjusted_scores, pg, pg, factor)
                    logger.debug(f"    Matched {match_reason}: '{rule.get('KEYWORD_STRING')}' → BOOST {pg} x{factor}")
                elif action in ('SUPPRESS', 'REDUCE'):
                    self._reduce_category(adjusted_scores, pg, pg, factor)
                    logger.debug(f"    Matched {match_reason}: '{rule.get('KEYWORD_STRING')}' → REDUCE {pg} x{factor}")

            # 1. Table Context Rules
            for rule in self._context_aware_rules.get('TABLE_NAME', []):
                kw = rule.get('KEYWORD_STRING', '').lower()
                if kw and kw in table_lower:
                    apply_rule_action(rule, "TABLE_NAME")

            # 2. Column Name Rules (Contains)
            for rule in self._context_aware_rules.get('COLUMN_NAME', []):
                kw = rule.get('KEYWORD_STRING', '').lower()
                if kw and kw in col_lower:
                    apply_rule_action(rule, "COLUMN_NAME")

            # 3. Column Suffix Rules
            for rule in self._context_aware_rules.get('COLUMN_SUFFIX', []):
                kw = rule.get('KEYWORD_STRING', '').lower()
                if kw and col_lower.endswith(kw):
                    apply_rule_action(rule, "COLUMN_SUFFIX")
            
            # 4. Column Exact Match Rules
            for rule in self._context_aware_rules.get('COLUMN_EXACT', []):
                kw = rule.get('KEYWORD_STRING', '').lower()
                if kw and col_lower == kw:
                    apply_rule_action(rule, "COLUMN_EXACT")

            # === Rule 5: Filter out very low scores (noise reduction) ===
            # Remove categories with confidence < 0.25 after adjustments
            adjusted_scores = {cat: score for cat, score in adjusted_scores.items() if score >= 0.25}
            
            # Apply smart address overrides
            adjusted_scores = self._apply_smart_address_overrides(adjusted_scores, col_name)

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
        """
        
        # REQUIREMENT: Only proceed if we have sensitive column evidence
        if not column_results:
            logger.info("  → No sensitive columns detected - table is NON_SENSITIVE")
            return 'NON_SENSITIVE', 0.0, []
        
        # Aggregate all potential categories from table scores and column multi-label results
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
            valid_col_scores = [s for s in column_scores if s > 0.40]
            
            if not valid_col_scores:
                logger.debug(f"  → Skipping category '{category}' - no high-confidence column detections")
                continue
            
            column_avg = sum(valid_col_scores) / len(valid_col_scores)
            # Progressive coverage boost: More columns = higher confidence
            if len(valid_col_scores) >= 5:
                coverage_boost = 1.15
            elif len(valid_col_scores) >= 3:
                coverage_boost = 1.10
            else:
                coverage_boost = 1.05
            
            combined_score = max(table_score, column_avg * coverage_boost)
            combined_score = min(0.99, combined_score)
            
            # Threshold check
            thresh = self._category_thresholds.get(category, 0.40)
            
            # EXCLUDE GENERIC / NON-SENSITIVE CATEGORIES
            if category.upper() in ('NON_SENSITIVE', 'GENERAL', 'SYSTEM', 'METADATA', 'UNKNOWN'):
                continue
            
            # CRITICAL: Check if it maps to a sensitive policy group (PII/SOX/SOC2)
            pg = self._map_category_to_policy_group(category)
            if pg not in {'PII', 'SOX', 'SOC2'}:
                logger.debug(f"  → Skipping category '{category}' - does not map to PII/SOX/SOC2 (maps to: {pg})")
                continue
            
            # STRICT validation: Require minimum confidence of 0.50
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
        

        
        return best_category, best_score, detected_categories

    def _classify_table_governance_driven(self, db: str, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies a single table asset using a multi-layered approach:
        1. Exact keyword matching from governance tables.
        2. If no exact match, semantic + keyword + pattern scoring.
        3. Multi-label classification and policy group mapping.
        """
        try:
            schema = asset['schema']
            table = asset['table']
            full_name = f"{db}.{schema}.{table}"
            
            logger.info(f"Governance-driven classification for: {full_name}")
            
            # Optimization: Fetch columns ONCE using batch query (User Request #1)
            columns = self._get_all_columns_batch(db, schema, table)

            # Optimization: Build context in-memory without extra DB calls (User Request #5 - Tune Queries)
            # Use 'asset' which already contains table metadata from discovery
            col_desc_list = [
                f"{col.get('COLUMN_NAME')} ({col.get('DATA_TYPE')})"
                for col in columns
            ]
            columns_str = ", ".join(col_desc_list) if col_desc_list else ""

            comment_desc_list = [
                f"{col.get('COLUMN_NAME')}: {col.get('COLUMN_COMMENT')}"
                for col in columns
                if col.get('COLUMN_COMMENT')
            ]
            comments_str = "; ".join(comment_desc_list) if comment_desc_list else ""

            context_parts = [
                f"Table: {schema}.{table}",
                f"Type: {asset.get('table_type', 'UNKNOWN')}",
                f"Description: {asset.get('comment', '') or 'No description'}",
                f"Columns: {columns_str}",
                f"Column Comments: {comments_str}"
            ]
            table_context = " | ".join([part for part in context_parts if part])

            # Step 1: Exact Keyword Matching
            exact_match_results = self._exact_match_keyword_detection(db, table_context)

            # OPTIMIZATION: Sampling skipped as governance-driven classification uses metadata only.
            batch_samples = {}
            
            # BATCH OPTIMIZATION: Prepare semantic embeddings for all columns
            precomputed_embeddings_map = {}
            if self._embedder and self._embed_backend == 'sentence-transformers':
                all_variants = []
                
                for column in columns:
                    col_name_var = column['COLUMN_NAME']
                    col_comment_var = column.get('COLUMN_COMMENT', '')
                    
                    # Reconstruct same semantic context logic as in column classification
                    semantic_context_var = f"{col_name_var}"
                    if col_comment_var:
                        semantic_context_var += f" {col_comment_var}"
                    
                    variants = self._generate_semantic_variants(semantic_context_var)
                    all_variants.extend([f"query: {v}" for v in variants])
                
                if all_variants:
                     try:
                         # Remove duplicates to save computation
                         unique_variants = list(set(all_variants))
                         # Check cache for existing embeddings before encoding
                         new_variants = [v for v in unique_variants if v not in getattr(self, '_embedding_cache', {})]
                         
                         if new_variants:
                             new_embeddings = self._embedder.encode(new_variants, normalize_embeddings=True)
                             for v, emb in zip(new_variants, new_embeddings):
                                 # Populate cache
                                 self._get_cached_embedding(v) # Helper will handle simple sets, but here we can set directly
                                 # Actually _get_cached_embedding does encoding if missing.
                                 # Let's manually set since we batch encoded.
                                 if not hasattr(self, '_embedding_cache'): self._embedding_cache = {}
                                 self._embedding_cache[v] = emb

                         # Build map from cache
                         precomputed_embeddings_map = {v: self._get_cached_embedding(v) for v in unique_variants}
                     except Exception as e:
                         logger.warning(f"Batch embedding failed: {e}")

            column_results = []
            
            for column in columns:
                col_name = column['COLUMN_NAME']
                # Pass pre-fetched samples to avoid N+1 queries
                col_samples = batch_samples.get(col_name, [])
                
                col_result = self._classify_column_governance_driven(
                    db, schema, table, column, 
                    pre_fetched_samples=col_samples,
                    precomputed_embeddings=precomputed_embeddings_map
                )
                
                # CRITICAL: Only include sensitive columns (skip None results)
                if col_result is not None:
                    column_results.append(col_result)

            if exact_match_results:
                logger.info(f"Exact match found for {asset['schema']}.{asset['table']}. Using exact match for table-level classification.")
                table_detected_categories = exact_match_results
                table_scores = {res['category']: res['confidence'] for res in exact_match_results}
                
                # Set table_category and confidence from exact match results
                if table_detected_categories:
                    table_category = table_detected_categories[0]['category']
                    confidence = table_detected_categories[0]['confidence']
                else:
                    table_category = 'NON_SENSITIVE'
                    confidence = 0.0
            else:
                # Use semantic scoring for table-level classification
                table_scores = self._compute_governance_scores(table_context)
                
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
            
            # Calculate CIA scores based on AGGREGATION of sensitive columns (Worst Case / High Water Mark)
            # Default to Internal (C1, I1, A1)
            c, i, a = (1, 1, 1)
            
            # Check for Public
            if not multi_label_policy_groups and not policy_group and table_category == 'NON_SENSITIVE':
                c, i, a = (0, 0, 0)
                label = "Public"
            else:
                # Iterate over ALL sensitive columns to find highest impact
                for col_res in column_results:
                    # Skip non-sensitive
                    if not col_res or col_res.get('category') == 'NON_SENSITIVE':
                        continue
                        
                    # Extract column metadata
                    col_pg = col_res.get('policy_group', 'NON_SENSITIVE')
                    col_cat = str(col_res.get('category', '')).upper()
                    
                    # Determine Column CIA
                    # Default for a sensitive column is at least Restricted (C2) if we don't know better, 
                    # but let's stick to the policy mapping logic.
                    col_c, col_i, col_a = (1, 1, 1)

                    # PII Logic
                    if col_pg == 'PII':
                        # High Sensitivity PII -> Confidential (C3)
                        # Check critical PII keywords
                        if any(x in col_cat for x in ['SSN', 'TAX', 'PASSPORT', 'CREDIT', 'BANK', 'ACCOUNT', 'FINANCIAL', 'DRIVER', 'LICENSE', 'MEDICAL', 'HEALTH']):
                             col_c, col_i, col_a = (3, 3, 3)
                        else:
                             # Standard PII -> Restricted (C2)
                             col_c, col_i, col_a = (2, 2, 2)
                    
                    # SOX Logic -> Confidential (C3) per policy
                    elif col_pg == 'SOX':
                        col_c, col_i, col_a = (3, 3, 3)
                        
                    # SOC2 Logic -> Restricted (C2)
                    elif col_pg == 'SOC2':
                        col_c, col_i, col_a = (2, 2, 2)

                    # Explicit check for Secrets/Keys -> Confidential (C3)
                    if any(x in col_cat for x in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'AUTH', 'CREDENTIAL']):
                         col_c, col_i, col_a = (3, 3, 3)
                    
                    # Aggregate Max (Worst Case)
                    c = max(c, col_c)
                    i = max(i, col_i)
                    a = max(a, col_a)
                
                # Determine Label based on final C score
                if c >= 3:
                    label = "Confidential"
                elif c >= 2:
                    label = "Restricted"
                else:
                    label = "Internal"
            
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

    def _batch_fetch_columns_for_assets(self, db: str, assets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Batch fetch columns for multiple tables to eliminate N+1 queries.
        Uses cached results if available.
        Returns: Dict mapping 'schema.table' -> List[Column Dict]
        """
        if not assets:
            return {}
            
        from collections import defaultdict
        out = defaultdict(list)
        to_fetch = []
        
        # 1. Check cache first
        for asset in assets:
            s = asset.get('schema')
            t = asset.get('table')
            if not s or not t:
                continue
            
            key = f"{s}.{t}"
            cache_key = f"meta_cols::{db}::{s}::{t}"
            
            if hasattr(self, "_cache") and cache_key in self._cache:
                out[key] = self._cache[cache_key]
            else:
                to_fetch.append(asset)
                
        if not to_fetch:
            return out

        # 2. Process missing assets in chunks
        batch_size = 50 
        logger.info(f"Batch fetching columns for {len(to_fetch)}/{len(assets)} tables in chunks of {batch_size}...")
        
        for i in range(0, len(to_fetch), batch_size):
            chunk = to_fetch[i:i+batch_size]
            conds = []
            params = []
            
            for a in chunk:
                s = a.get('schema')
                t = a.get('table')
                if s and t:
                    conds.append("(TABLE_SCHEMA = %s AND TABLE_NAME = %s)")
                    params.extend([s, t])
            
            if not conds:
                continue
                
            where_clause = " OR ".join(conds)
            
            sql = f"""
                SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COMMENT, ORDINAL_POSITION
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE {where_clause}
                ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
            """
            
            try:
                rows = snowflake_connector.execute_query(sql, params) or []
                
                # Group by table
                batch_results = defaultdict(list)
                for r in rows:
                    t_key = f"{r['TABLE_SCHEMA']}.{r['TABLE_NAME']}"
                    r_norm = {
                        'COLUMN_NAME': r['COLUMN_NAME'],
                        'DATA_TYPE': r['DATA_TYPE'],
                        'IS_NULLABLE': r['IS_NULLABLE'], 
                        'CHARACTER_MAXIMUM_LENGTH': r['CHARACTER_MAXIMUM_LENGTH'],
                        'COMMENT': r['COMMENT'],
                        'COLUMN_COMMENT': r['COMMENT'], # Alias for backward compatibility
                        'ORDINAL_POSITION': r['ORDINAL_POSITION']
                    }
                    batch_results[t_key].append(r_norm)
                
                # Update output and cache
                for a in chunk:
                    s = a.get('schema')
                    t = a.get('table')
                    t_key = f"{s}.{t}"
                    cols = batch_results.get(t_key, [])
                    out[t_key] = cols
                    
                    # Cache it
                    if hasattr(self, "_cache"):
                        self._cache[f"meta_cols::{db}::{s}::{t}"] = cols
                        
            except Exception as e:
                logger.error(f"Error in batch column fetch (chunk {i}): {e}")
                
        return out

    def _get_category_policy_info(self, category: str) -> Dict[str, Any]:
        """
        Get CIA and Label info based on category's policy group.
        Fully metadata-driven, no hardcoded category names.
        """
        # 1. Get Policy Group (using robust mapping with fallbacks)
        pg = self._map_category_to_policy_group(category)
        
        # 2. Map Policy Group to CIA/Label defaults
        # Defaults if not strictly defined in _policy_defaults
        defaults = {
            'PII': {'c': 3, 'i': 2, 'a': 2, 'label': 'Confidential'},
            'SOX': {'c': 2, 'i': 3, 'a': 2, 'label': 'Restricted'},
            'SOC2': {'c': 2, 'i': 2, 'a': 2, 'label': 'Restricted'},
            'PCI': {'c': 3, 'i': 3, 'a': 3, 'label': 'Critical'},
            'HIPAA': {'c': 3, 'i': 2, 'a': 2, 'label': 'Confidential'},
            'PUBLIC': {'c': 0, 'i': 0, 'a': 0, 'label': 'Public'},
            'INTERNAL': {'c': 1, 'i': 1, 'a': 1, 'label': 'Internal'}
        }
        
        # Normalize PG for lookup
        pg_key = str(pg).upper()
        if pg_key in defaults:
            return defaults[pg_key]
            
        # Fallback based on text heuristics if Policy metadata is missing (Last Resort)
        if 'CONFIDENTIAL' in pg_key: return defaults['PII']
        if 'RESTRICTED' in pg_key: return defaults['SOX']
        
        return defaults['INTERNAL']

    def _run_governance_driven_pipeline(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Optimized high-performance pipeline using ONLY governance table data.
        Features: Batch I/O, Cached Metadata, Exact-Match-First, Vectorized processing.
        """
        results = []
        
        # Optimization: Set session parameters for observability and caching
        try:
            if snowflake_connector:
                 snowflake_connector.execute_non_query("ALTER SESSION SET QUERY_TAG = 'AI_CLASSIFICATION_PIPELINE'")
                 snowflake_connector.execute_non_query("ALTER SESSION SET USE_CACHED_RESULT = TRUE")
        except Exception as e:
             logger.warning(f"Failed to set Snowflake session parameters: {e}")
        
        # 1. Initialize Governance Metadata (ONCE)
        if not self._category_centroids:
            logger.info("Initializing governance metadata...")
            self._load_metadata_driven_categories()
            
        # Ensure keywords are loaded efficiently
        active_keywords = self._load_active_governance_keywords(db)
        
        # DIAGNOSTICS
        logger.info("=" * 80)
        logger.info(f"GOVERNANCE PIPELINE: Processing {len(assets)} assets on {db}")
        logger.info(f"Active Keywords: {len(active_keywords)}")
        logger.info("=" * 80)

        # 2. Batch Fetch Columns (Eliminate N+1)
        table_columns_map = self._batch_fetch_columns_for_assets(db, assets)
        
        # 3. Batch Processing Preparation
        assets_processed_data = {} 
        embedding_requests = set()
        
        # PASS 1: Exact Match & Filtering
        for asset in assets:
            schema = asset.get('schema')
            table = asset.get('table')
            key = f"{schema}.{table}"
            columns = table_columns_map.get(key, [])
            
            asset_col_results = []
            
            for col in columns:
                col_name = col['COLUMN_NAME']
                col_type = col['DATA_TYPE']
                col_comment = col.get('COLUMN_COMMENT', '')
                
                # Check Exact Matches
                search_contexts = [col_name.lower(), f"{col_name} {col_type}".lower()]
                if col_comment: search_contexts.append(col_comment.lower())
                
                exact_matches = []
                for ctx in search_contexts:
                    if ctx:
                        matches = self._perform_exact_keyword_matching(ctx, active_keywords)
                        if matches: exact_matches.extend(matches)
                
                if exact_matches:
                    asset_col_results.append({
                        'col': col,
                        'exact': self._deduplicate_matches(exact_matches),
                        'semantic': None
                    })
                else:
                    # Queue for embedding
                    sem_ctx = col_name
                    if col_comment: sem_ctx += f" {col_comment}"
                    variants = self._generate_semantic_variants(sem_ctx)
                    for v in variants:
                        embedding_requests.add(f"query: {v}")
                    asset_col_results.append({
                        'col': col,
                        'exact': None,
                        'semantic_pending': variants
                    })
            
            assets_processed_data[key] = asset_col_results

        # PASS 2: Batch Embeddings
        if self._embedder and self._embed_backend == 'sentence-transformers' and embedding_requests:
            logger.info(f"Computing embeddings for {len(embedding_requests)} semantic contexts...")
            needed = [t for t in embedding_requests if t not in getattr(self, '_embedding_cache', {})]
            if needed:
                emb_batch_size = 256
                for i in range(0, len(needed), emb_batch_size):
                    batch = needed[i:i+emb_batch_size]
                    try:
                        embeddings = self._embedder.encode(batch, normalize_embeddings=True)
                        if not hasattr(self, '_embedding_cache'): self._embedding_cache = {}
                        for text, emb in zip(batch, embeddings):
                            self._embedding_cache[text] = emb
                    except Exception as e:
                        logger.error(f"Embedding batch failed: {e}")
        
        # PASS 3: Final Classification
        passed_count = 0
        filtered_count = 0
        
        for asset in assets:
            schema = asset.get('schema')
            table = asset.get('table')
            key = f"{schema}.{table}"
            table_col_data = assets_processed_data.get(key, [])
            
            final_column_results = []
            
            for item in table_col_data:
                col = item['col']
                exact_res = item.get('exact')
                
                best_match = None
                match_method = None
                
                if exact_res:
                    best_match = exact_res[0]
                    match_method = 'EXACT_KEYWORD'
                else:
                   # Checked cached semantic match
                   sem_ctx = col['COLUMN_NAME']
                   if col.get('COLUMN_COMMENT'): sem_ctx += f" {col.get('COLUMN_COMMENT')}"
                   sem_matches = self._perform_semantic_classification(db, sem_ctx)
                   if sem_matches:
                         best = sem_matches[0]
                         if best['confidence'] >= 0.40:
                             best_match = best
                             match_method = 'SEMANTIC'
                
                if best_match:
                    cat = best_match['category']
                    policy_info = self._get_category_policy_info(cat)
                    
                    col_result = {
                        'schema': schema,
                        'table': table,
                        'column_name': col['COLUMN_NAME'],
                        'data_type': col['DATA_TYPE'],
                        'category': cat,
                        'confidence': best_match['confidence'],
                        'status': 'SENSITIVE',
                        'method': match_method,
                        'match_type': best_match.get('match_type', 'UNKNOWN'),
                        'matched_keyword': best_match.get('keyword_string'),
                        'policy_group': self._map_category_to_policy_group(cat),
                        'detected_categories': [best_match],
                        'column': col['COLUMN_NAME'],
                        'c': policy_info['c'],
                        'i': policy_info['i'],
                        'a': policy_info['a'],
                        'label': policy_info['label'],
                        'confidence_pct': best_match['confidence'] * 100
                    }
                    final_column_results.append(col_result)

            if final_column_results:
                final_column_results.sort(key=lambda x: (x['c'] + x['i'] + x['a'], x['confidence']), reverse=True)
                top_col = final_column_results[0]
                
                # Determine Table Policy Group (Union of column policies)
                # For simplicity, we take the top column's compliance/policy
                compliance = self._map_category_to_policy_group(top_col['category'])
                
                table_result = {
                    'Schema': schema,
                    'Table': table,
                    'Column': top_col['column'],
                    'Category': top_col['category'],
                    'Confidence': top_col['confidence'],
                    'Sensitivity': top_col['label'],
                    'Compliance': compliance,
                    'CIA': f"C:{top_col['c']} I:{top_col['i']} A:{top_col['a']}",
                    'c': top_col['c'],
                    'i': top_col['i'],
                    'a': top_col['a'],
                    'column_count': len(final_column_results),
                    'Status': 'Classified',
                    'Method': top_col['method'],
                    'column_results': final_column_results,
                    
                    # Additional metadata for saving
                    'detected_categories': [c['detected_categories'][0] for c in final_column_results],
                    'policy_group': compliance
                }
                
                results.append(table_result)
                passed_count += 1
            else:
                filtered_count += 1
                
        logger.info("=" * 80)
        logger.info(f"Summary: {passed_count} Classified, {filtered_count} Filtered")
        logger.info("=" * 80)
        
        return results

# Singleton instance
ai_classification_pipeline_service = AIClassificationPipelineService()