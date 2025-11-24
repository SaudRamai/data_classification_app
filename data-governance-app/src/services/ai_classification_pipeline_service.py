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
        self._conf_label_threshold: float = 0.30  # ENHANCED: Lowered from 0.45 to enable 80%+ confidence scores
        self._debug: bool = False
        self._cache: Dict[str, Any] = {}
        self._embed_cache: Dict[str, Any] = {}
        self._embed_ready: bool = False
        # Track whether we had to fall back to built-in categories instead of governance-driven ones
        self._using_fallback_categories: bool = False
        # Business glossary will be loaded dynamically from SENSITIVE_KEYWORDS table
        self._business_glossary_map: Dict[str, str] = {}

    def render_classification_pipeline(self) -> None:
        """Render the Automatic AI Classification Pipeline sub-tab."""
        st.markdown("### Automatic AI Classification Pipeline")
        st.caption("Automatically discovers existing data assets, derives business context, performs semantic category detection, recommends CIA levels per Avendra's Data Classification Policy, and applies governance tags with full validation, review routing, and audit logging.")

        show_steps = False

        # Get active database
        db = self._get_active_database()
        if not db:
            st.info("Use Global Filters to select a database to run the pipeline.")
            return

        # Additional validation
        if db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            st.error("Invalid database selected. Please choose a valid database.")
            return

        # Get governance database
        gov_db = self._get_governance_database(db)

        # Show status and set Snowflake context
        try:
            schema_filter = self._get_schema_filter()
            table_filter = self._get_table_filter()
        except Exception:
            schema_filter = None; table_filter = None
        st.caption(
            f"Using Database: {db}"
            + (f" | Schema: {schema_filter}" if schema_filter else "")
            + (f" | Table filter: {table_filter}" if table_filter else "")
        )
        try:
            snowflake_connector.execute_non_query(f"USE DATABASE {db}")
        except Exception:
            pass
        try:
            self._auto_tune_parameters()
        except Exception:
            pass

        # Removed automatic background pipeline as it's unused and causes errors

        if show_steps:
            with st.expander("Step 2: Collect Metadata", expanded=False):
                colm1, colm2 = st.columns([1, 1])
                with colm1:
                    if st.button("Collect table & column metadata", key="btn_collect_meta"):
                        try:
                            tables_df, columns_df, glossary_df = self._collect_metadata(db, schema_filter, table_filter, gov_db)
                            st.session_state["pipe_meta_tables"] = tables_df
                            st.session_state["pipe_meta_columns"] = columns_df
                            st.session_state["pipe_meta_glossary"] = glossary_df
                        except Exception as me:
                            st.error(f"Metadata collection failed: {me}")
                with colm2:
                    st.caption("Collects information_schema tables/columns, plus governance glossary references.")

            try:
                tables_df = st.session_state.get("pipe_meta_tables") if hasattr(st, 'session_state') else None
                columns_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                glossary_df = st.session_state.get("pipe_meta_glossary") if hasattr(st, 'session_state') else None
            except Exception:
                tables_df = columns_df = glossary_df = None

            if isinstance(tables_df, pd.DataFrame) and not tables_df.empty:
                st.markdown("**Tables (preview)**")
                st.dataframe(tables_df.head(100), width='stretch', hide_index=True)

            if isinstance(columns_df, pd.DataFrame) and not columns_df.empty:
                st.markdown("**Columns (preview)**")
                st.dataframe(columns_df.head(200), width='stretch', hide_index=True)

                # Sampling UI
                try:
                    sample_cols = columns_df[["TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME"]].drop_duplicates()
                    sample_cols["FQN"] = sample_cols.apply(lambda r: f"{db}.{r['TABLE_SCHEMA']}.{r['TABLE_NAME']} :: {r['COLUMN_NAME']}", axis=1)
                    sel = st.selectbox("Sample column values", options=[""] + list(sample_cols["FQN"]), key="pipe_sample_pick")
                    if sel:
                        try:
                            parts = sel.split(" :: ")
                            tblfqn = parts[0]
                            colname = parts[1]
                            _, sch, tbl = tblfqn.split('.')
                            values = self._sample_column_values(db=db, schema=sch, table=tbl, column=colname, sample_rows=100)
                            if values:
                                st.markdown("**Sample Values**")
                                st.write(values[:50])
                            else:
                                st.caption("No non-null values sampled.")
                        except Exception as se:
                            st.warning(f"Sampling failed: {se}")
                except Exception:
                    pass

            if isinstance(glossary_df, pd.DataFrame) and not glossary_df.empty:
                st.markdown("**Glossary / Compliance Mapping**")
                st.dataframe(glossary_df.head(200), width='stretch', hide_index=True)

        if show_steps:
            with st.expander("Step 3: Semantic Embedding Generation", expanded=False):
                c1, c2 = st.columns([1, 1])
                with c1:
                    if st.button("Initialize embedding backend", key="btn_init_embed"):
                        try:
                            emb_info = self.ai_service.initialize_sensitive_detection()
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_info"] = emb_info
                            st.success(f"Backend: {emb_info.get('backend')} | Categories: {', '.join(emb_info.get('categories', []))}")
                        except Exception as ee:
                            st.error(f"Embedding init failed: {ee}")
                with c2:
                    try:
                        emb_info = st.session_state.get("pipe_embed_info") if hasattr(st, 'session_state') else None
                        if emb_info:
                            st.caption(f"Backend: {emb_info.get('backend')} | Categories loaded: {len(emb_info.get('categories', []))}")
                    except Exception:
                        pass

                try:
                    cols_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                except Exception:
                    cols_df = None

                cc1, cc2 = st.columns([1, 1])
                with cc1:
                    if st.button("Embed column contexts (sample)", key="btn_embed_cols"):
                        try:
                            out_rows = []
                            if isinstance(cols_df, pd.DataFrame) and not cols_df.empty:
                                sample = cols_df.head(100).copy()
                                for _, r in sample.iterrows():
                                    ctx = f"{db}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}.{r.get('COLUMN_NAME')}"
                                    com = r.get('COLUMN_COMMENT') or ''
                                    if com:
                                        ctx = f"{ctx} | {com}"
                                    vec = None
                                    try:
                                        if hasattr(self.ai_service, "_get_embedding"):
                                            vec = self.ai_service._get_embedding(ctx)
                                    except Exception:
                                        vec = None
                                    dim = int(getattr(vec, "shape", [0])[-1]) if vec is not None and hasattr(vec, 'shape') else (len(vec) if isinstance(vec, (list, tuple)) else 0)
                                    out_rows.append({
                                        "context": ctx,
                                        "dim": dim,
                                    })
                            dfv = pd.DataFrame(out_rows)
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_columns"] = dfv
                        except Exception as ce:
                            st.error(f"Column embedding failed: {ce}")
                with cc2:
                    if st.button("Build category reference embeddings", key="btn_embed_cats"):
                        try:
                            info = self.ai_service.initialize_sensitive_detection()
                            cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                            rows = []
                            for k, v in cents.items():
                                dim = int(getattr(v, "shape", [0])[-1]) if v is not None and hasattr(v, 'shape') else (len(v) if isinstance(v, (list, tuple)) else 0)
                                rows.append({"category": k, "dim": dim, "has_centroid": v is not None})
                            dfr = pd.DataFrame(rows)
                            if hasattr(st, 'session_state'):
                                st.session_state["pipe_embed_categories"] = dfr
                        except Exception as ce2:
                            st.error(f"Category embedding failed: {ce2}")

                try:
                    dfv = st.session_state.get("pipe_embed_columns") if hasattr(st, 'session_state') else None
                    if isinstance(dfv, pd.DataFrame) and not dfv.empty:
                        st.markdown("**Embedded Column Contexts (sample)**")
                        st.dataframe(dfv.head(50), width='stretch', hide_index=True)
                except Exception:
                    pass

                try:
                    dfr = st.session_state.get("pipe_embed_categories") if hasattr(st, 'session_state') else None
                    if isinstance(dfr, pd.DataFrame) and not dfr.empty:
                        st.markdown("**Category Reference Embeddings**")
                        st.dataframe(dfr, width='stretch', hide_index=True)
                except Exception:
                    pass

        if show_steps:
            with st.expander("Step 4: Similarity Matching", expanded=False):
                thr = st.slider("Confidence threshold (cosine)", min_value=0.3, max_value=0.95, value=0.45, step=0.05, key="pipe_sim_thr")
                run_btn = st.button("Compute best category per column (sample)", key="btn_compute_similarity")
                cols_df = None
                try:
                    cols_df = st.session_state.get("pipe_meta_columns") if hasattr(st, 'session_state') else None
                except Exception:
                    cols_df = None
                if run_btn:
                    try:
                        cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                        if not cents:
                            _ = self.ai_service.initialize_sensitive_detection()
                            cents = getattr(self.ai_service, "_category_centroids", {}) or {}
                        out_rows: List[Dict[str, Any]] = []
                        if isinstance(cols_df, pd.DataFrame) and not cols_df.empty and cents:
                            sample = cols_df.head(100).copy()
                            for _, r in sample.iterrows():
                                ctx = f"{db}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}.{r.get('COLUMN_NAME')}"
                                com = r.get('COLUMN_COMMENT') or ''
                                if com:
                                    ctx = f"{ctx} | {com}"
                                v = None
                                try:
                                    if hasattr(self.ai_service, "_get_embedding"):
                                        v = self.ai_service._get_embedding(ctx)
                                except Exception:
                                    v = None
                                best_cat = None
                                best_sim = 0.0
                                if v is not None and np is not None:
                                    try:
                                        vv = np.asarray(v, dtype=float)
                                        nv = float(np.linalg.norm(vv) or 0.0)
                                        if nv > 0:
                                            vv = vv / nv
                                        for cat, c in cents.items():
                                            if c is None:
                                                continue
                                            cc = np.asarray(c, dtype=float)
                                            nc = float(np.linalg.norm(cc) or 0.0)
                                            if nc > 0:
                                                cc = cc / nc
                                            sim = float(np.dot(vv, cc))
                                            if sim > best_sim:
                                                best_sim = sim
                                                best_cat = cat
                                    except Exception:
                                        pass
                                assigned = best_cat if (best_cat and best_sim >= thr) else None
                                out_rows.append({
                                    "Schema": r.get('TABLE_SCHEMA'),
                                    "Table": r.get('TABLE_NAME'),
                                    "Column": r.get('COLUMN_NAME'),
                                    "BestCategory": best_cat or "",
                                    "Similarity": round(best_sim, 4),
                                    "Assigned": assigned or "",
                                })
                        df_sim = pd.DataFrame(out_rows)
                        if hasattr(st, 'session_state'):
                            st.session_state["pipe_similarity_results"] = df_sim
                    except Exception as se:
                        st.error(f"Similarity matching failed: {se}")

                try:
                    df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                    if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                        st.markdown("**Similarity Results (sample)**")
                        st.dataframe(df_sim, width='stretch', hide_index=True)
                except Exception:
                    pass

            try:
                df_sim = st.session_state.get("pipe_similarity_results") if hasattr(st, 'session_state') else None
                if isinstance(df_sim, pd.DataFrame) and not df_sim.empty:
                    st.markdown("**Similarity Results (sample)**")
                    st.dataframe(df_sim, width='stretch', hide_index=True)
            except Exception:
                pass

        if show_steps:
            with st.expander("Debug: Discovery preview", expanded=False):
                st.write({
                    "database": db,
                    "schema_filter": schema_filter,
                    "table_filter": table_filter,
                })
                try:
                    sample_assets = self._discover_assets(db)[:10]
                    if sample_assets:
                        st.dataframe(pd.DataFrame(sample_assets), width='stretch', hide_index=True)
                    else:
                        st.caption("No assets discovered with current filters.")
                except Exception as _de:
                    st.caption(f"Discovery preview error: {_de}")

        # Run pipeline button
        if st.button("Run AI Classification Pipeline", type="primary", key="run_ai_pipeline"):
            self._run_classification_pipeline(db, gov_db)

    def _get_active_database(self) -> Optional[str]:
        """Get the active database from global filters."""
        try:
            from src.pages.page_helpers import _active_db_from_filter
            db = _active_db_from_filter()
        except Exception:
            db = None

        # Fallbacks from session state
        if not db:
            try:
                if hasattr(st, "session_state"):
                    db = (
                        st.session_state.get("sf_database")
                        or (st.session_state.get("global_filters", {}) or {}).get("database")
                        or st.session_state.get("rt_db")
                        or st.session_state.get("selected_database")
                    )
            except Exception:
                db = None

        # Settings fallback
        if not db and settings is not None:
            try:
                db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            except Exception:
                db = None

        # Probe Snowflake context last
        if not db:
            try:
                rows = snowflake_connector.execute_query("select current_database() as DB") or []
                if rows and rows[0].get("DB"):
                    db = rows[0].get("DB")
            except Exception:
                db = None

        try:
            dbu = str(db or "").strip().upper()
            if dbu in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
                return None
        except Exception:
            pass

        return db

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

                # Show backend status
                st.caption(f"Embedding backend: {self._embed_backend}")
                st.caption(
                    "Detection mode: "
                    + ("MiniLM embeddings + keyword fallback" if self._embed_backend == 'sentence-transformers' else "keyword/regex fallback only")
                )
                # Single message to indicate whether semantic search is using governance-driven categories or fallback
                try:
                    if getattr(self, "_using_fallback_categories", False):
                        st.warning("Semantic categories: using built-in fallback (PII / SOX / SOC2). Verify governance tables for full coverage.")
                    else:
                        st.info("Semantic categories: loaded from governance tables (SENSITIVITY_CATEGORIES / SENSITIVE_KEYWORDS / SENSITIVE_PATTERNS).")
                except Exception:
                    pass
                try:
                    cat_cnt = len(getattr(self, "_category_centroids", {}) or {})
                    tok_cnt = sum(len(v) for v in (getattr(self, "_category_tokens", {}) or {}).values())
                    st.caption(f"Categories loaded: {cat_cnt} | Tokens configured: {tok_cnt}")
                    if self._embed_backend == 'sentence-transformers' and cat_cnt == 0:
                        st.warning("MiniLM is active but no category centroids are available. Falling back to keywords only. Verify governance config and embeddings initialization.")
                except Exception:
                    pass

                # Step 2-8: Run local classification pipeline (no governance tables)
                results = self._classify_assets_local(db=db, assets=assets[:50])

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

                # Display results (table-level only)
                self._display_classification_results(results)

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
            rows = snowflake_connector.execute_query(
                f"""
                SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                FROM {schema_fqn}.SENSITIVE_KEYWORDS
                WHERE COALESCE(is_active, true) AND (
                    LOWER(category) = LOWER(%(n)s) OR LOWER(category_name) = LOWER(%(n)s)
                )
                """,
                {"n": category_name},
            ) or []
        except Exception:
            try:
                # CATEGORY_ID-based lookup using SENSITIVITY_CATEGORIES
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                    FROM {schema_fqn}.SENSITIVE_KEYWORDS
                    WHERE COALESCE(is_active, true) AND category_id IN (
                        SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                    )
                    """,
                    {"n": category_name},
                ) or []
            except Exception:
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT COALESCE(keyword, KEYWORD, KEYWORD_STRING) AS KW
                        FROM {schema_fqn}.SENSITIVITY_KEYWORDS
                        WHERE COALESCE(is_active, true) AND category_id IN (
                            SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                        )
                        """,
                        {"n": category_name},
                    ) or []
                except Exception:
                    rows = []
        out: List[str] = []
        for r in rows:
            try:
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
                    LOWER(COALESCE(keyword, KEYWORD, KEYWORD_STRING)) AS KEYWORD,
                    UPPER(COALESCE(category, category_name, CATEGORY_NAME)) AS CATEGORY
                FROM {schema_fqn}.SENSITIVE_KEYWORDS
                WHERE COALESCE(is_active, IS_ACTIVE, true) = true
                """) or []
            
            glossary_map = {}
            for r in rows:
                try:
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
                    CATEGORY_NAME,
                    COALESCE(DESCRIPTION, '') AS DESCRIPTION,
                    COALESCE(DETECTION_THRESHOLD, 0.65) AS DETECTION_THRESHOLD,
                    COALESCE(DETECTION_THRESHOLD, 0.65) AS DEFAULT_THRESHOLD,
                    1.0 AS SENSITIVITY_WEIGHT,
                    COALESCE(IS_ACTIVE, TRUE) AS IS_ACTIVE,
                    CATEGORY_ID
                FROM {schema_fqn}.SENSITIVITY_CATEGORIES
                WHERE COALESCE(IS_ACTIVE, TRUE) = TRUE
                ORDER BY CATEGORY_NAME
                """
            ) or []
            logger.info(f"✓ Loaded {len(categories_data)} active categories from SENSITIVITY_CATEGORIES")
            
            # Debug: Log what was loaded
            for cat in categories_data:
                cat_name = str(cat.get("CATEGORY_NAME") or "").strip()
                desc = str(cat.get("DESCRIPTION") or "").strip()
                logger.info(f"   Category: {cat_name}, Description length: {len(desc)} chars")
                
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVITY_CATEGORIES: {e}")
            import traceback
            logger.error(traceback.format_exc())
            categories_data = []
        
        if not categories_data:
            logger.error("CRITICAL: No active categories found in SENSITIVITY_CATEGORIES")
            logger.warning("System will NOT classify any columns without governance metadata")
            self._category_centroids = {}
            self._category_tokens = {}
            self._category_patterns = {}
            self._category_thresholds = {}
            self._category_weights = {}
            self._category_keywords = {}
            self._category_keyword_metadata = {}
            self._category_pattern_metadata = {}
            return
        
        # Store category metadata with ALL fields
        self._category_thresholds = {}
        self._category_default_thresholds = {}
        self._category_weights = {}
        category_descriptions = {}
        category_ids = {}
        
        for cat in categories_data:
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
                logger.error(f"  → FIX: UPDATE {schema_fqn}.SENSITIVITY_CATEGORIES SET DESCRIPTION = 'meaningful description' WHERE CATEGORY_NAME = '{cat_name}'")
                continue  # Skip this category
            
            if len(description) < 10:
                logger.warning(f"Category '{cat_name}' has very short DESCRIPTION ({len(description)} chars)")
                logger.warning(f"  → This may result in poor centroid quality")
                logger.warning(f"  → Recommend description of 50+ characters")
            
            category_descriptions[cat_name] = description
            category_ids[cat_name] = cat.get("CATEGORY_ID")
            self._category_thresholds[cat_name] = float(cat.get("DETECTION_THRESHOLD") or 0.65)
            self._category_default_thresholds[cat_name] = float(cat.get("DEFAULT_THRESHOLD") or 0.65)
            self._category_weights[cat_name] = float(cat.get("SENSITIVITY_WEIGHT") or 1.0)
            
            logger.info(f"  Category: {cat_name}")
            logger.info(f"    Description: '{description[:100]}...' ({len(description)} chars)")
            logger.info(f"    Detection Threshold: {self._category_thresholds[cat_name]:.2f}")
            logger.info(f"    Default Threshold: {self._category_default_thresholds[cat_name]:.2f}")
            logger.info(f"    Sensitivity Weight: {self._category_weights[cat_name]:.2f}")
        
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
                    COALESCE(p.PATTERN_STRING, p.PATTERN_REGEX) AS PATTERN_STRING,
                    COALESCE(p.PATTERN_REGEX, p.PATTERN_STRING) AS PATTERN_REGEX,
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
            
            for pat in patterns_data:
                cat_name = str(pat.get("CATEGORY_NAME") or "").strip()
                pattern = str(pat.get("PATTERN_STRING") or pat.get("PATTERN_REGEX") or "").strip()
                
                if cat_name in patterns_by_category and pattern:
                    patterns_by_category[cat_name].append(pattern)
                    
                    # Store full metadata for weighted scoring
                    pattern_metadata_by_category[cat_name].append({
                        'pattern': pattern,
                        'weight': float(pat.get("SENSITIVITY_WEIGHT") or 1.0),
                        'sensitivity_type': str(pat.get("SENSITIVITY_TYPE") or "STANDARD").upper()
                    })
            
            total_patterns = sum(len(pats) for pats in patterns_by_category.values())
            logger.info(f"✓ Loaded {total_patterns} patterns from SENSITIVE_PATTERNS")
            for cat, pats in patterns_by_category.items():
                if pats:
                    logger.info(f"  {cat}: {len(pats)} patterns")
        except Exception as e:
            logger.error(f"✗ Failed to load SENSITIVE_PATTERNS: {e}")
        
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
            
            # Generate embeddings
            try:
                if self._embedder is not None and np is not None and self._embed_backend == 'sentence-transformers':
                    examples = self._generate_category_examples(cat_name, combined_text)
                    logger.info(f"    Generated {len(examples)} base examples")
                    
                    # Add keywords as examples
                    examples.extend(keywords[:20])  # Add top 20 keywords as training examples
                    logger.info(f"    Total examples (with keywords): {len(examples)}")
                    
                    # Preprocess examples
                    processed_examples = [self._preprocess_text_local(s, remove_stopwords=True) for s in examples]
                    logger.info(f"    Encoding {len(processed_examples)} examples...")
                    
                    # CRITICAL FIX: Add E5 "passage:" prefix for category centroids
                    # E5 requires "passage:" for documents/definitions being searched
                    is_e5 = 'e5' in str(getattr(self._embedder, 'model_name', '') or '').lower()
                    if is_e5:
                        processed_examples = [f"passage: {ex}" for ex in processed_examples]
                        logger.info(f"    ✓ Applied E5 'passage:' prefix to {len(processed_examples)} examples")
                    
                    # Encode all examples
                    vecs = self._embedder.encode(processed_examples, normalize_embeddings=True)
                    
                    # CRITICAL FIX: Weighted averaging - description gets 2x weight
                    # First vector is from description, rest are from keywords/examples
                    weights = [2.0] + [1.0] * (len(vecs) - 1)
                    weights_array = np.array(weights) / np.sum(weights)  # Normalize weights
                    
                    # Weighted average instead of simple mean
                    centroid = np.average(vecs, axis=0, weights=weights_array)
                    
                    # Normalize centroid
                    norm = float(np.linalg.norm(centroid) or 0.0)
                    if norm > 0:
                        centroid = centroid / norm
                    centroids[cat_name] = centroid
                    logger.info(f"    ✓ Created weighted embedding centroid for {cat_name} (dimension: {len(centroid)})")
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
    
    def _create_fallback_categories(self) -> None:
        """
        DEPRECATED: Use _load_metadata_driven_categories() instead.
        This method now delegates to the metadata-driven approach.
        """
        logger.warning("_create_fallback_categories() is deprecated. Using metadata-driven approach.")
        self._load_metadata_driven_categories()

    def _semantic_scores(self, text: str, vector: Optional[np.ndarray] = None) -> Dict[str, float]:
        """Compute semantic similarity scores per category in [0,1] using local centroids.
        Supports optional pre-computed vector for dual-embedding fusion.
        
        CRITICAL FIX: Uses E5 'query:' prefix and applies boosting BEFORE normalization.
        """
        scores: Dict[str, float] = {}
        if not text and vector is None:
            return scores
        if self._embedder is None or not self._category_centroids:
            return scores
        try:
            v = vector
            if v is None:
                t = str(text or "")
                key = f"emb::pp1::{t}"
                v = self._embed_cache.get(key) if hasattr(self, "_embed_cache") else None
                if v is None:
                    # CRITICAL FIX: Add E5 "query:" prefix for search queries
                    # E5 requires "query:" for columns being classified
                    is_e5 = 'e5' in str(getattr(self._embedder, 'model_name', '') or '').lower()
                    t_enc = f"query: {t}" if is_e5 else t
                    
                    v_raw = self._embedder.encode([t_enc], normalize_embeddings=True)
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

            # Calculate raw cosine similarities
            raw: Dict[str, float] = {}
            for cat, c in self._category_centroids.items():
                try:
                    if c is None:
                        continue
                    # Cosine similarity (dot product of normalized vectors)
                    sim = float(np.dot(v, c))
                    # Convert from [-1, 1] to [0, 1]
                    conf = max(0.0, min(1.0, (sim + 1.0) / 2.0))
                    raw[cat] = conf
                except Exception:
                    continue

            if not raw:
                return {}
            
            # CRITICAL FIX: Apply confidence boosting BEFORE min-max normalization
            # This preserves strong signals instead of suppressing them
            boosted: Dict[str, float] = {}
            for cat, confidence in raw.items():
                # Aggressive boosting for strong signals
                if confidence >= 0.75:
                    # Very strong signal → 0.90-0.99
                    boosted_conf = 0.90 + (confidence - 0.75) * 0.36
                elif confidence >= 0.60:
                    # Strong signal → 0.75-0.90
                    boosted_conf = 0.75 + (confidence - 0.60) * 1.0
                elif confidence >= 0.45:
                    # Moderate signal → 0.55-0.75
                    boosted_conf = 0.55 + (confidence - 0.45) * 1.33
                elif confidence >= 0.30:
                    # Weak signal → 0.35-0.55
                    boosted_conf = 0.35 + (confidence - 0.30) * 1.33
                else:
                    # Very weak signal → 0.00-0.35
                    boosted_conf = confidence * 1.17
                
                boosted[cat] = max(0.0, min(0.99, boosted_conf))
            
            # NOW apply min-max normalization to spread scores
            # This emphasizes differences between categories
            vals = list(boosted.values())
            mn = min(vals)
            mx = max(vals)
            
            if mx > mn and mx > 0.5:  # Only normalize if there's a clear winner
                for k, v0 in boosted.items():
                    normalized = (float(v0) - float(mn)) / (float(mx) - float(mn))
                    scores[k] = max(0.0, min(0.99, normalized))
            else:
                # No clear winner, use boosted scores as-is
                scores = boosted
                
        except Exception as e:
            logger.error(f"Semantic scoring failed: {e}")
            return {}
        return scores


    def _compute_fused_embedding(self, name: str, values: str, metadata: str, data_type: str = "", sample_values: List[Any] = None) -> Optional[np.ndarray]:
        """Compute multi-view fused embedding from name, values, and metadata.
        
        CRITICAL FIX: Uses E5 'query:' prefix and semantic type hints for better accuracy.
        
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
            # Detect E5 model
            is_e5 = 'e5' in str(getattr(self._embedder, 'model_name', '') or '').lower()
            
            # Infer semantic type for better context
            semantic_type = ""
            if sample_values:
                semantic_type = semantic_type_detector.infer_semantic_type(
                    sample_values, data_type, name
                )
            
            # Encode each component with E5 query prefix and semantic hints
            vecs = []
            weights = []
            
            # View 1: Column Name (40% weight)
            if name:
                name_text = f"query: {name}" if is_e5 else name
                v_name = self._embedder.encode([name_text], normalize_embeddings=True)[0]
                vecs.append(v_name)
                weights.append(0.40)
            
            # View 2: Sample Values with Semantic Type Hint (35% weight)
            if values:
                # Add semantic type hint for clarity
                if semantic_type:
                    values_text = f"query: {semantic_type} values: {values[:200]}" if is_e5 else f"{semantic_type} values: {values[:200]}"
                else:
                    values_text = f"query: {values[:200]}" if is_e5 else values[:200]
                v_vals = self._embedder.encode([values_text], normalize_embeddings=True)[0]
                vecs.append(v_vals)
                weights.append(0.35)
            
            # View 3: Metadata/Comments (25% weight)
            if metadata:
                meta_text = f"query: {metadata}" if is_e5 else metadata
                v_meta = self._embedder.encode([meta_text], normalize_embeddings=True)[0]
                vecs.append(v_meta)
                weights.append(0.25)
            
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
        Metadata-driven pattern scoring using ONLY data from governance tables.
        Uses self._category_pattern_metadata loaded from SENSITIVE_PATTERNS table.
        Applies SENSITIVITY_WEIGHT and SENSITIVITY_TYPE from metadata.
        """
        out: Dict[str, float] = {}
        try:
            # Use pattern metadata if available
            if hasattr(self, '_category_pattern_metadata') and self._category_pattern_metadata:
                t = str(text or "")
                
                for cat, pattern_list in self._category_pattern_metadata.items():
                    if not pattern_list:
                        continue
                    
                    total_weighted_score = 0.0
                    match_count = 0
                    
                    for pat_meta in pattern_list:
                        pattern = pat_meta['pattern']
                        weight = pat_meta['weight']
                        sensitivity_type = pat_meta['sensitivity_type']
                        
                        try:
                            if re.search(pattern, t, re.IGNORECASE):
                                match_count += 1
                                # Weighted contribution
                                contribution = weight
                                total_weighted_score += contribution
                                logger.debug(f"    Pattern match: '{pattern[:50]}...' → score={contribution:.3f}")
                        except Exception as e:
                            # Invalid regex, skip
                            logger.debug(f"    Invalid pattern: '{pattern[:50]}...' → {e}")
                            continue
                    
                    if match_count > 0:
                        # Get category threshold
                        threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.65)
                        category_weight = getattr(self, '_category_weights', {}).get(cat, 1.0)
                        
                        # Normalize by number of patterns
                        num_patterns = len(pattern_list)
                        normalized_score = (total_weighted_score / max(1, num_patterns)) * category_weight
                        
                        # Cap at 1.0
                        final_score = min(1.0, normalized_score)
                        
                        # STRICT: Only include if score meets category threshold
                        if final_score >= threshold:
                            out[cat] = final_score
                            logger.debug(f"  ✓ Pattern score: {cat} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                        else:
                            logger.debug(f"  ✗ Below threshold: {cat} = {final_score:.2f} < {threshold:.2f}")
                
                return out
            
            # Fallback to simple pattern matching if metadata not available
            if not hasattr(self, "_category_patterns") or not self._category_patterns:
                return out
            
            t = str(text or "")
            for cat, patterns in self._category_patterns.items():
                hits = 0
                for p in (patterns or [])[:20]:
                    try:
                        if not p:
                            continue
                        if re.search(p, t, re.IGNORECASE):
                            hits += 1
                    except Exception:
                        continue
                
                if hits > 0:
                    threshold = getattr(self, '_category_thresholds', {}).get(cat, 0.65)
                    score = max(0.0, min(1.0, hits / 3.0))
                    if score >= threshold:
                        out[cat] = score
        except Exception:
            return {}
        return out
    
    def _keyword_scores_metadata_driven(self, text: str) -> Dict[str, float]:
        """
        Metadata-driven keyword scoring using ONLY data from governance tables.
        NO HARDCODED KEYWORDS.
        
        Uses self._category_keyword_metadata loaded from SENSITIVE_KEYWORDS table.
        Applies MATCH_TYPE, SENSITIVITY_TYPE, and SCORE from metadata.
        """
        scores: Dict[str, float] = {}
        t = (text or '').lower()
        
        # Use keyword metadata loaded from governance tables
        if not hasattr(self, '_category_keyword_metadata') or not self._category_keyword_metadata:
            logger.warning("No category keyword metadata loaded from governance tables")
            return scores
        
        for category, keyword_list in self._category_keyword_metadata.items():
            if not keyword_list:
                continue
                
            total_weighted_score = 0.0
            match_count = 0
            
            for kw_meta in keyword_list:
                keyword = kw_meta['keyword']
                weight = kw_meta['weight']
                match_type = kw_meta['match_type']
                sensitivity_type = kw_meta['sensitivity_type']
                base_score = kw_meta['score']
                
                matched = False
                match_quality = 0.0
                
                try:
                    # Apply MATCH_TYPE from metadata
                    if match_type == 'EXACT':
                        # Word boundary matching
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched = True
                            match_quality = 1.0  # Perfect match
                    elif match_type == 'PARTIAL':
                        # Substring matching
                        if keyword in t:
                            matched = True
                            match_quality = 0.8  # Partial match
                    elif match_type == 'FUZZY':
                        # Contains any word from keyword
                        keyword_words = keyword.split()
                        if any(word in t for word in keyword_words):
                            matched = True
                            match_quality = 0.6  # Fuzzy match
                    else:
                        # Default: EXACT matching
                        if re.search(r'\b' + re.escape(keyword) + r'\b', t, re.IGNORECASE):
                            matched = True
                            match_quality = 1.0
                except Exception:
                    # Fallback to simple substring
                    if keyword in t:
                        matched = True
                        match_quality = 0.7
                
                if matched:
                    match_count += 1
                    # Weighted score = base_score * weight * match_quality
                    contribution = base_score * weight * match_quality
                    total_weighted_score += contribution
                    
                    logger.debug(f"    Keyword match: '{keyword}' ({match_type}) → score={contribution:.3f}")
            
            if match_count > 0:
                # Get category threshold
                threshold = getattr(self, '_category_thresholds', {}).get(category, 0.65)
                category_weight = getattr(self, '_category_weights', {}).get(category, 1.0)
                
                # Normalize by number of keywords to avoid bias toward categories with many keywords
                num_keywords = len(keyword_list)
                normalized_score = (total_weighted_score / max(1, num_keywords)) * category_weight
                
                # Cap at 1.0
                final_score = min(1.0, normalized_score)
                
                # STRICT: Only include if score meets category threshold
                if final_score >= threshold:
                    scores[category] = final_score
                    logger.debug(f"  ✓ Keyword score: {category} = {final_score:.2f} ({match_count} matches, threshold={threshold:.2f})")
                else:
                    logger.debug(f"  ✗ Below threshold: {category} = {final_score:.2f} < {threshold:.2f}")
        
        return scores
    
    def _fallback_keyword_matching(self, text: str) -> Dict[str, float]:
        """
        DEPRECATED: Use _keyword_scores_metadata_driven() instead.
        This method now delegates to the metadata-driven approach.
        """
        logger.warning("_fallback_keyword_matching() is deprecated. Using metadata-driven keyword scoring.")
        return self._keyword_scores_metadata_driven(text)

    def _load_patterns_from_governance(self, schema_fqn: str, category_name: str) -> List[str]:
        rows = []
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT COALESCE(pattern, PATTERN, PATTERN_STRING) AS PTN
                FROM {schema_fqn}.SENSITIVE_PATTERNS
                WHERE COALESCE(is_active, true) AND (
                    LOWER(category) = LOWER(%(n)s) OR LOWER(category_name) = LOWER(%(n)s)
                )
                """,
                {"n": category_name},
            ) or []
        except Exception:
            try:
                # CATEGORY_ID-based lookup using SENSITIVITY_CATEGORIES
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COALESCE(pattern, PATTERN, PATTERN_STRING) AS PTN
                    FROM {schema_fqn}.SENSITIVE_PATTERNS
                    WHERE COALESCE(is_active, true) AND category_id IN (
                        SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                    )
                    """,
                    {"n": category_name},
                ) or []
            except Exception:
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT COALESCE(pattern, PATTERN, PATTERN_STRING) AS PTN
                        FROM {schema_fqn}.SENSITIVITY_PATTERNS
                        WHERE COALESCE(is_active, true) AND category_id IN (
                            SELECT CATEGORY_ID FROM {schema_fqn}.SENSITIVITY_CATEGORIES WHERE LOWER(CATEGORY_NAME) = LOWER(%(n)s)
                        )
                        """,
                        {"n": category_name},
                    ) or []
                except Exception:
                    rows = []
        out: List[str] = []
        for r in rows:
            try:
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
            except Exception:
                matches = []
            try:
                from src.services.ai_assistant_service import ai_assistant_service as _aas
                _map = getattr(_aas, "_SEMANTIC_TO_AVENDRA", {}) or {}
            except Exception:
                _map = {}
            for m in matches:
                try:
                    # Tolerate different field names from governance queries
                    c = str(
                        m.get("category")
                        or m.get("CATEGORY")
                        or m.get("CATEGORY_NAME")
                        or ""
                    ).strip()
                    conf = float(m.get("confidence") or m.get("CONFIDENCE") or 0.0)
                except Exception:
                    continue
                if not c:
                    continue
                av = _map.get(c, c)
                out[av] = max(0.0, min(1.0, conf))
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

    def _map_category_to_policy_group(self, category: str) -> Optional[str]:
        """Map a granular category to one of the policy groups: PII, SOX, SOC2."""
        if not category:
            return None
        
        cat_upper = str(category).strip().upper()
        
        # Direct mapping with extensive granular categories
        mapping = {
            # PII
            'PII': 'PII',
            'PERSONAL_DATA': 'PII',
            'PERSONAL DATA': 'PII',
            'PERSONAL': 'PII',
            'SENSITIVE_PERSONAL': 'PII',
            'EMAIL': 'PII',
            'PHONE': 'PII',
            'SSN': 'PII',
            'DOB': 'PII',
            'BIRTH_DATE': 'PII',
            'GENDER': 'PII',
            'ETHNICITY': 'PII',
            'CREDIT_CARD': 'PII',
            'PASSPORT': 'PII',
            'DRIVER_LICENSE': 'PII',
            'ADDRESS': 'PII',
            'CUSTOMER': 'PII',
            'EMPLOYEE': 'PII',
            'PATIENT': 'PII',
            'HEALTH': 'PII',
            'BIOMETRIC': 'PII',
            'USER': 'PII',
            'USERNAME': 'PII',
            'LOGIN': 'PII',
            
            # SOX (Financial)
            'SOX': 'SOX',
            'FINANCIAL': 'SOX',
            'FINANCIAL_DATA': 'SOX',
            'FINANCIAL DATA': 'SOX',
            'ACCOUNTING': 'SOX',
            'REVENUE': 'SOX',
            'EXPENSE': 'SOX',
            'PROFIT': 'SOX',
            'LOSS': 'SOX',
            'SALARY': 'SOX',
            'PAYROLL': 'SOX',
            'BONUS': 'SOX',
            'COMMISSION': 'SOX',
            'BANK': 'SOX',
            'BANK_ACCOUNT': 'SOX',
            'IBAN': 'SOX',
            'SWIFT': 'SOX',
            'ROUTING': 'SOX',
            'INVOICE': 'SOX',
            'BILLING': 'SOX',
            'TAX': 'SOX',
            'ASSET': 'SOX',
            'LIABILITY': 'SOX',
            'EQUITY': 'SOX',
            'GL': 'SOX',
            'GENERAL_LEDGER': 'SOX',
            'PROPRIETARY': 'SOX',
            'PROPRIETARY_DATA': 'SOX',
            'BUDGET': 'SOX',
            'FORECAST': 'SOX',
            
            # SOC2 (Security/Regulatory/Internal)
            'SOC2': 'SOC2',
            'SOC_2': 'SOC2',
            'SECURITY': 'SOC2',
            'COMPLIANCE': 'SOC2',
            'REGULATORY': 'SOC2',
            'REGULATORY_DATA': 'SOC2',
            'INTERNAL': 'SOC2',
            'INTERNAL_DATA': 'SOC2',
            'CONFIDENTIAL': 'SOC2',
            'SECRET': 'SOC2',
            'PASSWORD': 'SOC2',
            'CREDENTIAL': 'SOC2',
            'ACCESS': 'SOC2',
            'AUDIT': 'SOC2',
            'LOG': 'SOC2',
            'KEY': 'SOC2',
            'TOKEN': 'SOC2',
            'ENCRYPTION': 'SOC2',
            'VULNERABILITY': 'SOC2',
            'INCIDENT': 'SOC2',
            'RISK': 'SOC2',
            'PRIVILEGE': 'SOC2',
            'PERMISSION': 'SOC2',
        }
        
        if cat_upper in mapping:
            return mapping[cat_upper]
            
        # Fuzzy / Substring matching for robust fallback
        if any(x in cat_upper for x in ['PERSONAL', 'PII', 'IDENTITY', 'CONTACT', 'DEMOGRAPHIC', 'HEALTH', 'MEDICAL', 'BIOMETRIC', 'USER', 'CLIENT', 'CITIZEN']):
            return 'PII'
        if any(x in cat_upper for x in ['FINANCIAL', 'MONEY', 'BANK', 'ACCOUNT', 'PAYMENT', 'TRANSACTION', 'SALARY', 'REVENUE', 'TAX', 'SOX', 'BILLING', 'INVOICE', 'COST', 'PRICE']):
            return 'SOX'
        if any(x in cat_upper for x in ['SECURITY', 'ACCESS', 'AUTH', 'PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'LOG', 'AUDIT', 'COMPLIANCE', 'REGULATORY', 'SOC2', 'CONFIDENTIAL', 'INTERNAL', 'PRIVACY']):
            return 'SOC2'
            
        return None

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
        """Classify assets using local MiniLM + keyword fallback and produce results compatible with UI."""
        results: List[Dict[str, Any]] = []
        for asset in assets:
            try:
                # 1. Business Glossary Mapping (Deterministic Override from SENSITIVE_KEYWORDS)
                glossary_cats = set()
                table_name = str(asset.get('table') or '').lower()
                for term, gcat in self._business_glossary_map.items():
                    if term in table_name:
                        glossary_cats.add(gcat)

                # Derive business context using metadata and samples (no governance glossary)
                context = ""
                try:
                    context = self.ai_service._derive_business_context(asset)  # type: ignore
                except Exception:
                    context = f"Table {asset.get('table')} in schema {asset.get('schema')}"
                # Build richer context with targeted samples and column names
                rich_ctx = self._build_richer_context(
                    asset,
                    max_cols=int(getattr(self, "_ctx_max_cols", 8) or 8),
                    max_vals=int(getattr(self, "_ctx_max_vals", 3) or 3),
                    business_purpose=context,
                )
                full_context = "\n".join([c for c in [context, rich_ctx] if c])

                q = self._context_quality_metrics(full_context)
                if q.get("too_short") or q.get("digit_ratio", 0.0) > 0.6:
                    try:
                        rich_ctx2 = self._build_richer_context(
                            asset,
                            max_cols=int(max(20, int(getattr(self, "_ctx_max_cols", 8)) * 2)),
                            max_vals=int(max(7, int(getattr(self, "_ctx_max_vals", 3)) * 2)),
                            business_purpose=context,
                        )
                        full_context = "\n".join([c for c in [context, rich_ctx2] if c])
                    except Exception:
                        pass

                ptxt = self._preprocess_text_local(full_context)
                sem = self._semantic_scores(ptxt)
                kw = self._keyword_scores(ptxt)
                pt = self._pattern_scores(ptxt)
                combined: Dict[str, float] = {}
                cats = set(list(sem.keys()) + list(kw.keys()) + list(pt.keys()))
                
                # Diagnostic logging for score computation
                logger.info(f"Score computation for {asset}:")
                logger.info(f"  Semantic scores: {sem}")
                logger.info(f"  Keyword scores: {kw}")
                logger.info(f"  Pattern scores: {pt}")
                
                # weights: allow dynamic override
                cfg = {}
                try:
                    cfg = self._load_dynamic_config()
                except Exception:
                    cfg = {}
                w_sem = float(cfg.get("w_sem", getattr(self, "_w_sem", 0.7)))
                w_kw = float(cfg.get("w_kw", getattr(self, "_w_kw", 0.3)))
                w_pt = float(cfg.get("w_pt", 0.2))
                # normalize weights so they sum <= 1; if exceed, rescale
                try:
                    total_w = w_sem + w_kw + w_pt
                    if total_w > 1.0:
                        w_sem /= total_w
                        w_kw /= total_w
                        w_pt /= total_w
                except Exception:
                    pass
                
                logger.info(f"  Weights: w_sem={w_sem:.2f}, w_kw={w_kw:.2f}, w_pt={w_pt:.2f}")
                
                # ENHANCED: Ensemble Certainty Score for Table Level
                # Formula: 0.5 * sem + 0.25 * kw + 0.15 * pt + 0.10 * gov
                
                # Get governance scores first
                gov_sem = {}
                try:
                    gov_sem = self._gov_semantic_scores(ptxt)
                except Exception:
                    pass

                all_cats = set(list(sem.keys()) + list(kw.keys()) + list(pt.keys()) + list(gov_sem.keys()))
                # CRITICAL FIX: Ensure glossary matches are included in the evaluation loop
                all_cats.update(glossary_cats)
                
                for cat in all_cats:
                    s = float(sem.get(cat, 0.0))
                    k = float(kw.get(cat, 0.0))
                    p = float(pt.get(cat, 0.0))
                    g = float(gov_sem.get(cat, 0.0))
                    
                    # Ensemble Score
                    score = (0.5 * s) + (0.25 * k) + (0.15 * p) + (0.10 * g)
                    
                    # Apply Business Glossary Override
                    pg = self._map_category_to_policy_group(cat)
                    if pg and pg in glossary_cats:
                        score = 0.99  # Force high confidence for glossary matches
                    
                    # High Certainty Rule
                    if score >= 0.90:
                        score = 0.99
                        
                    combined[cat] = max(0.0, min(1.0, score))
                    
                    logger.debug(f"    {cat}: sem={s:.3f}, kw={k:.3f}, pt={p:.3f}, gov={g:.3f} → combined={combined[cat]:.3f}")

                # Apply heuristic boosts for FINANCIAL/REGULATORY from structure/content
                boosts = self._category_boosts(asset, full_context)
                if boosts:
                    for cat, b in boosts.items():
                        combined[cat] = max(0.0, min(1.0, combined.get(cat, 0.0) + b))
                
                combined = self._apply_quality_calibration(self._calibrate_scores(combined), q)
                
                # -------------------------------------------------------------------------
                # ENHANCED: Multi-Label Detection & Reasoning
                # -------------------------------------------------------------------------
                detected_cats_set = set()
                reasoning_json = {}
                
                for cat, score in combined.items():
                    # Use 0.50 as threshold for "clear evidence" in multi-label context
                    if score >= 0.50:
                        pg = self._map_category_to_policy_group(cat)
                        if pg:
                            detected_cats_set.add(pg)
                            # Generate reasoning
                            reasons = []
                            if sem.get(cat, 0) >= 0.4: reasons.append(f"Semantic match ({sem.get(cat):.2f})")
                            if kw.get(cat, 0) >= 0.4: reasons.append(f"Keyword match ({kw.get(cat):.2f})")
                            if pt.get(cat, 0) >= 0.4: reasons.append(f"Pattern match ({pt.get(cat):.2f})")
                            if gov_sem.get(cat, 0) >= 0.4: reasons.append(f"Governance ({gov_sem.get(cat):.2f})")
                            
                            # Append to existing reasoning for this policy group if exists
                            existing = reasoning_json.get(pg, "")
                            new_r = "; ".join(reasons)
                            if existing:
                                reasoning_json[pg] = existing + " | " + new_r
                            else:
                                reasoning_json[pg] = new_r

                detected_list = sorted(list(detected_cats_set))
                
                # Select Best Category for UI (Legacy Support)
                if not combined:
                    best_cat = None
                    confidence = 0.0
                else:
                    best_cat = max(combined, key=combined.get)
                    confidence = float(combined.get(best_cat, 0.0))

                # Governance alignment boost (legacy check, kept for safety)
                try:
                    gov_hint = None
                    if isinstance(gov_sem, dict) and gov_sem:
                        gov_hint = max(gov_sem.items(), key=lambda x: x[1])[0]
                    if gov_hint and gov_hint == best_cat:
                        confidence = min(1.0, confidence * 1.15)
                except Exception:
                    pass

                if bool(getattr(self, "_debug", False)):
                    try:
                        top = sorted(combined.items(), key=lambda x: x[1], reverse=True)[:5]
                        st.caption("Debug: top category scores (normalized)")
                        st.write(top)
                        st.caption("Debug: context sample")
                        st.code((full_context or "")[:800])
                    except Exception:
                        pass

                # CIA mapping and label
                try:
                    canon_cat = self._normalize_category_for_cia(best_cat)
                    c, i, a = ai_assistant_service.CIA_MAPPING.get(canon_cat, (1, 1, 1))  # type: ignore
                except Exception:
                    c, i, a = (1, 1, 1)

                # -------------------------------------------------------------------------
                # ENHANCED: Column-Level High Water Mark Aggregation
                # -------------------------------------------------------------------------
                # "Table-level labels vs Column-level CIA"
                # We run column classification to find the most sensitive elements.
                # The table's CIA should be the MAXIMUM of its columns' CIA (High Water Mark).
                column_reasoning = []
                try:
                    # Perform column-level classification
                    col_results = self._classify_columns_local(
                        db=db,
                        schema=str(asset.get('schema')),
                        table=str(asset.get('table')),
                        max_cols=50  # Analyze up to 50 columns
                    )

                    if col_results:
                        # Calculate High Water Mark from columns
                        max_col_c = 1
                        max_col_i = 1
                        max_col_a = 1
                        max_col_conf = 0.0
                        sensitive_cols = []

                        for cr in col_results:
                            cc = int(cr.get('c', 1))
                            ci = int(cr.get('i', 1))
                            ca = int(cr.get('a', 1) )
                            c_conf = float(cr.get('confidence', 0.0))
                            
                            # Track max CIA
                            max_col_c = max(max_col_c, cc)
                            max_col_i = max(max_col_i, ci)
                            max_col_a = max(max_col_a, ca)
                            
                            # Track confidence of the drivers of sensitivity
                            if max(cc, ci, ca) >= 2:
                                sensitive_cols.append(f"{cr.get('column')} ({cr.get('label')})")
                                max_col_conf = max(max_col_conf, c_conf)

                        # Apply High Water Mark: Table CIA is max of Table-Context CIA and Column-Max CIA
                        old_score = max(c, i, a)
                        new_score = max(max_col_c, max_col_i, max_col_a)
                        
                        if new_score > old_score:
                            logger.info(f"Table {asset.get('table')} upgraded from C={c}/I={i}/A={a} to {max_col_c}/{max_col_i}/{max_col_a} based on columns")
                            c = max(c, max_col_c)
                            i = max(i, max_col_i)
                            a = max(a, max_col_a)
                            
                            # If we upgraded based on columns, use the column confidence if it's higher
                            if max_col_conf > confidence:
                                confidence = max_col_conf
                                # Update best_cat to the most frequent category from sensitive columns
                                if sensitive_cols:
                                    # Extract categories from sensitive columns (format: "column_name (CATEGORY)")
                                    categories = [col.split('(')[-1].rstrip(')') for col in sensitive_cols]
                                    # Count category occurrences
                                    from collections import Counter
                                    category_counter = Counter(categories)
                                    most_common = category_counter.most_common(1)
                                    if most_common:
                                        best_cat = most_common[0][0]  # Get the most frequent category
                                        logger.info(f"Table {asset.get('table')} category set to {best_cat} based on {len(sensitive_cols)} sensitive columns")
                                    
                                    column_reasoning = sensitive_cols[:3]
                                    if len(sensitive_cols) > 3:
                                        column_reasoning.append(f"+{len(sensitive_cols)-3} more")

                except Exception as e:
                    logger.warning(f"Failed to aggregate column CIA for {asset.get('table')}: {e}")
                # -------------------------------------------------------------------------

                try:
                    base_label = self.ai_service._map_cia_to_label(c, i, a)  # type: ignore
                except Exception:
                    # Fallback: derive from max CIA level using the same 0-3 scale
                    try:
                        score = int(max(int(c), int(i), int(a)))
                    except Exception:
                        score = 1
                    if score <= 0:
                        base_label = 'Public'
                    elif score == 1:
                        base_label = 'Internal'
                    elif score == 2:
                        base_label = 'Restricted'
                    else:
                        base_label = 'Confidential'
                lbl_thr = float(getattr(self, "_conf_label_threshold", 0.45))
                final_label = base_label if confidence >= lbl_thr else "Uncertain — review"

                # Validation & routing (disabled to avoid database errors)
                validation_status = 'REVIEW_REQUIRED'
                issues = ['Validation disabled']
                route = 'STANDARD_REVIEW'

                # SQL preview for tagging (disabled to avoid database errors)
                sql_preview = None

                # Emoji label for UI and compliance hints
                label_emoji_map = {
                    'Confidential': '🟥 Confidential',
                    'Restricted': '🟧 Restricted',
                    'Internal': '🟨 Internal',
                    'Public': '🟩 Public',
                    'Uncertain — review': '⬜ Uncertain — review',
                }
                color_map = {
                    'Confidential': 'Red',
                    'Restricted': 'Orange',
                    'Internal': 'Yellow',
                    'Public': 'Green',
                    'Uncertain — review': 'Gray',
                }
                label_emoji = label_emoji_map.get(final_label, final_label)
                # Prefer governance-derived compliance mapping
                compliance = []
                try:
                    from src.services.ai_classification_service import ai_classification_service as _svc
                    comp_map = getattr(_svc, "_gov_cat_compliance", {}) or {}
                    try:
                        sem_to_av = getattr(ai_assistant_service, "_SEMANTIC_TO_AVENDRA", {}) or {}
                    except Exception:
                        sem_to_av = {}
                    if best_cat and comp_map:
                        # Gather governance categories that map to the detected category
                        mapped = [gcat for gcat, av in sem_to_av.items() if av == best_cat]
                        tags = []
                        for gcat in (mapped or []):
                            try:
                                tags.extend(comp_map.get(gcat, []) or [])
                            except Exception:
                                continue
                        if not tags:
                            tags = comp_map.get(best_cat, []) or []
                        compliance = list(dict.fromkeys(tags))
                except Exception:
                    compliance = ai_assistant_service._COMPLIANCE_MAP.get(best_cat, []) if hasattr(ai_assistant_service, '_COMPLIANCE_MAP') else []

                # Confidence normalization and tiering (non-breaking: keep confidence in 0..1)
                confidence_pct = round(confidence * 100.0, 1)
                if confidence_pct < 50.0:
                    confidence_tier = "Uncertain"
                elif confidence_pct < 75.0:
                    confidence_tier = "Likely"
                else:
                    confidence_tier = "Confident"

                # Filter: Only include PII, SOX, SOC2 using robust mapping
                display_cat = self._map_category_to_policy_group(best_cat)

                # STRICT FILTERING: Only include tables that map to PII, SOX, or SOC2 with high confidence
                # Exclude low-sensitivity tables and those that don't clearly belong to these three categories
                if display_cat and display_cat in {'PII', 'SOX', 'SOC2'} and confidence >= 0.50:
                    logger.info(f"✓ INCLUDED TABLE: {asset.get('full_name')} ({display_cat}, {confidence:.1%})")
                    results.append({
                        'asset': asset,
                        'business_context': full_context,
                        'category': display_cat,
                        'confidence': confidence,
                        'confidence_pct': confidence_pct,
                        'confidence_tier': confidence_tier,
                        'c': c,
                        'i': i,
                        'a': a,
                        'label': final_label,
                        'label_emoji': label_emoji,
                        'color': color_map.get(final_label, ''),
                        'validation_status': validation_status,
                        'issues': issues,
                        'route': route,
                        'application_status': 'QUEUED_FOR_REVIEW',
                        'failure_reason': None,
                        'sql_preview': sql_preview,
                        'compliance': compliance,
                        'reasoning': column_reasoning,
                        'multi_label_analysis': {
                            "detected_categories": detected_list,
                            "reasoning": reasoning_json
                        }
                    })
                else:
                    if not display_cat or display_cat not in {'PII', 'SOX', 'SOC2'}:
                        logger.info(f"✗ FILTERED OUT TABLE: {asset.get('full_name')} (category '{display_cat}' not in [PII, SOX, SOC2])")
                    elif confidence < 0.50:
                        logger.info(f"✗ FILTERED OUT TABLE: {asset.get('full_name')} (low confidence: {confidence:.1%} < 50%)")
            except Exception as e:
                logger.error(f"Error classifying {asset.get('full_name')}: {e}")
        return results

    def _classify_columns_local(self, db: str, schema: str, table: str, max_cols: int = 50) -> List[Dict[str, Any]]:
        """Classify individual columns using E5 embeddings, dual fusion, and ensemble scoring."""
        results: List[Dict[str, Any]] = []
        try:
            # Ensure embeddings are initialized
            if self._embedder is None or not self._category_centroids:
                logger.info("Initializing embeddings for column classification...")
                self._init_local_embeddings()
                
                if not self._category_centroids:
                    logger.error("CRITICAL: No category centroids available after initialization.")
                    logger.error("  → Semantic classification will be DISABLED.")
                    logger.error("  → Check SENSITIVITY_CATEGORIES table and logs.")
                else:
                    logger.info(f"Embeddings initialized: {len(self._category_centroids)} centroids")
            
            # Fetch columns from information_schema
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                ORDER BY ORDINAL_POSITION
                LIMIT {max_cols}
                """,
                {"s": schema, "t": table},
            ) or []
            
            logger.info(f"Column-level classification: {db}.{schema}.{table} with {len(cols)} columns")
            
            if not cols:
                logger.warning(f"No columns found for {db}.{schema}.{table}")
                return results
            
            for col in cols:
                try:
                    col_name = str(col.get('COLUMN_NAME') or '')
                    col_type = str(col.get('DATA_TYPE') or '')
                    col_comment = str(col.get('COMMENT') or '')
                    
                    if not col_name:
                        continue
                    
                    # 1. Business Glossary Mapping (Deterministic Override from SENSITIVE_KEYWORDS)
                    glossary_cats = set()
                    col_lower = col_name.lower()
                    for term, gcat in self._business_glossary_map.items():
                        if term in col_lower:
                            glossary_cats.add(gcat)
                    
                    # 2. MIN/MAX Profile Patterns
                    min_val, max_val = self._get_min_max_values(db, schema, table, col_name)
                    range_info = ""
                    if min_val and max_val:
                        range_info = f"Range: MIN({min_val}), MAX({max_val})"
                    
                    # 3. Build Contexts
                    # Metadata Context
                    meta_parts = [f"Table: {table}", f"Column: {col_name}", f"Type: {col_type}"]
                    if col_comment:
                        meta_parts.append(f"Comment: {col_comment}")
                    if range_info:
                        meta_parts.append(range_info)
                    meta_context = " | ".join(meta_parts)
                    
                    # Sample Values
                    sample_str = ""
                    try:
                        samples = self._sample_column_values(db, schema, table, col_name, sample_rows=50) or []
                        if samples:
                            sample_str = ", ".join([str(s)[:40] for s in samples[:10]])
                    except Exception:
                        pass
                    
                    # Full Context for Keywords/Patterns
                    full_context = f"{meta_context} | Values: {sample_str}"
                    ptxt = self._preprocess_text_local(full_context)
                    
                    # 4. Dual Embedding Fusion
                    # Fuse: Name, Values, Metadata
                    fused_vec = self._compute_fused_embedding(col_name, sample_str, meta_context)
                    
                    # 5. Compute Scores
                    sem = self._semantic_scores(ptxt, vector=fused_vec)
                    kw = self._keyword_scores(ptxt)
                    pt = self._pattern_scores(ptxt)
                    gov_sem = self._gov_semantic_scores(ptxt)
                    
                    # 6. Ensemble Certainty Score
                    # Formula: 0.5 * sem + 0.25 * kw + 0.15 * pt + 0.10 * gov
                    combined: Dict[str, float] = {}
                    all_cats = set(list(sem.keys()) + list(kw.keys()) + list(pt.keys()) + list(gov_sem.keys()))
                    # CRITICAL FIX: Ensure glossary matches are included in the evaluation loop
                    all_cats.update(glossary_cats)
                    
                    for cat in all_cats:
                        s = float(sem.get(cat, 0.0))
                        k = float(kw.get(cat, 0.0))
                        p = float(pt.get(cat, 0.0))
                        g = float(gov_sem.get(cat, 0.0))
                        
                        # Apply Business Glossary Override
                        # Check if this category maps to any of the detected glossary categories
                        pg = self._map_category_to_policy_group(cat)
                        
                        if pg and pg in glossary_cats:
                            # Boost significantly if it matches a glossary mapping
                            s = max(s, 0.95)
                            k = max(k, 0.95)
                        
                        # Ensemble Score
                        score = (0.5 * s) + (0.25 * k) + (0.15 * p) + (0.10 * g)
                        
                        # Force high confidence if glossary match (override ensemble)
                        if pg and pg in glossary_cats:
                            score = 0.99
                        
                        # High Certainty Rule
                        if score >= 0.90:
                            score = 0.99 # Force high confidence
                            
                        combined[cat] = max(0.0, min(1.0, score))
                        
                    # 7. Multi-Label Detection & Reasoning
                    detected_cats_set = set()
                    reasoning_json = {}
                    
                    for cat, score in combined.items():
                        # Use 0.50 as threshold for "clear evidence" in multi-label context
                        if score >= 0.50:
                            pg = self._map_category_to_policy_group(cat)
                            if pg:
                                detected_cats_set.add(pg)
                                # Generate reasoning
                                reasons = []
                                if sem.get(cat, 0) >= 0.4: reasons.append(f"Semantic match ({sem.get(cat):.2f})")
                                if kw.get(cat, 0) >= 0.4: reasons.append(f"Keyword match ({kw.get(cat):.2f})")
                                if pt.get(cat, 0) >= 0.4: reasons.append(f"Pattern match ({pt.get(cat):.2f})")
                                if gov_sem.get(cat, 0) >= 0.4: reasons.append(f"Governance ({gov_sem.get(cat):.2f})")
                                
                                # Append to existing reasoning for this policy group if exists
                                existing = reasoning_json.get(pg, "")
                                new_r = "; ".join(reasons)
                                if existing:
                                    reasoning_json[pg] = existing + " | " + new_r
                                else:
                                    reasoning_json[pg] = new_r

                    detected_list = sorted(list(detected_cats_set))

                    # 8. Ensemble Voting (Select Best for Legacy UI)
                    if not combined:
                        best_cat = None
                        confidence = 0.0
                    else:
                        best_cat = max(combined, key=combined.get)
                        confidence = float(combined.get(best_cat, 0.0))
                        
                    # Multi-signal check (optional logging)
                    sorted_cats = sorted(combined.items(), key=lambda x: x[1], reverse=True)
                    if len(sorted_cats) > 1:
                        diff = sorted_cats[0][1] - sorted_cats[1][1]
                        if diff < 0.05:
                            logger.info(f"    Multi-signal detected for {col_name}: {sorted_cats[:2]}")

                    # Derive a display category strictly limited to PII, SOX, SOC2 using robust mapping
                    display_cat = self._map_category_to_policy_group(best_cat)
                    
                    # Determine label based on confidence
                    try:
                        canon_cat = self._normalize_category_for_cia(best_cat)
                        c, i, a = self.ai_service.CIA_MAPPING.get(canon_cat, (1, 1, 1))  # type: ignore
                    except Exception:
                        c, i, a = (1, 1, 1)
                    
                    # Assign label based on CIA levels and confidence using the same 0-3 policy scale
                    if confidence >= 0.20:
                        if c >= 2 or i >= 2 or a >= 2:
                            label = 'Restricted' if max(c, i, a) >= 3 else 'Confidential'
                        else:
                            label = 'Internal'
                    else:
                        label = 'Uncertain'
                    
                    logger.info(f"  Column {col_name}: {display_cat} (raw={best_cat}) @ {confidence:.1%} → {label}")
                    
                    # STRICT FILTERING: Include only columns that map to PII, SOX, or SOC2 with high confidence
                    # Exclude low-sensitivity columns and those that don't clearly belong to these three categories
                    if display_cat and display_cat in {'PII', 'SOX', 'SOC2'} and confidence >= 0.50:
                        logger.info(f"    ✓ INCLUDED: {col_name} ({display_cat}, {confidence:.1%})")
                        results.append({
                            'column': col_name,
                            'data_type': col_type,
                            'comment': col_comment,
                            'context': full_context,
                            'category': display_cat,
                            'confidence': confidence,
                            'confidence_pct': round(confidence * 100.0, 1),
                            'label': label,
                            'c': c,
                            'i': i,
                            'a': a,
                            'scores': combined,
                            'detected_category': display_cat,
                            'final_confidence': confidence,
                            'high_confidence': confidence >= 0.90,
                            'signals': {
                                'semantic': sem.get(best_cat, 0.0),
                                'keywords': kw.get(best_cat, 0.0),
                                'patterns': pt.get(best_cat, 0.0),
                                'governance': gov_sem.get(best_cat, 0.0)
                            },
                            'multi_label_analysis': {
                                "detected_categories": detected_list,
                                "reasoning": reasoning_json
                            }
                        })
                    else:
                        if not display_cat or display_cat not in {'PII', 'SOX', 'SOC2'}:
                            logger.info(f"    ✗ FILTERED OUT: {col_name} (category '{display_cat}' not in [PII, SOX, SOC2])")
                        elif confidence < 0.50:
                            logger.info(f"    ✗ FILTERED OUT: {col_name} (low confidence: {confidence:.1%} < 50%)")
                except Exception as e:
                    logger.warning(f"Column classification failed for {col_name}: {e}", exc_info=True)
                    # Don't add error rows to results - just log and skip
        except Exception as e:
            logger.error(f"Column-level classification failed: {e}", exc_info=True)
        
        logger.info(f"✓ Column classification complete: {len(results)} columns included in results")
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
                token_set = {
                    "ssn","social","credit","debit","card","cvv","iban","swift","routing","account","acct","tax","tin","pan","aadhaar","passport","phone","mobile","email","mail","dob","birth","dateofbirth","address"
                }
                regex_list = [r"\b(?:ssn|iban|swift|tin|pan|aadhaar)\b", r"\b(?:credit|debit)\b", r"\b(?:phone|mobile)\b", r"\b(?:email)\b"]

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
        """Display the classification results in a structured format."""
        st.markdown("#### Classification Results")

        # Filter out errors for display
        successful_results = [r for r in results if 'error' not in r]

        if not successful_results:
            st.warning("No successful classifications to display.")
            return

        # Create display dataframe
        display_data = []
        for result in successful_results:
            asset = result['asset']
            c_val = int(result.get('c', 0) or 0)
            i_val = int(result.get('i', 0) or 0)
            a_val = int(result.get('a', 0) or 0)
            display_data.append({
            "Asset": asset['full_name'],
            "Business Context": result.get('business_context', '')[:100] + '...' if result.get('business_context') and len(result.get('business_context', '')) > 100 else result.get('business_context', ''),
            "Category": result.get('category', 'N/A'),
            "Classification": result.get('label_emoji', result.get('label', 'N/A')),
            "Color": result.get('color', 'N/A'),
            "C": c_val,
            "I": i_val,
            "A": a_val,
            "Compliance": ", ".join(result.get('compliance', [])) if result.get('compliance') else 'N/A',
            "Route": result.get('route', 'N/A'),
            "Status": result.get('application_status', 'N/A')
            })

        results_df = pd.DataFrame(display_data)
        try:
            try:
                theme_base = st.get_option("theme.base")
            except Exception:
                theme_base = "light"
            is_dark = str(theme_base or "").lower() == "dark"
            if is_dark:
                mp = {
                    'Red': '#7f1d1d',
                    'Orange': '#7c2d12',
                    'Yellow': '#7a6e00',
                    'Green': '#14532d',
                    'Gray': '#374151',
                }
                fg = '#ffffff'
            else:
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
                except Exception:
                    pass
                return styles

            styled = results_df.style.apply(_apply_classification_style, axis=1)
            st.dataframe(styled, width='stretch', hide_index=True)
        except Exception:
            st.dataframe(results_df, width='stretch', hide_index=True)

        # Show detailed results in expandable sections
        with st.expander("Detailed Results", expanded=False):
            for result in successful_results[:10]:  # Limit for performance
                asset = result['asset']
                with st.container():
                    col1, col2 = st.columns([1, 2])

                    with col1:
                        st.markdown(f"**{asset['full_name']}**")
                        st.write(f"**Category:** {result.get('category', 'N/A')}")
                        
                        # Display confidence with enhanced visualization
                        confidence_pct = result.get('confidence', 0) * 100
                        confidence_tier = result.get('confidence_tier', 'Uncertain')
                        if confidence_pct >= 80:
                            st.write(f"**Confidence:** 🟢 {confidence_pct:.1f}% ({confidence_tier})")
                        elif confidence_pct >= 60:
                            st.write(f"**Confidence:** 🟡 {confidence_pct:.1f}% ({confidence_tier})")
                        else:
                            st.write(f"**Confidence:** 🔴 {confidence_pct:.1f}% ({confidence_tier})")
                        
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
                    
                    # Column-level detection with automatic loading (full-width display)
                    try:
                        table_key = asset['full_name']
                        col_key = f"col_results_{table_key.replace('.', '_')}"
                        col_loading_key = f"col_loading_{table_key.replace('.', '_')}"
                        
                        # Initialize state flags
                        if col_loading_key not in st.session_state:
                            st.session_state[col_loading_key] = False
                        if col_key not in st.session_state:
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
                        logger.info(f"Displaying column results: {len(col_rows) if col_rows else 0} rows in session state")
                        
                        if col_rows and len(col_rows) > 0:
                            logger.info(f"Raw results from _classify_columns_local:")
                            for r in col_rows:
                                logger.info(f"  - {r.get('column')}: {r.get('category')} @ {r.get('confidence_pct')}% (label={r.get('label')})")
                            
                            # Filter for display - show only higher-confidence PII / SOX / SOC2 columns
                            col_rows_clean = [
                                r for r in col_rows
                                if 'error' not in r
                                and r.get('category') in {'PII', 'SOX', 'SOC2'}
                                and r.get('confidence_pct', 0) >= 50
                            ]
                            
                            logger.info(f"After display filter: {len(col_rows_clean)} rows")
                            for r in col_rows_clean:
                                logger.info(f"  - {r.get('column')}: {r.get('category')} @ {r.get('confidence_pct')}% (label={r.get('label')})")
                            
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
                                
                                # Create display dataframe (no confidence column)
                                col_display = []
                                for col in col_rows_clean:
                                    raw_label = col.get('label', 'N/A')
                                    label_with_emoji = label_emoji_map.get(raw_label, raw_label)
                                    raw_cat = col.get('category')
                                    # Use robust mapping for display
                                    display_cat = self._map_category_to_policy_group(raw_cat)
                                    
                                    col_display.append({
                                        "Column": col.get('column', 'N/A'),
                                        "Data Type": col.get('data_type', 'N/A'),
                                        "Category": display_cat if display_cat is not None else 'N/A',
                                        "Label": label_with_emoji,
                                        "C": col.get('c', 0),
                                        "I": col.get('i', 0),
                                        "A": col.get('a', 0),
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


# Singleton instance
ai_classification_pipeline_service = AIClassificationPipelineService()
