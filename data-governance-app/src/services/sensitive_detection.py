"""
Sensitive Detection Service

Modular, platform-agnostic logic to detect sensitive columns and tables,
and assign CIA classifications. Designed to combine regex screening and
ML using engineered features with weak-label training. Includes caching
and multithreading for performance on large tables.

Functions:
- analyze_metadata(table_name, df, column_meta) -> Dict[str, Dict]
- regex_screen(series) -> Dict[str, float]
- ml_predict(features_df, name_hints) -> pd.Series (probabilities)
- aggregate_table_sensitivity(table_name, col_probs) -> Dict[str, Any]
- assign_cia(detected_type, probability) -> Dict[str, int]
- classify_table_sensitivity(table_name, df, column_meta) -> Dict[str, Any]

Notes:
- Works with any pandas DataFrame as input sample data.
- If scikit-learn is unavailable, falls back to heuristic ensemble.
- Emphasizes recall (reducing false negatives) via ensemble max rule.
"""
from __future__ import annotations

import logging
import math
import re
import statistics
from collections import Counter
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import numpy as np
try:
    import streamlit as st  # type: ignore
except Exception:
    st = None  # type: ignore
try:
    from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
    from src.config.settings import settings  # type: ignore
except Exception:
    snowflake_connector = None  # type: ignore
    settings = None  # type: ignore

# Module logger
logger = logging.getLogger(__name__)

# Optional embeddings model for semantic similarity
_EMB_MODEL = None
_NP = None
def _get_embedding_model():
    global _EMB_MODEL, _NP
    if _EMB_MODEL is not None:
        return _EMB_MODEL, _NP
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        import numpy as _np  # type: ignore
        _EMB_MODEL = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        _NP = _np
    except Exception:
        _EMB_MODEL = None
        _NP = None
    return _EMB_MODEL, _NP

# Dynamic configuration loader (Snowflake-backed). Falls back to static defaults when unavailable.
try:
    from src.services.dynamic_config_service import load_config as _load_dynamic_config
except Exception:  # pragma: no cover - optional
    _load_dynamic_config = None  # type: ignore

# Optional scikit-learn, with safe fallback
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score
    _SKLEARN_AVAILABLE = True
except Exception:
    _SKLEARN_AVAILABLE = False


# ---------------------- Regex Catalog ----------------------
# All regex patterns are loaded from the database (SENSITIVE_PATTERNS table).
# These will be populated on first use via _load_patterns_from_db()
_REGEX_PATTERNS: Dict[str, List[str]] = {}
_NAME_TOKENS: Dict[str, List[str]] = {}
_CATEGORY_WEIGHTS: Dict[str, float] = {}
_PATTERNS_LOADED = False

def _load_patterns_from_db() -> None:
    """Load patterns and configurations from the database with proper schema qualification."""
    global _REGEX_PATTERNS, _NAME_TOKENS, _CATEGORY_WEIGHTS, _PATTERNS_LOADED
    
    if _PATTERNS_LOADED or snowflake_connector is None:
        return
        
    try:
        # Check if tables exist first
        tables = snowflake_connector.execute_query(
            "SHOW TABLES LIKE 'SENSITIVE_%' IN SCHEMA DATA_CLASSIFICATION_GOVERNANCE"
        )
        
        if not tables:
            logger.warning("Sensitivity tables not found in DATA_CLASSIFICATION_GOVERNANCE schema")
            return
            
        # Load patterns from SENSITIVE_PATTERNS
        patterns = snowflake_connector.execute_query(
            """
            SELECT 
                p.PATTERN_NAME as name,
                p.PATTERN_STRING as pattern,
                c.CATEGORY_NAME as category,
                p.SENSITIVITY_WEIGHT as weight
            FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p
            JOIN DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c 
                ON p.CATEGORY_ID = c.CATEGORY_ID
            WHERE p.IS_ACTIVE = TRUE
            AND c.IS_ACTIVE = TRUE
            """
        ) or []
        
        # Load keywords from SENSITIVE_KEYWORDS
        keywords = snowflake_connector.execute_query(
            """
            SELECT 
                k.KEYWORD_STRING as keyword,
                c.CATEGORY_NAME as category,
                k.SENSITIVITY_WEIGHT as weight,
                k.MATCH_TYPE as match_type
            FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k
            JOIN DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c 
                ON k.CATEGORY_ID = c.CATEGORY_ID
            WHERE k.IS_ACTIVE = TRUE
            AND c.IS_ACTIVE = TRUE
            """
        ) or []
        
        # Load categories and weights
        categories = snowflake_connector.execute_query(
            """
            SELECT 
                CATEGORY_NAME as name,
                CONFIDENTIALITY_LEVEL as c_level,
                INTEGRITY_LEVEL as i_level,
                AVAILABILITY_LEVEL as a_level,
                DETECTION_THRESHOLD as threshold
            FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
            WHERE IS_ACTIVE = TRUE
            """
        ) or []
        
        # Process patterns
        _REGEX_PATTERNS = {}
        for p in patterns:
            cat = p['category']
            if cat not in _REGEX_PATTERNS:
                _REGEX_PATTERNS[cat] = []
            try:
                re.compile(p['pattern'])  # Validate pattern
                _REGEX_PATTERNS[cat].append({
                    'pattern': p['pattern'],
                    'weight': float(p['weight']) if p['weight'] is not None else 1.0,
                    'name': p['name']
                })
            except re.error as e:
                logger.warning(f"Invalid regex pattern {p['pattern']}: {str(e)}")
        
        # Process keywords
        _NAME_TOKENS = {}
        for k in keywords:
            cat = k['category']
            if cat not in _NAME_TOKENS:
                _NAME_TOKENS[cat] = []
            _NAME_TOKENS[cat].append({
                'token': k['keyword'],
                'weight': float(k['weight']) if k['weight'] is not None else 1.0,
                'match_type': k['match_type'] or 'EXACT'
            })
        
        # Process categories and weights
        _CATEGORY_WEIGHTS = {}
        for c in categories:
            category_name = c['name'].upper()
            _CATEGORY_WEIGHTS[category_name] = {
                'c_level': int(c['c_level']) if c['c_level'] is not None else 1,
                'i_level': int(c['i_level']) if c['i_level'] is not None else 1,
                'a_level': int(c['a_level']) if c['a_level'] is not None else 1,
                'threshold': float(c['threshold']) if c['threshold'] is not None else 0.5
            }
        
        # Load sensitivity weights if available
        try:
            weight_rows = snowflake_connector.execute_query("""
                SELECT 
                    w.CATEGORY, 
                    w.WEIGHT 
                FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_WEIGHTS w
                WHERE w.IS_ACTIVE = TRUE
            """) or []
            
            for row in weight_rows:
                if not row:
                    continue
                category = str(row.get('CATEGORY', '')).strip().upper()
                weight = float(row.get('WEIGHT', 1.0))
                if category in _CATEGORY_WEIGHTS:
                    _CATEGORY_WEIGHTS[category]['weight'] = weight
                    
        except Exception as e:
            logger.warning(f"Could not load category weights: {str(e)}")
            # Use default weights if we couldn't load them
            for category in _CATEGORY_WEIGHTS:
                _CATEGORY_WEIGHTS[category]['weight'] = 1.0
        
        _PATTERNS_LOADED = True
        
    except Exception as e:
        import traceback
        import sys
        error_msg = f"Error in _load_patterns_from_db: {str(e)}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        
        # Log to audit if available
        try:
            snowflake_connector.execute_query(
                """
                INSERT INTO DATA_CLASSIFICATION_GOVERNANCE.AUDIT_LOG (
                    AUDIT_ID,
                    TIMESTAMP, 
                    USER_ID, 
                    ACTION, 
                    RESOURCE_TYPE, 
                    RESOURCE_ID, 
                    DETAILS
                ) VALUES (
                    UUID_STRING(),
                    CURRENT_TIMESTAMP(),
                    CURRENT_USER(),
                    'ERROR',
                    'PATTERN_LOAD',
                    'SENSITIVE_DETECTION',
                    PARSE_JSON(OBJECT_CONSTRUCT(
                        'error', %s,
                        'traceback', %s,
                        'module', 'sensitive_detection',
                        'function', '_load_patterns_from_db'
                    ))
                )
                """, 
                (str(e), traceback.format_exc())
            )
        except Exception as audit_err:
            print(f"Failed to log error to audit: {str(audit_err)}", file=sys.stderr)
        
        if st is not None:
            st.warning(f"Could not load patterns from database: {str(e)}")
        
        # Fall back to default patterns if database load fails
        _load_default_configs()
        _PATTERNS_LOADED = True  # Mark as loaded to prevent repeated attempts


# ---------------------- Utilities ----------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = float(len(s))
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())


def _safe_len(x: Any) -> int:
    try:
        return len(str(x))
    except Exception:
        return 0


def _luhn_ok(num: str) -> bool:
    try:
        s = [int(x) for x in num]
        checksum = 0
        dbl = False
        for d in reversed(s):
            if dbl:
                d2 = d * 2
                if d2 > 9:
                    d2 -= 9
                checksum += d2
            else:
                checksum += d
            dbl = not dbl
        return checksum % 10 == 0
    except Exception:
        return False


def _series_basic_stats(series: pd.Series) -> Dict[str, float]:
    s = series.dropna()
    n = len(s)
    if n == 0:
        return {
            "null_count": int(series.isna().sum()),
            "null_ratio": 1.0,
            "unique_count": 0,
            "unique_ratio": 0.0,
            "avg_len": 0.0,
            "std_len": 0.0,
            "min_len": 0.0,
            "max_len": 0.0,
            "avg_entropy": 0.0,
        }
    vals = s.astype(str)
    lens = vals.map(len)
    uniq = vals.nunique(dropna=True)
    ent = vals.map(_entropy)
    return {
        "null_count": int(series.isna().sum()),
        "null_ratio": float(series.isna().mean()),
        "unique_count": int(uniq),
        "unique_ratio": float(uniq) / float(len(series)),
        "avg_len": float(lens.mean()),
        "std_len": float(lens.std(ddof=0) if len(lens) > 1 else 0.0),
        "min_len": float(lens.min()),
        "max_len": float(lens.max()),
        "avg_entropy": float(ent.mean()),
    }


def _load_default_configs() -> Dict[str, Any]:
    """Load default configurations using the dynamic config service."""
    defaults = {
        "numeric_stats": {
            "num_min": 0.0, 
            "num_max": 0.0, 
            "num_mean": 0.0, 
            "num_std": 0.0, 
            "num_skew": 0.0, 
            "num_kurt": 0.0
        },
        "char_ratios": {
            "digit_ratio": 0.0, 
            "alpha_ratio": 0.0, 
            "space_ratio": 0.0, 
            "punct_ratio": 0.0
        },
        "fuzzy_threshold": 0.8,
        "exact_match_weight": 1.0,
        "fuzzy_match_weight": 0.8
    }
    
    if not _load_dynamic_config:
        logger.debug("Dynamic config service not available, using defaults")
        return defaults
    
    try:
        # Load all configurations using the dynamic config service
        config = _load_dynamic_config(force_refresh=False)
        
        # Extract thresholds from CIA rules (if available)
        if config.get('cia_rules'):
            for category, rules in config['cia_rules'].items():
                if 'MIN_THRESHOLD' in rules and 'fuzzy_threshold' not in defaults:
                    defaults['fuzzy_threshold'] = float(rules['MIN_THRESHOLD'])
        
        # Extract weights from patterns and keywords
        if config.get('patterns'):
            for category, patterns in config['patterns'].items():
                for pattern in patterns:
                    if 'weight' in pattern and pattern.get('active', True):
                        weight = float(pattern['weight'])
                        if 'exact' in str(pattern.get('match_type', '')).lower():
                            defaults['exact_match_weight'] = max(defaults['exact_match_weight'], weight)
                        else:
                            defaults['fuzzy_match_weight'] = max(defaults['fuzzy_match_weight'], weight)
        
        # Update from model config if available in the config service
        if 'model_config' in config:
            model_config = config['model_config']
            if 'fuzzy_threshold' in model_config:
                defaults['fuzzy_threshold'] = float(model_config['fuzzy_threshold'])
            if 'exact_match_weight' in model_config:
                defaults['exact_match_weight'] = float(model_config['exact_match_weight'])
            if 'fuzzy_match_weight' in model_config:
                defaults['fuzzy_match_weight'] = float(model_config['fuzzy_match_weight'])
        
        print(f"[DEBUG] Loaded dynamic config with thresholds: {defaults}")
        
    except Exception as e:
        print(f"[WARNING] Failed to load configurations from dynamic config service: {str(e)}")
    
    return defaults

# Load default configs at module level
_DEFAULT_CONFIGS = _load_default_configs()

def _series_numeric_stats(series: pd.Series) -> Dict[str, float]:
    """Compute numeric statistics for a series, using database-configured defaults for empty series."""
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return _DEFAULT_CONFIGS["numeric_stats"].copy()
    
    return {
        "num_min": float(s.min()),
        "num_max": float(s.max()),
        "num_mean": float(s.mean()),
        "num_std": float(s.std(ddof=0) if len(s) > 1 else 0.0),
        "num_skew": float(s.skew() if len(s) > 2 else 0.0),
        "num_kurt": float(s.kurt() if len(s) > 3 else 0.0),
    }


def _series_charclass_ratios(series: pd.Series) -> Dict[str, float]:
    """Compute character class ratios for a series, using database-configured defaults for empty series."""
    s = series.dropna().astype(str)
    if s.empty:
        return _DEFAULT_CONFIGS["char_ratios"].copy()
        
    total = max(1, s.map(len).sum())
    digits = sum(ch.isdigit() for v in s for ch in v)
    alpha = sum(ch.isalpha() for v in s for ch in v)
    spaces = sum(ch.isspace() for v in s for ch in v)
    punct = sum((not ch.isalnum()) and (not ch.isspace()) for v in s for ch in v)
    
    return {
        "digit_ratio": digits / total,
        "alpha_ratio": alpha / total,
        "space_ratio": spaces / total,
        "punct_ratio": punct / total,
    }


def _split_camel_and_delims(name: str) -> List[str]:
    """
    Split a column name into normalized tokens by:
    - Replacing non-alphanumeric with spaces
    - Splitting underscores and spaces
    - Splitting camelCase/PascalCase boundaries
    Returns lowercased tokens without empty strings
    """
    try:
        s = str(name or "")
    except Exception:
        s = ""
    # Replace non-alnum with space
    s = re.sub(r"[^0-9A-Za-z]+", " ", s)
    # Insert space before camel case boundaries: fooBar -> foo Bar, XMLId -> XML Id
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r" \1", s)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    # Split and normalize
    parts = [p.lower().strip() for p in re.split(r"[\s_]+", s) if p and p.strip()]
    return parts


def _normalize_name(name: str) -> str:
    try:
        s = str(name or "").lower()
    except Exception:
        return ""
    return re.sub(r"[^0-9a-z]+", "", s)


def _flatten_keywords(cfg: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize dynamic keyword configuration into a flat list:
    [{"category","token","match_type","weight"}, ...]
    Accepts both dict form {cat: [..]} and flat list.
    """
    flat: List[Dict[str, Any]] = []
    if not cfg:
        return flat
    kws = cfg.get("keywords") if isinstance(cfg, dict) else None
    if isinstance(kws, dict):
        for cat, items in (kws or {}).items():
            for it in (items or []):
                try:
                    kw = str(it.get("keyword") or it.get("token") or "").strip()
                    if not kw:
                        continue
                    flat.append({
                        "category": str(cat),
                        "token": kw,
                        "match_type": str(it.get("match_type") or "fuzzy").lower(),
                        "weight": float(it.get("weight", 1.0 if (str(it.get("match_type") or "").lower()=="exact") else 0.8)),
                    })
                except Exception:
                    continue
    elif isinstance(kws, list):
        for it in (kws or []):
            try:
                cat = str(it.get("category") or "").strip()
                tok = str(it.get("token") or it.get("keyword") or "").strip()
                if not cat or not tok:
                    continue
                flat.append({
                    "category": cat,
                    "token": tok,
                    "match_type": str(it.get("match_type") or "fuzzy").lower(),
                    "weight": float(it.get("weight", 1.0 if (str(it.get("match_type") or "").lower()=="exact") else 0.8)),
                })
            except Exception as e:
                logger.debug(f"Error processing keyword item: {str(e)}")
                continue
    return flat


def _name_hint_categories(col_name: str, cfg: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Extract category hints from column name using dynamic keywords.
    
    Keywords are loaded from the SENSITIVE_PATTERNS database table with IS_STRICT=TRUE.
    """
    # Ensure patterns are loaded from the database
    _load_patterns_from_db()
    
    if not col_name or not isinstance(col_name, str):
        return []
        
    if not cfg:
        cfg = _NAME_TOKENS
        if not cfg:
            logger.debug("No name tokens available for hinting")
            return []
    
    # Get thresholds and weights from config
    fuzzy_threshold = _DEFAULT_CONFIGS.get("fuzzy_threshold", 0.8)
    exact_match_weight = _DEFAULT_CONFIGS.get("exact_match_weight", 1.0)
    fuzzy_match_weight = _DEFAULT_CONFIGS.get("fuzzy_match_weight", 0.8)
        
    name_tokens = _split_camel_and_delims(col_name)
    name_norm = _normalize_name(col_name)
    if not name_norm:
        return []

    # Prepare keyword list with precomputed normalized token
    flat = _flatten_keywords(cfg)
    for it in flat:
        try:
            it["token_norm"] = _normalize_name(it.get("token") or "")
        except Exception as e:
            logger.debug(f"Error normalizing token: {str(e)}")
            it["token_norm"] = ""

    hits: List[Dict[str, Any]] = []
    from difflib import SequenceMatcher

    for it in flat:
        tok = it.get("token") or ""
        tok_norm = it.get("token_norm") or ""
        if not tok_norm:
            continue
            
        mt = str(it.get("match_type") or "fuzzy").lower()
        base_w = float(it.get("weight", fuzzy_match_weight if mt != "exact" else exact_match_weight))

        matched = False
        weight = 0.0
        
        # Exact: whole normalized string equal or any token-piece equals original keyword (case-insensitive)
        if mt == "exact":
            if name_norm == tok_norm or tok.lower() in [t.lower() for t in name_tokens]:
                matched = True
                weight = exact_match_weight if base_w is None else float(base_w)
        else:
            # Fuzzy: substring or similarity against full normalized name and each piece
            if tok_norm in name_norm:
                matched = True
                weight = float(base_w)
            else:
                # Try best ratio against pieces and full
                cand_strs = [name_norm] + [_normalize_name(p) for p in name_tokens]
                best_ratio = 0.0
                for s in cand_strs:
                    try:
                        r = SequenceMatcher(None, tok_norm, s).ratio()
                        if r > best_ratio:
                            best_ratio = r
                    except Exception as e:
                        logger.debug(f"Error computing similarity ratio: {str(e)}")
                        continue
                        
                # Get threshold from config or use default
                thr = fuzzy_threshold
                try:
                    if isinstance(cfg, dict) and isinstance(cfg.get("model_metadata"), dict):
                        thr = float((cfg["model_metadata"].get("thresholds") or {}).get("token_fuzzy_threshold", thr))
                except Exception as e:
                    logger.debug(f"Error loading threshold: {str(e)}")
                    
                if best_ratio >= thr:
                    matched = True
                    weight = float(base_w) * float(best_ratio)

        if matched:
            hits.append({
                "category": str(it.get("category") or ""),
                "token": str(tok),
                "weight": float(max(0.0, min(1.0, weight))),
                "match_type": mt,
            })

    return hits


def regex_screen(series: pd.Series, max_rows: int = 200, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Compute regex match probabilities for the given series.
    
    Patterns are loaded from the SENSITIVE_PATTERNS database table.
    Returns a dict of pattern -> probability (0..1), adjusted by consistency.
    """
    # Ensure patterns are loaded from the database
    _load_patterns_from_db()
    
    if not _REGEX_PATTERNS:
        logger.warning("No regex patterns loaded from database. Regex screening will be skipped.")
        return {}
        
    if series is None or series.empty:
        return {}

    vals = series.dropna().astype(str).head(max_rows)
    probs: Dict[str, float] = {}

    # Use only dynamic patterns from governance
    dyn = _compile_dynamic_patterns(cfg)
    all_keys = set(dyn.keys())

    for key in sorted(all_keys):
        # Prepare patterns list: static strings compiled + dynamic compiled
        patterns: List[str] = []
        compiled_dyn = dyn.get(key) or []
        total_considered = 0
        total_matched = 0
        rx_match_counts: Dict[int, int] = {}
        for v in vals:
            v = v.strip()
            if not v:
                continue
            total_considered += 1
            hit_rx_index: Optional[int] = None
            # Dynamic patterns only
            if compiled_dyn:
                for jdx, (_raw, cre, _w) in enumerate(compiled_dyn):
                    try:
                        if cre.search(v):
                            hit_rx_index = jdx
                            break
                    except Exception:
                        continue
            if hit_rx_index is not None:
                # extra validation for credit cards via Luhn
                if key == "credit_card":
                    digits = re.sub(r"[^0-9]", "", v)
                    if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                        continue
                total_matched += 1
                rx_match_counts[hit_rx_index] = rx_match_counts.get(hit_rx_index, 0) + 1
        if total_considered == 0:
            probs[key] = 0.0
            continue
        match_ratio = total_matched / total_considered
        most_common = max(rx_match_counts.values()) if rx_match_counts else 0
        consistency = (most_common / total_matched) if total_matched else 0.0
        strength = match_ratio * (0.7 + 0.3 * consistency)
        probs[key] = float(min(1.0, strength))

    return probs


def _name_hint_categories(col_name: str, cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    up = (col_name or "").upper()
    cats: List[str] = []
    # Dynamic keywords only (exact/fuzzy)
    dyn = _dynamic_keywords_lookup(cfg)
    for cat, items in (dyn or {}).items():
        for kw, mt, _wt in items:
            k = kw.upper()
            if mt == "exact":
                if up == k or up.endswith("_" + k) or up.startswith(k + "_"):
                    cats.append(cat)
            else:
                if k in up:
                    cats.append(cat)
    return sorted(list(set(cats)))


def analyze_metadata(table_name: str, df: pd.DataFrame, column_meta: Optional[List[Dict[str, Any]]] = None,
                     max_rows: int = 200, workers: int = 8, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Generate column-level features required for ML and scoring.

    Returns a dict: { column_name: { features... } }
    """
    if df is None or df.empty:
        return {}

    cols = list(df.columns)
    feats: Dict[str, Dict[str, Any]] = {}

    def _compute_for_col(c: str) -> Tuple[str, Dict[str, Any]]:
        s = df[c]
        base = _series_basic_stats(s)
        num = _series_numeric_stats(s)
        char = _series_charclass_ratios(s)
        rx = regex_screen(s, max_rows=max_rows, cfg=cfg)
        name_cats = _name_hint_categories(c, cfg=cfg)
        # helpful binary flags (use dynamic patterns if available)
        flags = {
            "has_uuid_ratio": float((s.astype(str).str.match(r"^[0-9a-fA-F\-]{8,}$", na=False)).mean()),
        }
        try:
            dyn = _compile_dynamic_patterns(cfg)
            for key, out_name in [("ipv4", "has_ipv4_ratio"), ("url", "has_url_ratio")]:
                cre_list = dyn.get(key) or []
                if cre_list:
                    # Use the first compiled regex
                    _cre = cre_list[0][1]
                    flags[out_name] = float((s.astype(str).map(lambda v: bool(_cre.search(str(v))))).mean())
                else:
                    flags[out_name] = 0.0
        except Exception:
            flags.setdefault("has_ipv4_ratio", 0.0)
            flags.setdefault("has_url_ratio", 0.0)
        out = {**base, **num, **char, **{f"rx_{k}": v for k, v in rx.items()}, **flags}
        out.update({f"name_hint_{cat}": 1.0 for cat in name_cats})
        out.update({"is_numeric_type": float(pd.api.types.is_numeric_dtype(s))})
        return c, out

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(_compute_for_col, c): c for c in cols}
        for fut in as_completed(futures):
            c, out = fut.result()
            feats[c] = out

    return feats


def _features_to_dataframe(features: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    if not features:
        return pd.DataFrame()
    df = pd.DataFrame(features).T.fillna(0.0)
    # ensure numeric columns only
    for col in list(df.columns):
        try:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        except Exception:
            df[col] = 0.0
    return df


def extract_column_features(df: pd.DataFrame, table_name: Optional[str] = None, max_rows: int = 200) -> pd.DataFrame:
    """Compute per-column features: null ratio, uniqueness, entropy, regex hits, char-class ratios.

    Returns a DataFrame where index are column names and columns are numeric features.
    """
    if df is None or df.empty:
        return pd.DataFrame()
    # Try dynamic config from session if present
    cfg: Optional[Dict[str, Any]] = None
    try:
        if st is not None and hasattr(st, "session_state"):
            cfg = st.session_state.get("sensitivity_config")
    except Exception:
        cfg = None
    feats = analyze_metadata(table_name or "", df, column_meta=None, max_rows=max_rows, cfg=cfg)
    return _features_to_dataframe(feats)


def detect_sensitive_bundles(df_sample: pd.DataFrame, column_features: pd.DataFrame) -> pd.DataFrame:
    """Detect multi-column bundles using dynamic configuration.

    Reads bundles from AIClassificationService.load_sensitivity_config()['bundles'] where each entry is
    expected to include: bundle_name/name, columns (list or comma string), and optional boost.

    Adds/updates columns: bundle_boost (numeric), bundles_detected (json-like str).
    Minimal no-op fallback if config is unavailable.
    """
    if df_sample is None or df_sample.empty or column_features is None or column_features.empty:
        return column_features if isinstance(column_features, pd.DataFrame) else pd.DataFrame()
    cf = column_features.copy()
    if "bundle_boost" not in cf.columns:
        cf["bundle_boost"] = 0.0
    if "bundles_detected" not in cf.columns:
        cf["bundles_detected"] = "[]"
    try:
        from src.services.ai_classification_service import ai_classification_service as _svc
        cfg = _svc.load_sensitivity_config()
        bundles_cfg = (cfg.get("bundles") or [])
        # Build a case-insensitive mapping for df columns
        df_cols = list(df_sample.columns)
        up_map = {str(c).upper(): c for c in df_cols}
        for b in bundles_cfg:
            name = str(b.get("bundle_name") or b.get("name") or "").strip()
            cols_def = b.get("columns")
            if isinstance(cols_def, str):
                cols_req = [x.strip() for x in cols_def.split(',') if x.strip()]
            elif isinstance(cols_def, (list, tuple)):
                cols_req = [str(x).strip() for x in cols_def if str(x).strip()]
            else:
                cols_req = []
            if not name or not cols_req:
                continue
            # Resolve presence by case-insensitive equality
            present = []
            for req in cols_req:
                key = req.upper()
                if key in up_map:
                    present.append(up_map[key])
            if len(present) == len(cols_req):
                boost = float(b.get("boost") or 1.0)
                for col in present:
                    if col in cf.index:
                        try:
                            cf.at[col, "bundle_boost"] = float(cf.at[col, "bundle_boost"] or 0.0) + boost
                        except Exception:
                            cf.at[col, "bundle_boost"] = boost
                        cur = cf.at[col, "bundles_detected"]
                        if not isinstance(cur, str):
                            cur = "[]"
                        if cur == "[]":
                            cf.at[col, "bundles_detected"] = f"['{name}']"
                        elif name not in cur:
                            cf.at[col, "bundles_detected"] = cur[:-1] + f", '{name}']"
    except Exception:
        # Minimal fallback: do nothing if config not available
        return cf
    return cf


def ml_predict(features: Dict[str, Dict[str, Any]], name_hints: Dict[str, List[str]],
               random_state: int = 42) -> Dict[str, float]:
    """
    Weakly-supervised ML using regex/name hints to create pseudo-labels.
    If sklearn is unavailable or not enough variety, fall back to heuristic.

    Returns: { column_name: probability_sensitive }
    """
    X = _features_to_dataframe(features)
    if X.empty:
        return {c: 0.0 for c in features.keys()}

    # Weak labels: sensitive if any strong regex hit or strong name hint
    y = []
    for c in X.index:
        rx_cols = [k for k in X.columns if k.startswith("rx_")]
        rx_max = float(X.loc[c, rx_cols].max()) if rx_cols else 0.0
        hint_sensitive = 1.0 if any(h in (name_hints.get(c) or []) for h in ["PII","PHI","Financial"]) else 0.0
        y.append(1 if (rx_max >= 0.15 or hint_sensitive >= 0.5) else 0)
    y = np.array(y, dtype=int)

    # If all labels are the same, use heuristic directly
    if y.sum() == 0 or y.sum() == len(y) or not _SKLEARN_AVAILABLE or len(X) < 4:
        probs: Dict[str, float] = {}
        for c in X.index:
            rx_cols = [k for k in X.columns if k.startswith("rx_")]
            rx_max = float(X.loc[c, rx_cols].max()) if rx_cols else 0.0
            uniq_ratio = float(X.loc[c, "unique_ratio"]) if "unique_ratio" in X.columns else 0.0
            avg_len = float(X.loc[c, "avg_len"]) if "avg_len" in X.columns else 0.0
            priors = 0.0
            if name_hints.get(c):
                priors = max(priors, 0.35)  # name hints
                for hint in name_hints[c]:
                    priors = max(priors, 0.35 * _CATEGORY_WEIGHTS.get(hint, 0.5))
            # combine using max rule to emphasize recall
            p = max(rx_max, priors, min(0.7, 0.5 * uniq_ratio + 0.01 * avg_len))
            probs[c] = float(min(1.0, p))
        return probs

    # Train simple RF on pseudo-labels
    model = RandomForestClassifier(n_estimators=200, max_depth=None, n_jobs=-1, random_state=random_state, class_weight="balanced")
    try:
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=min(0.4, max(0.2, 1.0/len(y))), random_state=random_state, stratify=y if y.sum() not in (0, len(y)) else None)
    except Exception:
        X_train, X_val, y_train, y_val = X, X, y, y
    try:
        model.fit(X_train, y_train)
    except Exception:
        # Fallback to heuristic on fit error
        return ml_predict(features, name_hints, random_state)

    try:
        proba = model.predict_proba(X)[:, 1]
    except Exception:
        # Fallback if predict_proba not available
        preds = model.predict(X)
        proba = preds.astype(float)

    probs = {c: float(p) for c, p in zip(X.index, proba)}

    # Calibrate toward high recall: ensure at least regex max
    for c in X.index:
        rx_cols = [k for k in X.columns if k.startswith("rx_")]
        rx_max = float(X.loc[c, rx_cols].max()) if rx_cols else 0.0
        probs[c] = float(max(probs[c], rx_max))

    return probs


def assign_cia(detected_type: str, probability: float, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """
    Enforce CIA mapping from governance config only (SENSITIVITY_CATEGORIES/CIA_RULES).
    No static fallback to ensure policy-only mapping.
    """
    dt = (detected_type or "").upper()
    p = float(probability or 0.0)
    try:
        if cfg and cfg.get("cia_rules"):
            rule = cfg["cia_rules"].get(dt) or cfg["cia_rules"].get(detected_type)
            if rule:
                thr = float(rule.get("MIN_THRESHOLD", 0.0))
                if p >= thr:
                    return {"C": int(rule.get("C", 0)), "I": int(rule.get("I", 0)), "A": int(rule.get("A", 0))}
        # If categories table-style config is provided
        if cfg and cfg.get("categories") and dt in cfg["categories"]:
            cdef = cfg["categories"][dt]
            return {"C": int(cdef.get("C", 0)), "I": int(cdef.get("I", 0)), "A": int(cdef.get("A", 0))}
    except Exception:
        pass
    # Strict: unknown category or missing config => zero baseline (Public)
    return {"C": 0, "I": 0, "A": 0}


def _dominant_type(name_hints: List[str], rx_probs: Dict[str, float]) -> Optional[str]:
    # Use governance-driven priority if available via dynamic config loader
    try:
        cfg = _load_dynamic_config() if _load_dynamic_config is not None else None
    except Exception:
        cfg = None
    prio: List[str] = []
    try:
        if cfg and isinstance(cfg.get("model_metadata"), dict):
            prio = list(cfg["model_metadata"].get("category_priority") or [])
    except Exception:
        prio = []
    # Candidates from name hints and regex keys directly (no static mapping)
    rx_cands = [k for k, v in (rx_probs or {}).items() if v >= 0.15]
    cands = list(dict.fromkeys((name_hints or []) + rx_cands))
    if not cands:
        return None
    for t in prio:
        if t in cands:
            return t
    return cands[0]


@lru_cache(maxsize=256)
def _cached_name_hints(table_name: str, col_name: str) -> Tuple[str, ...]:
    # Cache of static-only hints to keep signature; dynamic hints will be added at runtime in analyze step
    return tuple(_name_hint_categories(col_name, cfg=None))


def aggregate_table_sensitivity(table_name: str, col_probs: Dict[str, float]) -> Dict[str, Any]:
    if not col_probs:
        return {"table": table_name, "sensitive": False, "score": 0.0}
    sensitive_cols = [c for c, p in col_probs.items() if p >= 0.5]
    score = float(np.mean(list(col_probs.values()))) if col_probs else 0.0
    return {
        "table": table_name,
        "sensitive": len(sensitive_cols) > 0,
        "score": round(score, 3),
        "sensitive_columns": sensitive_cols,
    }


def _analyze_composites(df_in: pd.DataFrame, feats: Dict[str, Dict[str, Any]], hints: Dict[str, List[str]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze columns for composite/multi-column patterns.
    
    Args:
        df_in: Input DataFrame
        feats: Features dictionary from analyze_metadata
        hints: Name hints for columns
        cfg: Configuration dictionary
        
    Returns:
        List of composite detections, each with type, columns, and risk
    """
    comps: List[Dict[str, Any]] = []
    if df_in is None or df_in.empty:
        return comps
        
    cols = list(df_in.columns)
    up_cols = {c: c.upper() for c in cols}
    
    # Dynamic bundles from config (each bundle lists column tokens to co-occur)
    try:
        if cfg and cfg.get("bundles"):
            for b in cfg["bundles"] or []:
                if not b.get("active", True):
                    continue
                    
                toks = [str(t).upper() for t in (b.get("columns") or [])]
                if not toks:
                    continue
                    
                present = []
                for t in toks:
                    hits = [c for c in cols if t in up_cols[c]]
                    if hits:
                        present.extend(hits[:1])
                        
                if present:
                    boost = float(b.get("boost", 0.1))
                    comps.append({
                        "type": str(b.get("name") or "bundle"),
                        "columns": sorted(list(set(present))),
                        "risk": float(min(1.0, max(0.0, boost))),
                    })
    except Exception as e:
        print(f"[WARN] Error in composite analysis: {str(e)}")
        
    return comps


def classify_table_sensitivity(table_name: str, df: pd.DataFrame,
                             column_meta: Optional[List[Dict[str, Any]]] = None,
                             probability_threshold: float = 0.5) -> Dict[str, Any]:
    """
    Full pipeline for table sensitivity classification.
    
    Args:
        table_name: Name of the table being analyzed
        df: DataFrame containing sample data from the table
        column_meta: Optional list of column metadata dictionaries
        probability_threshold: Threshold for considering a column sensitive (0-1)
        
    Returns:
        Dict containing analysis results with structure:
        {
            "table": str,
            "schema": Optional[str],
            "sensitive": bool,
            "score": float,
            "columns": [
                {
                    "column": str,
                    "sensitive": bool,
                    "probability": float,
                    "suggested_cia": {"C": int, "I": int, "A": int},
                    "dominant_type": Optional[str],
                    "justification": str,
                    "related_columns": List[str],
                    "composite_hits": List[str]
                },
                ...
            ],
            "composites": List[Dict[str, Any]],
            "config_version": Optional[str]
        }
    """
    # Initialize empty result structure
    result: Dict[str, Any] = {
        "table": table_name,
        "sensitive": False,
        "score": 0.0,
        "columns": [],
        "composites": [],
        "config_version": None
    }
    
    try:
        if df is None or df.empty:
            print(f"[WARN] Empty or no data provided for table: {table_name}")
            result["error"] = "No data provided"
            return result
            
        print(f"[INFO] Analyzing table: {table_name}, shape: {df.shape}")
        
        # Load dynamic configuration once per call
        current_cfg = {}
        try:
            if _load_dynamic_config is not None:
                dynamic_cfg = _load_dynamic_config()
                if dynamic_cfg:
                    current_cfg.update(dynamic_cfg)
                    result["config_version"] = current_cfg.get("version")
        except Exception as e:
            print(f"[WARN] Could not load dynamic config: {str(e)}")

        # Analyze metadata and get name hints
        features = analyze_metadata(table_name, df, column_meta, cfg=current_cfg)
        
        # Get name hints for columns
        name_hints: Dict[str, List[str]] = {}
        for c in df.columns:
            name_hints[c] = list(_cached_name_hints(table_name, c))
        
        # Merge in dynamic keyword categories (if any)
        try:
            if current_cfg:
                for c in df.columns:
                    dyn_h = _name_hint_categories(c, cfg=current_cfg)
                    if dyn_h:
                        base = set(name_hints.get(c, []))
                        name_hints[c] = list(sorted(base.union(set(dyn_h))))
        except Exception as e:
            print(f"[WARN] Error processing name hints: {str(e)}")
            
        # Get ML predictions
        probs = ml_predict(features, name_hints)

        # Run composite analysis
        composites = _analyze_composites(df, features, name_hints, current_cfg)
        result["composites"] = composites

        # Build column outputs
        columns_out: List[Dict[str, Any]] = []
        sensitive_columns = 0
        total_confidence = 0.0
        
        for c in df.columns:
            f = features.get(c, {})
            rx_probs = {k.replace("rx_", ""): float(v) for k, v in f.items() if k.startswith("rx_")}
            dom = _dominant_type(name_hints.get(c) or [], rx_probs)
            # Ensemble: combine regex and ML using weighted average, retain recall by upper-bounding with max
            rx_max = max(rx_probs.values()) if rx_probs else 0.0
            p_ml = float(probs.get(c, 0.0))
            
            # Calculate combined probability with weighted average
            w_rx = 0.7  # Higher weight for regex patterns
            w_ml = 0.3  # Lower weight for ML
            p_combined = (w_rx * rx_max + w_ml * p_ml) / (w_rx + w_ml)
            p_combined = max(p_combined, rx_max, p_ml)  # Upper-bound by max of all
            
            # Check if column is sensitive
            is_sensitive = p_combined >= probability_threshold
            if is_sensitive:
                sensitive_columns += 1
                total_confidence += p_combined
                
            # Get CIA classification
            cia = assign_cia(dom, p_combined, current_cfg) if dom else {"C": 0, "I": 0, "A": 0}
            
            # Add column to results
            columns_out.append({
                "column": c,
                "sensitive": is_sensitive,
                "probability": round(p_combined, 4),
                "suggested_cia": cia,
                "dominant_type": dom,
                "justification": f"Detected as {dom} with {p_combined*100:.1f}% confidence" if dom else "No specific type detected",
                "related_columns": [],
                "composite_hits": [
                    c for comp in composites 
                    if c in comp.get("columns", []) and comp.get("type") == dom
                ]
            })
            
        # Update result with column analysis
        result["columns"] = columns_out
        result["sensitive"] = sensitive_columns > 0
        result["score"] = round(total_confidence / max(1, sensitive_columns), 4) if sensitive_columns > 0 else 0.0
        
    except Exception as e:
        print(f"[ERROR] Error in sensitivity classification for {table_name}: {str(e)}")
        result["error"] = f"Classification error: {str(e)}"
        
    # Apply embeddings-based related column grouping and boost if available
    try:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            import numpy as _np  # type: ignore
            _emb_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        except Exception as e:
            _emb_model = None
            _np = None
            
        if _emb_model is not None and _np is not None and columns_out:
            names = [r["column"] for r in columns_out]
            texts = [re.sub(r"[_\-]+", " ", n).strip() for n in names]
            vecs = _emb_model.encode(texts, normalize_embeddings=True)
            vecs = _np.array(vecs)
            n = len(names)
            groups: List[List[int]] = []
            used = set()
            
            # Group similar column names using embeddings
            for i in range(n):
                if i in used:
                    continue
                grp = [i]
                used.add(i)
                for j in range(i+1, n):
                    if j in used:
                        continue
                    sim = float(_np.dot(vecs[i], vecs[j]))
                    if sim >= 0.80:  # Similarity threshold
                        grp.append(j)
                        used.add(j)
                if len(grp) >= 2:
                    groups.append(grp)
            
            # Apply boost and set related columns for each group
            for grp in groups:
                rel_names = [names[k] for k in grp]
                for idx in grp:
                    row = columns_out[idx]
                    row["related_columns"] = [n for n in rel_names if n != row["column"]]
                    
                    # Boost probability for grouped columns
                    base_p = float(row.get("probability", 0.0))
                    if base_p < 0.85:  # Only boost if not already high confidence
                        row["probability"] = round(float(min(1.0, 0.15 + 0.85 * base_p)), 3)
                    
                    # Update sensitive flag and CIA based on new probability
                    row["sensitive"] = bool(row["probability"] >= probability_threshold)
                    row["suggested_cia"] = assign_cia(
                        row.get("dominant_type") or ("PII" if row["sensitive"] else "Public"),
                        row["probability"]
                    )
    except Exception as e:
        print(f"[WARN] Error in embeddings-based analysis: {str(e)}")
    
    # Aggregate results at table level
    table_agg = aggregate_table_sensitivity(
        table_name, 
        {r["column"]: r["probability"] for r in columns_out}
    )
    
    # Prepare final result
    result.update({
        "schema": None,
        "sensitive": bool(table_agg["sensitive"]),
        "score": float(table_agg["score"]),
        "config_version": (current_cfg.get("version") if current_cfg else None),
    })
    
    return result


# ---------------------- Sample Usage ----------------------
if __name__ == "__main__":
    data = {
        "id": [1, 2, 3, 4, 5],
        "email_address": ["alice@example.com", "bob@corp.org", None, "charlie@mail.com", "delta@xyz.io"],
        "phone": ["+1-202-555-0101", None, "(020) 7946 0958", "1234567", ""],
        "invoice_amount": [100.50, 200.0, 150.75, 0.0, 9999.99],
        "account_no": ["123456789", "987654321", "123-456-789", None, "111222333"],
        "notes": ["call back", "VIP customer", "N/A", "see https://example.com", "GL-LEDGER"],
    }
    df_demo = pd.DataFrame(data)
    result = classify_table_sensitivity("PUBLIC.DEMO.CUSTOMERS", df_demo)
    print(pd.DataFrame(result["columns"]))
    print({k: v for k, v in result.items() if k != "columns"})
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np
from collections import defaultdict

class SensitiveDataDetector:
    """
    Core sensitive data detection engine with multi-layered detection:
    1. Metadata pattern matching (table/column names)
    2. Regex-based data sampling
    3. AI-assisted classification
    4. Configurable category sensitivity weights
    """
    
    def __init__(self, governance_db: Optional[str] = None, governance_schema: str = 'DATA_CLASSIFICATION_GOVERNANCE'):
        """Initialize the detector with configuration.
        
        Args:
            governance_db: Name of the governance database
            governance_schema: Schema containing the governance tables
        """
        self.governance_db = governance_db
        self.governance_schema = governance_schema
        self.sample_size = 100
        self.min_confidence = 0.6
        self.use_ai = True
        
        # Initialize configuration
        self._config = {
            'categories': None,
            'keywords': None,
            'patterns': None,
            'thresholds': None,
            'last_loaded': None
        }
        
        # Legacy attributes for backward compatibility
        self.patterns = {}
        self.keywords = {}
        self.weights = {}
        
        # Load configuration
        try:
            self._load_configuration()
        except Exception as e:
            logger.warning(f"Failed to load detection configuration: {e}")
    
    def _load_configuration(self) -> None:
        """Load configuration from governance database."""
        if not self.governance_db or not snowflake_connector:
            logger.warning("Governance database or connector not available")
            return
            
        try:
            # Load categories
            categories = self._load_categories()
            
            # Load keywords with category info
            keywords = self._load_keywords()
            
            # Load patterns with compiled regex
            patterns = self._load_patterns()
            
            # Load thresholds
            thresholds = self._load_thresholds()
            
            # Update config
            self._config.update({
                'categories': categories,
                'keywords': keywords,
                'patterns': patterns,
                'thresholds': thresholds,
                'last_loaded': datetime.utcnow()
            })
            
            logger.info("Successfully loaded detection configuration")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _load_categories(self) -> Dict[str, Dict]:
        """Load sensitivity categories from the database."""
        query = f"""
            SELECT 
                CATEGORY_ID,
                CATEGORY_NAME,
                DESCRIPTION,
                CONFIDENTIALITY_LEVEL,
                DETECTION_THRESHOLD,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.SENSITIVITY_CATEGORIES
            WHERE IS_ACTIVE = TRUE
        """
        
        rows = snowflake_connector.execute_query(query) or []
        return {row['CATEGORY_ID']: dict(row) for row in rows}
    
    def _load_keywords(self) -> List[Dict]:
        """Load sensitive keywords from the database."""
        query = f"""
            SELECT 
                k.KEYWORD_ID,
                k.CATEGORY_ID,
                k.KEYWORD_STRING,
                k.MATCH_TYPE,
                k.SENSITIVITY_WEIGHT,
                c.CATEGORY_NAME,
                k.IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.SENSITIVE_KEYWORDS k
            JOIN {self.governance_db}.{self.governance_schema}.SENSITIVITY_CATEGORIES c
                ON k.CATEGORY_ID = c.CATEGORY_ID
            WHERE k.IS_ACTIVE = TRUE
            ORDER BY k.SENSITIVITY_WEIGHT DESC
        """
        
        return snowflake_connector.execute_query(query) or []
    
    def _load_patterns(self) -> List[Dict]:
        """Load detection patterns from the database."""
        query = f"""
            SELECT 
                p.PATTERN_ID,
                p.CATEGORY_ID,
                p.PATTERN_STRING,
                p.PATTERN_TYPE,
                p.SENSITIVITY_WEIGHT,
                c.CATEGORY_NAME,
                p.IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.SENSITIVE_PATTERNS p
            JOIN {self.governance_db}.{self.governance_schema}.SENSITIVITY_CATEGORIES c
                ON p.CATEGORY_ID = c.CATEGORY_ID
            WHERE p.IS_ACTIVE = TRUE
            ORDER BY p.SENSITIVITY_WEIGHT DESC
        """
        
        patterns = snowflake_connector.execute_query(query) or []
        
        # Pre-compile regex patterns for better performance
        for pattern in patterns:
            try:
                pattern['compiled_pattern'] = re.compile(
                    pattern['PATTERN_STRING'], 
                    re.IGNORECASE | re.MULTILINE
                )
            except re.error as e:
                logger.warning(f"Invalid regex pattern {pattern['PATTERN_STRING']}: {e}")
                pattern['compiled_pattern'] = None
        
        return patterns
    
    def _load_thresholds(self) -> List[Dict]:
        """Load sensitivity thresholds from the database."""
        query = f"""
            SELECT 
                THRESHOLD_NAME,
                CONFIDENCE_LEVEL,
                SENSITIVITY_LEVEL,
                DESCRIPTION,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.SENSITIVITY_THRESHOLDS
            WHERE IS_ACTIVE = TRUE
            ORDER BY CONFIDENCE_LEVEL DESC
        """
        
        return snowflake_connector.execute_query(query) or []
    
    def _determine_sensitivity_level(self, confidence: float) -> str:
        """Determine the sensitivity level based on confidence score."""
        if not self._config['thresholds']:
            # Default thresholds if not configured
            if confidence >= 0.8:
                return "HIGH"
            elif confidence >= 0.5:
                return "MEDIUM"
            elif confidence >= 0.3:
                return "LOW"
            return "NONE"
        
        # Use configured thresholds
        for threshold in self._config['thresholds']:
            if confidence >= threshold['CONFIDENCE_LEVEL']:
                return threshold['SENSITIVITY_LEVEL']
        
        return "NONE"
    
    def _check_keyword_matches(self, text: str) -> List[Dict]:
        """Check if text contains any sensitive keywords."""
        if not text or not self._config['keywords']:
            return []
            
        matches = []
        text_upper = text.upper()
        
        for keyword in self._config['keywords']:
            keyword_str = keyword['KEYWORD_STRING'].upper()
            match_type = keyword.get('MATCH_TYPE', '').upper()
            
            if match_type == 'EXACT' and keyword_str == text_upper:
                matches.append({
                    'keyword_id': keyword['KEYWORD_ID'],
                    'keyword': keyword_str,
                    'category_id': keyword['CATEGORY_ID'],
                    'category_name': keyword['CATEGORY_NAME'],
                    'match_type': 'exact',
                    'weight': float(keyword['SENSITIVITY_WEIGHT'] or 0)
                })
            elif match_type == 'CONTAINS' and keyword_str in text_upper:
                matches.append({
                    'keyword_id': keyword['KEYWORD_ID'],
                    'keyword': keyword_str,
                    'category_id': keyword['CATEGORY_ID'],
                    'category_name': keyword['CATEGORY_NAME'],
                    'match_type': 'contains',
                    'weight': float(keyword['SENSITIVITY_WEIGHT'] or 0)
                })
            elif match_type == 'REGEX':
                try:
                    if re.search(keyword_str, text_upper, re.IGNORECASE):
                        matches.append({
                            'keyword_id': keyword['KEYWORD_ID'],
                            'keyword': keyword_str,
                            'category_id': keyword['CATEGORY_ID'],
                            'category_name': keyword['CATEGORY_NAME'],
                            'match_type': 'regex',
                            'weight': float(keyword['SENSITIVITY_WEIGHT'] or 0)
                        })
                except re.error:
                    logger.warning(f"Invalid regex pattern in keyword: {keyword_str}")
        
        return matches
    
    def _check_pattern_matches(self, text: str) -> List[Dict]:
        """Check if text matches any sensitive patterns."""
        if not text or not isinstance(text, str) or not self._config['patterns']:
            return []
            
        matches = []
        
        for pattern in self._config['patterns']:
            if not pattern.get('compiled_pattern'):
                continue
                
            if pattern['compiled_pattern'].search(text):
                matches.append({
                    'pattern_id': pattern['PATTERN_ID'],
                    'pattern': pattern['PATTERN_STRING'],
                    'category_id': pattern['CATEGORY_ID'],
                    'category_name': pattern['CATEGORY_NAME'],
                    'weight': float(pattern['SENSITIVITY_WEIGHT'] or 0)
                })
        
        return matches
    
    def _sample_column_data(self, database: str, schema: str, table: str, column: str) -> List[Any]:
        """Sample data from a table column for pattern matching."""
        if self.sample_size <= 0 or not snowflake_connector:
            return []
            
        query = f"""
            SELECT "{column}" as sample_value
            FROM "{database}"."{schema}"."{table}"
            WHERE "{column}" IS NOT NULL
            SAMPLE ({self.sample_size} ROWS)
        """
        
        try:
            results = snowflake_connector.execute_query(query) or []
            return [row['SAMPLE_VALUE'] for row in results if row['SAMPLE_VALUE'] is not None]
        except Exception as e:
            logger.warning(f"Error sampling data from {database}.{schema}.{table}.{column}: {e}")
            return []
    
    def _calculate_confidence(self, matches: List[Dict]) -> float:
        """Calculate confidence score based on matches and weights."""
        if not matches:
            return 0.0
            
        # Use the highest weight match
        max_weight = max(float(match.get('weight', 0)) for match in matches)
        
        # Normalize to 0-1 range
        return min(max_weight / 100.0, 1.0)
    
    def detect_sensitive_columns(
        self,
        database: str,
        schema_name: Optional[str] = None,
        table_name: Optional[str] = None,
        column_name: Optional[str] = None
    ) -> List[Dict]:
        """Detect sensitive data in database columns.
        
        Args:
            database: Database name
            schema_name: Optional schema name filter
            table_name: Optional table name filter
            column_name: Optional column name filter
            
        Returns:
            List of detection results for each column analyzed
        """
        if not snowflake_connector:
            logger.error("Snowflake connector not available")
            return []
            
        # Build query to get column metadata
        query = f"""
            SELECT 
                TABLE_SCHEMA,
                TABLE_NAME, 
                COLUMN_NAME,
                DATA_TYPE
            FROM "{database}".INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
        """
        
        params = {}
        
        if schema_name:
            query += " AND TABLE_SCHEMA = %(schema_name)s"
            params['schema_name'] = schema_name
            
        if table_name:
            query += " AND TABLE_NAME = %(table_name)s"
            params['table_name'] = table_name
            
        if column_name:
            query += " AND COLUMN_NAME = %(column_name)s"
            params['column_name'] = column_name
            
        query += " ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
        
        # Get all columns to analyze
        columns = snowflake_connector.execute_query(query, params) or []
        
        if not columns:
            logger.warning(f"No columns found matching criteria in database: {database}")
            return []
        
        results = []
        
        # Process each column
        for col in columns:
            try:
                schema = col['TABLE_SCHEMA']
                table = col['TABLE_NAME']
                column = col['COLUMN_NAME']
                data_type = col['DATA_TYPE']
                
                logger.debug(f"Analyzing column: {schema}.{table}.{column}")
                
                # 1. Check column name against keywords
                column_matches = self._check_keyword_matches(column)
                table_matches = self._check_keyword_matches(table)
                schema_matches = self._check_keyword_matches(schema)
                
                # 2. Sample data and check for pattern matches
                sample_values = []
                data_matches = []
                
                if self.sample_size > 0 and snowflake_connector:
                    sample_values = self._sample_column_data(database, schema, table, column)
                    
                    # Check each sample value against patterns
                    for value in sample_values:
                        if value is None:
                            continue
                        data_matches.extend(self._check_pattern_matches(str(value)))
                
                # 3. Combine all matches
                all_matches = column_matches + table_matches + schema_matches + data_matches
                
                # Calculate confidence and sensitivity
                confidence = self._calculate_confidence(all_matches)
                sensitivity_level = self._determine_sensitivity_level(confidence)
                
                # Get unique categories
                detected_categories = set()
                for match in all_matches:
                    if 'category_id' in match and match['category_id'] not in detected_categories:
                        detected_categories.add(match['category_id'])
                
                # Create result dictionary
                result = {
                    'database': database,
                    'schema': schema,
                    'table': table,
                    'column': column,
                    'data_type': data_type,
                    'confidence': confidence,
                    'sensitivity_score': confidence * 100,  # Convert to 0-100 scale
                    'sensitivity_level': sensitivity_level,
                    'detected_categories': list(detected_categories),
                    'sample_values': sample_values[:5],  # Keep first 5 samples
                    'match_details': {
                        'column_matches': column_matches,
                        'table_matches': table_matches,
                        'schema_matches': schema_matches,
                        'data_matches': data_matches
                    }
                }
                
                # Add to results if sensitive or above threshold
                if confidence >= self.min_confidence or sensitivity_level != "NONE":
                    results.append(result)
                
            except Exception as e:
                logger.error(
                    f"Error processing column {col.get('TABLE_SCHEMA', '?')}."
                    f"{col.get('TABLE_NAME', '?')}.{col.get('COLUMN_NAME', '?')}: {e}"
                )
        
        return results
    
    def detect_sensitive_tables(
        self,
        database: str,
        schema_name: Optional[str] = None,
        table_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Detect sensitive tables based on column analysis.
        
        Args:
            database: Database name
            schema_name: Optional schema name filter
            table_name: Optional table name filter
            
        Returns:
            List of dictionaries with table-level sensitivity information
        """
        # First, detect sensitive columns
        column_results = self.detect_sensitive_columns(
            database=database,
            schema_name=schema_name,
            table_name=table_name
        )
        
        # Group by table
        table_results = {}
        
        for col_result in column_results:
            table_key = f"{col_result['schema']}.{col_result['table']}"
            
            if table_key not in table_results:
                table_results[table_key] = {
                    'database': database,
                    'schema': col_result['schema'],
                    'table': col_result['table'],
                    'sensitive_columns': [],
                    'sensitivity_score': 0,
                    'sensitivity_level': 'NONE',
                    'categories': set(),
                    'last_scanned': datetime.utcnow().isoformat()
                }
            
            # Add column info
            table_results[table_key]['sensitive_columns'].append({
                'column_name': col_result['column'],
                'data_type': col_result['data_type'],
                'sensitivity_score': col_result['sensitivity_score'],
                'sensitivity_level': col_result['sensitivity_level'],
                'confidence': col_result['confidence'],
                'detected_categories': col_result['detected_categories']
            })
            
            # Track highest sensitivity level
            current_level = table_results[table_key]['sensitivity_level']
            if col_result['sensitivity_level'] == 'HIGH' or \
               (current_level == 'MEDIUM' and col_result['sensitivity_level'] == 'LOW') or \
               (current_level == 'NONE' and col_result['sensitivity_level'] in ['LOW', 'MEDIUM']):
                table_results[table_key]['sensitivity_level'] = col_result['sensitivity_level']
            
            # Track categories
            table_results[table_key]['categories'].update(col_result['detected_categories'])
            
            # Update max score
            table_results[table_key]['sensitivity_score'] = max(
                table_results[table_key]['sensitivity_score'],
                col_result['sensitivity_score']
            )
        
        # Convert to list and format categories
        results = []
        for table_info in table_results.values():
            table_info['categories'] = list(table_info['categories'])
            results.append(table_info)
        
        return results
        
    def configure(self, patterns: Dict, keywords: Dict, weights: Dict):
        """Configure detection rules and weights"""
        self.patterns = patterns
        self.keywords = keywords 
        self.weights = weights
        
    def detect_column(self, name: str, sample_data: pd.Series) -> Dict[str, Any]:
        """Multi-signal column sensitivity detection"""
        signals = defaultdict(float)
        
        # 1. Pattern matching on sample data
        if not sample_data.empty:
            pattern_scores = self._apply_patterns(sample_data)
            for category, score in pattern_scores.items():
                signals[category] += score * self.weights.get("pattern", 0.4)
                
        # 2. Name-based detection
        name_scores = self._analyze_name(name)
        for category, score in name_scores.items():
            signals[category] += score * self.weights.get("name", 0.3)
            
        # 3. Statistical profiling
        profile_scores = self._profile_data(sample_data)
        for category, score in profile_scores.items():
            signals[category] += score * self.weights.get("profile", 0.3)
            
        # 4. Determine dominant category and confidence
        if signals:
            dominant = max(signals.items(), key=lambda x: x[1])
            confidence = dominant[1]
            categories = [k for k, v in signals.items() if v >= confidence * 0.7]
        else:
            dominant = (None, 0)
            confidence = 0
            categories = []
            
        return {
            "dominant_category": dominant[0],
            "confidence": confidence,
            "categories": categories,
            "signals": dict(signals)
        }
        
    def _apply_patterns(self, series: pd.Series) -> Dict[str, float]:
        """Apply regex patterns to sample data"""
        scores = defaultdict(float)
        
        # Skip if no data
        if series.empty:
            return dict(scores)
            
        # Apply each pattern category
        for category, patterns in self.patterns.items():
            matches = 0
            total = 0
            
            for pattern in patterns:
                try:
                    # Apply regex to non-null string values
                    mask = series.astype(str).str.match(pattern, na=False)
                    matches += mask.sum()
                    total += len(mask)
                except Exception:
                    continue
                    
            # Calculate match ratio
            if total > 0:
                score = matches / total
                scores[category] = score
                
        return dict(scores)
        
    def _analyze_name(self, name: str) -> Dict[str, float]:
        """Analyze column name for sensitivity signals"""
        scores = defaultdict(float)
        
        # Skip if no name
        if not name:
            return dict(scores)
            
        name = name.lower()
        
        # Check each category's keywords
        for category, keywords in self.keywords.items():
            category_score = 0
            
            for keyword in keywords:
                if keyword.lower() in name:
                    category_score += 1
                    
            if category_score > 0:
                scores[category] = min(category_score / len(keywords), 1.0)
                
        return dict(scores)
        
    def _profile_data(self, series: pd.Series) -> Dict[str, float]:
        """Statistical profiling for validation"""
        scores = defaultdict(float)
        
        # Skip if no data
        if series.empty:
            return dict(scores)
            
        try:
            # Basic statistics
            null_ratio = series.isnull().mean()
            unique_ratio = series.nunique() / len(series)
            
            # Analyze value patterns
            if series.dtype == object:
                # Text analysis
                text_stats = self._analyze_text_patterns(series)
                scores.update(text_stats)
            elif np.issubdtype(series.dtype, np.number):
                # Numeric analysis
                num_stats = self._analyze_numeric_patterns(series)
                scores.update(num_stats)
                
        except Exception:
            pass
            
        return dict(scores)
        
    def _analyze_text_patterns(self, series: pd.Series) -> Dict[str, float]:
        """Analyze text data patterns"""
        scores = defaultdict(float)
        
        try:
            # Sample non-null values
            sample = series.dropna().astype(str).sample(
                n=min(1000, len(series)),
                random_state=42
            )
            
            # Character pattern analysis
            has_numbers = sample.str.contains(r'\d').mean()
            has_special = sample.str.contains(r'[^A-Za-z0-9\s]').mean()
            
            # Length analysis
            lengths = sample.str.len()
            length_std = lengths.std()
            
            # Update category scores based on patterns
            if has_numbers > 0.8 and length_std < 2:
                scores["ID_NUMBER"] = 0.8
            if has_special > 0.5:
                scores["ENCRYPTED"] = 0.6
                
        except Exception:
            pass
            
        return dict(scores)
        
    def _analyze_numeric_patterns(self, series: pd.Series) -> Dict[str, float]:
        """Analyze numeric data patterns"""
        scores = defaultdict(float)
        
        try:
            # Basic statistics
            std = series.std()
            mean = series.mean()
            cv = std / mean if mean != 0 else 0
            
            # Update scores based on patterns
            if 0 <= cv <= 0.1:
                scores["SEQUENTIAL"] = 0.7
            if series.min() >= 0 and series.max() <= 1:
                scores["PROBABILITY"] = 0.8
                
        except Exception:
            pass
            
        return dict(scores)
