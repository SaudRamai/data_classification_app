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
# All regex patterns must be provided by governance config tables (SENSITIVE_PATTERNS).
# Keep an empty default to ensure we never rely on hard-coded expressions.
_REGEX_PATTERNS: Dict[str, List[str]] = {}

# Name tokens mapping to sensitive categories (for hints)
_NAME_TOKENS: Dict[str, List[str]] = {}

_CATEGORY_WEIGHTS: Dict[str, float] = {
    "PII": 1.0,
    "PHI": 0.95,
    "Financial": 0.9,
}


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


def _series_numeric_stats(series: pd.Series) -> Dict[str, float]:
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return {"num_min": 0.0, "num_max": 0.0, "num_mean": 0.0, "num_std": 0.0, "num_skew": 0.0, "num_kurt": 0.0}
    return {
        "num_min": float(s.min()),
        "num_max": float(s.max()),
        "num_mean": float(s.mean()),
        "num_std": float(s.std(ddof=0) if len(s) > 1 else 0.0),
        "num_skew": float(s.skew() if len(s) > 2 else 0.0),
        "num_kurt": float(s.kurt() if len(s) > 3 else 0.0),
    }


def _series_charclass_ratios(series: pd.Series) -> Dict[str, float]:
    s = series.dropna().astype(str)
    if s.empty:
        return {"digit_ratio": 0.0, "alpha_ratio": 0.0, "space_ratio": 0.0, "punct_ratio": 0.0}
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
            except Exception:
                continue
    return flat


def _name_tokens_for(colname: str, cfg: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Map a column name to sensitivity categories using dynamic keywords.
    Returns: list of {"category","token","weight", "match_type"}
    Matching:
      - Exact: normalized equality with tokens or whole-piece match => weight as provided (default 1.0)
      - Fuzzy: substring/similarity using difflib ratio => weight scaled (default 0.8 * ratio)
    """
    try:
        if cfg is None and st is not None and hasattr(st, "session_state"):
            cfg = st.session_state.get("sensitivity_config")
    except Exception:
        pass

    name_tokens = _split_camel_and_delims(colname)
    name_norm = _normalize_name(colname)
    if not name_norm:
        return []

    # Prepare keyword list with precomputed normalized token
    flat = _flatten_keywords(cfg)
    for it in flat:
        try:
            it["token_norm"] = _normalize_name(it.get("token") or "")
        except Exception:
            it["token_norm"] = ""

    hits: List[Dict[str, Any]] = []
    from difflib import SequenceMatcher

    for it in flat:
        tok = it.get("token") or ""
        tok_norm = it.get("token_norm") or ""
        if not tok_norm:
            continue
        mt = str(it.get("match_type") or "fuzzy").lower()
        base_w = float(it.get("weight", 0.8 if mt != "exact" else 1.0))

        matched = False
        weight = 0.0
        # Exact: whole normalized string equal or any token-piece equals original keyword (case-insensitive)
        if mt == "exact":
            if name_norm == tok_norm or tok.lower() in [t.lower() for t in name_tokens]:
                matched = True
                weight = 1.0 if base_w is None else float(base_w)
        else:
            # Fuzzy: substring or similarity against full normalized name and each piece
            if tok_norm in name_norm:
                matched = True
                weight = float(base_w)
            else:
                # Try best ratio against pieces and full
                cand_strs = [name_norm] + [ _normalize_name(p) for p in name_tokens ]
                best_ratio = 0.0
                for s in cand_strs:
                    try:
                        r = SequenceMatcher(None, tok_norm, s).ratio()
                        if r > best_ratio:
                            best_ratio = r
                    except Exception:
                        continue
                thr = 0.8
                try:
                    if isinstance(cfg, dict) and isinstance(cfg.get("model_metadata"), dict):
                        thr = float((cfg["model_metadata"].get("thresholds") or {}).get("token_fuzzy_threshold", thr))
                except Exception:
                    pass
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


def _compile_dynamic_patterns(cfg: Optional[Dict[str, Any]]) -> Dict[str, List[Tuple[str, Any, float]]]:
    """
    Build dynamic pattern catalog from configuration.
    Returns: {category: [(name, compiled_regex, weight), ...]}
    """
    out: Dict[str, List[Tuple[str, Any, float]]] = {}
    if not cfg:
        return out
    try:
        pats = cfg.get("patterns") or {}
        if isinstance(pats, dict):
            for cat, items in (pats or {}).items():
                for it in (items or []):
                    try:
                        rx = str(it.get("regex") or it.get("pattern") or "").strip()
                        if not rx:
                            continue
                        wt = float(it.get("weight", 0.5))
                        cre = re.compile(rx)
                        out.setdefault(str(cat), []).append((rx, cre, wt))
                    except Exception:
                        continue
        elif isinstance(pats, list):
            for it in (pats or []):
                try:
                    cat = str(it.get("category") or "").strip()
                    rx = str(it.get("regex") or it.get("pattern") or "").strip()
                    if not cat or not rx:
                        continue
                    wt = float(it.get("weight", 0.5))
                    cre = re.compile(rx)
                    out.setdefault(cat, []).append((rx, cre, wt))
                except Exception:
                    continue
    except Exception:
        return out


def classify_sensitive_columns(features_df: pd.DataFrame, table_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """Classify sensitive columns using regex, keyword, ML, and semantic hints.

    Args:
      features_df: DataFrame where each row represents a column and includes fields like
        - column (str)
        - regex_hits (list[str]) [optional]
        - token_hits (list[str]) [optional]
        - numeric/statistical features (e.g., uniqueness, entropy, ratios)
      table_name: Optional full table name for persistence.

    Returns: list of dict rows with keys:
      column, dominant_category, confidence, suggested_cia, related_columns, bundle_boost, regex_hits, token_hits
    """
    if features_df is None or features_df.empty:
        return []

    # Load dynamic config from session if available
    cfg: Optional[Dict[str, Any]] = None
    try:
        if st is not None and hasattr(st, "session_state"):
            cfg = st.session_state.get("sensitivity_config")
    except Exception:
        cfg = None

    # Helper to get CIA mapping from config categories
    def _cia_for(cat: Optional[str]) -> Dict[str, int]:
        try:
            # Governance-driven category priority (fallback to natural order if unavailable)
            try:
                cfg = _load_dynamic_config() if _load_dynamic_config is not None else None
                _prio_seq = []
                if cfg and isinstance(cfg.get("model_metadata"), dict):
                    _prio_seq = list(cfg["model_metadata"].get("category_priority") or [])
                PRIORITY = {c: i for i, c in enumerate(_prio_seq)} if _prio_seq else {}
            except Exception:
                PRIORITY = {}
            if cfg and cfg.get("categories") and cfg["categories"].get(cat):
                return {"C": int(cfg["categories"][cat].get("C", 0)),
                        "I": int(cfg["categories"][cat].get("I", 0)),
                        "A": int(cfg["categories"][cat].get("A", 0))}
        except Exception:
            pass
        # Fallback
        return assign_cia(cat or "Public", 1.0)

    # Normalize features_df columns
    df = features_df.copy()
    if "column" not in df.columns:
        df["column"] = df.index.astype(str)

    # Helper for token-score normalization: per-piece best weights
    def _token_score_for(col_name: str, hits: List[Dict[str, Any]]) -> float:
        pieces = _split_camel_and_delims(col_name)
        if not pieces:
            return 0.0
        best_per_piece: List[float] = []
        for p in pieces:
            p_norm = _normalize_name(p)
            best = 0.0
            for h in hits:
                tok = str(h.get("token") or "")
                tnorm = _normalize_name(tok)
                if not tnorm:
                    continue
                if tnorm == p_norm or tnorm in p_norm or p_norm in tnorm:
                    best = max(best, float(h.get("weight", 0.0)))
            best_per_piece.append(best)
        score = sum(best_per_piece) / float(len(pieces))
        return float(max(0.0, min(1.0, score)))

    # Category embeddings built from dynamic keywords
    def _build_category_embeddings(cfg_in: Optional[Dict[str, Any]]):
        model, _np = _get_embedding_model()
        if model is None or _np is None or not cfg_in:
            return {}
        cats: Dict[str, List[str]] = {}
        # Prefer flattened list if provided
        kw_items = cfg_in.get("keywords_flat") or cfg_in.get("keywords") or []
        # If keywords is a dict of category->items, convert to flat items
        if isinstance(kw_items, dict):
            flat: List[Dict[str, Any]] = []
            try:
                for _cat, _lst in kw_items.items():
                    for _it in (_lst or []):
                        flat.append({
                            "category": _cat,
                            "token": _it.get("token") or _it.get("keyword"),
                        })
            except Exception:
                flat = []
            kw_items = flat
        for item in (kw_items or []):
            try:
                cat = str(item.get("category") or "").strip()
                tok = str(item.get("token") or "").strip()
                if cat and tok:
                    cats.setdefault(cat, []).append(tok)
            except Exception:
                continue
        embeds: Dict[str, Any] = {}
        for cat, toks in cats.items():
            try:
                vecs = model.encode(toks, normalize_embeddings=True)
                vecs = _np.array(vecs)
                if vecs.size == 0:
                    continue
                embeds[cat] = vecs.mean(axis=0)
            except Exception:
                continue
        return embeds

    def _semantic_similarity(col_name: str, samples: List[str], cat_embeds: Dict[str, Any]) -> Tuple[Optional[str], float]:
        model, _np = _get_embedding_model()
        if model is None or _np is None or not cat_embeds:
            return None, 0.0
        try:
            text = (re.sub(r"[_\-]+", " ", col_name or "").strip() + " " + " ".join([str(s) for s in (samples or [])][:10])).strip()
            if not text:
                return None, 0.0
            col_vec = model.encode([text], normalize_embeddings=True)
            col_vec = _np.array(col_vec)[0]
            sims: Dict[str, float] = {}
            for cat, ref in cat_embeds.items():
                try:
                    sims[cat] = float(_np.dot(col_vec, ref))
                except Exception:
                    continue
            if not sims:
                return None, 0.0
            cat, sc = max(sims.items(), key=lambda kv: kv[1])
            return cat, float(max(0.0, min(1.0, sc)))
        except Exception:
            return None, 0.0

    out: List[Dict[str, Any]] = []
    cols = list(df["column"].astype(str))
    cols_upper = [c.upper() for c in cols]
    # Build a quick lookup for bundles to find related columns
    bundles = cfg.get("bundles") if cfg else []
    cat_embeds = _build_category_embeddings(cfg)

    for idx, row in df.iterrows():
        colname = str(row.get("column"))
        up = colname.upper()
        # Collect regex and token hits if provided, else approximate from features
        regex_hits = list(row.get("regex_hits") or [])
        token_hits = list(row.get("token_hits") or [])
        if not regex_hits:
            # derive from rx_* columns with non-zero values
            try:
                rx_thr = 0.15
                if cfg and isinstance(cfg.get("model_metadata"), dict):
                    rx_thr = float((cfg["model_metadata"].get("thresholds", {}) or {}).get("rx_feature_hit_threshold", rx_thr))
                regex_hits = [k.replace("rx_", "") for k, v in row.items() if isinstance(k, str) and k.startswith("rx_") and float(v or 0.0) > float(rx_thr)]
            except Exception:
                regex_hits = [k.replace("rx_", "") for k, v in row.items() if isinstance(k, str) and k.startswith("rx_") and float(v or 0.0) > 0.15]
        if not token_hits:
            token_hits = _name_tokens_for(colname, cfg)

        # Scores per spec (normalize by total configured items where meaningful)
        try:
            total_patterns = max(1, len(regex_hits) + 3)  # guard; if not explicit list, treat hits magnitude as proxy
            regex_score = min(1.0, float(len(regex_hits)) / float(total_patterns))
        except Exception:
            regex_score = 0.0
        try:
            token_score = _token_score_for(colname, token_hits)
        except Exception:
            token_score = 0.0

        # ML probability (use an existing heuristic model on engineered features if present)
        ml_conf = 0.0
        try:
            # Heuristic from provided features: uniqueness, entropy, digit ratio
            uniq = float(row.get("unique_ratio") or row.get("uniqueness") or 0.0)
            entr = float(row.get("avg_entropy") or 0.0)
            dig = float(row.get("digit_ratio") or 0.0)
            base = 0.0
            if uniq >= 0.8 and entr >= 2.0:
                base += 0.5
            elif uniq >= 0.6 and entr >= 1.5:
                base += 0.3
            if dig >= 0.5:
                base += 0.2
            ml_conf = max(0.0, min(1.0, base))
        except Exception:
            ml_conf = 0.0

        # Semantic similarity
        samples = list(row.get("sample_values") or [])
        sem_cat, sem_sim = _semantic_similarity(colname, samples, cat_embeds)
        semantic_conf = float(max(0.0, min(1.0, sem_sim)))
        semantic_category = sem_cat

        # Ensemble per spec (with semantic) — allow dynamic weights
        try:
            w = {"regex": 0.4, "token": 0.2, "ml": 0.25, "semantic": 0.15}
            if cfg and isinstance(cfg.get("model_metadata"), dict):
                ew = (cfg["model_metadata"].get("ensemble_weights") or {})
                w.update({
                    "regex": float(ew.get("regex", w["regex"])),
                    "token": float(ew.get("token", w["token"])),
                    "ml": float(ew.get("ml", w["ml"])),
                    "semantic": float(ew.get("semantic", w["semantic"]))
                })
            s = w["regex"] * float(regex_score) + w["token"] * float(token_score) + w["ml"] * float(ml_conf) + w["semantic"] * float(semantic_conf)
            final_conf = float(max(0.0, min(1.0, s)))
        except Exception:
            final_conf = 0.4 * regex_score + 0.2 * token_score + 0.25 * ml_conf + 0.15 * semantic_conf

        # Bundle detection to derive related columns and boost
        related: List[str] = []
        bundle_boost = False
        try:
            if bundles:
                for b in bundles:
                    toks = [str(x).upper() for x in (b.get("columns") or [])]
                    if not toks:
                        continue
                    # if this column matches any bundle token
                    if any(t in up for t in toks):
                        present = [c for c in cols_upper if any(t in c for t in toks)]
                        related = [rc for rc in present if rc != up]
                        if related:
                            bundle_boost = True
                            try:
                                final_conf = min(1.0, final_conf + float(b.get("boost", 0.05)))
                            except Exception:
                                final_conf = min(1.0, final_conf + 0.05)
                            break
        except Exception:
            pass

        # Determine dominant category by summing per-category evidence
        def _dominant_from(regex_hits: List[str], token_hits_list: List[Dict[str, Any]], sem_cat: Optional[str], regex_sc: float, token_sc: float, sem_sc: float) -> Optional[str]:
            from collections import defaultdict
            scores = defaultdict(float)
            # Token evidence: sum raw weights per category; optional bonus for exact matches on small-signal columns
            for h in (token_hits_list or []):
                c = str(h.get("category") or "").strip()
                w = float(h.get("weight", 0.0))
                if not c:
                    continue
                if str(h.get("match_type") or "") == "exact":
                    w = min(1.0, w + 0.1)
                scores[c] += w
            # Normalize token contribution to token_sc
            total_token_raw = sum(max(0.0, float(h.get("weight", 0.0))) for h in (token_hits_list or [])) or 1.0
            if scores and total_token_raw > 0:
                scale = float(token_sc) / float(total_token_raw)
                for k in list(scores.keys()):
                    scores[k] *= scale
            # Regex evidence: add regex_sc to each category present in regex_hits
            for c in (regex_hits or []):
                try:
                    scores[str(c)] += float(regex_sc)
                except Exception:
                    continue
            # Semantic evidence
            if sem_cat:
                scores[str(sem_cat)] += float(sem_sc)
            if not scores:
                return None
            # Apply governance priority if present to break ties
            prio = []
            try:
                if cfg and isinstance(cfg.get("model_metadata"), dict):
                    prio = list(cfg["model_metadata"].get("category_priority") or [])
            except Exception:
                prio = []
            best_cat, best_val = None, -1.0
            for cat, val in scores.items():
                if val > best_val:
                    best_cat, best_val = cat, val
                elif abs(val - best_val) < 1e-9 and prio:
                    # tie-break by priority order
                    try:
                        if prio.index(cat) < prio.index(best_cat):
                            best_cat = cat
                            best_val = val
                    except Exception:
                        pass
            return best_cat

        dominant = _dominant_from(regex_hits, token_hits, semantic_category, regex_score, token_score, semantic_conf)
        # If semantic strong and disagrees, prefer semantic
        if semantic_category and semantic_conf >= 0.80 and semantic_category != dominant:
            dominant = semantic_category
        cia = _cia_for(dominant)

        row_out = {
            "column": colname,
            "dominant_category": dominant,
            "confidence": int(round(max(0.0, min(1.0, final_conf)) * 100)),
            "suggested_cia": cia,
            "related_columns": related,
            "bundle_boost": bool(bundle_boost),
            "regex_hits": regex_hits,
            "token_hits": token_hits,
            "semantic_category": semantic_category,
            "semantic_confidence": int(round(semantic_conf * 100)),
        }

        # Optional persistence into SENSITIVE_AUDIT and CLASSIFICATION_AI_RESULTS
        try:
            if table_name and snowflake_connector is not None:
                schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
                if settings is not None:
                    db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                    if db:
                        schema_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE"
                snowflake_connector.execute_non_query(
                    f"""
                    create table if not exists {schema_fqn}.SENSITIVE_AUDIT (
                      audit_id number autoincrement,
                      table_name string,
                      column_name string,
                      category string,
                      confidence number,
                      cia string,
                      bundle_detected boolean,
                      scanned_at timestamp_ntz default current_timestamp(),
                      primary key (audit_id)
                    )
                    """
                )
                snowflake_connector.execute_non_query(
                    f"""
                    insert into {schema_fqn}.SENSITIVE_AUDIT (table_name, column_name, category, confidence, cia, bundle_detected)
                    values (%(t)s, %(c)s, %(cat)s, %(conf)s, %(cia)s, %(bb)s)
                    """,
                    {
                        "t": str(table_name),
                        "c": colname,
                        "cat": str(dominant or ""),
                        "conf": int(row_out["confidence"]),
                        "cia": f"{cia.get('C',0)}/{cia.get('I',0)}/{cia.get('A',0)}",
                        "bb": bool(bundle_boost),
                    },
                )
                # Persist raw AI outputs for analysis
                snowflake_connector.execute_non_query(
                    f"""
                    create table if not exists {schema_fqn}.CLASSIFICATION_AI_RESULTS (
                      result_id number autoincrement,
                      table_name string,
                      column_name string,
                      ai_category string,
                      regex_confidence float,
                      keyword_confidence float,
                      ml_confidence float,
                      semantic_confidence float,
                      final_confidence float,
                      semantic_category string,
                      model_version string,
                      details variant,
                      created_at timestamp_ntz default current_timestamp(),
                      primary key (result_id)
                    )
                    """
                )
                details = {
                    "regex_hits": regex_hits,
                    "token_hits": token_hits,
                }
                snowflake_connector.execute_non_query(
                    f"""
                    insert into {schema_fqn}.CLASSIFICATION_AI_RESULTS (
                      table_name, column_name, ai_category, regex_confidence, keyword_confidence, ml_confidence, semantic_confidence, final_confidence, semantic_category, model_version, details
                    ) values (%(t)s, %(c)s, %(ai)s, %(r)s, %(k)s, %(m)s, %(s)s, %(f)s, %(scat)s, %(ver)s, PARSE_JSON(%(det)s))
                    """,
                    {
                        "t": str(table_name),
                        "c": colname,
                        "ai": str(dominant or ""),
                        "r": float(regex_score * 100.0),
                        "k": float(token_score * 100.0),
                        "m": float(ml_conf * 100.0),
                        "s": float(semantic_conf * 100.0),
                        "f": float(max(0.0, min(1.0, final_conf)) * 100.0),
                        "scat": str(semantic_category or ""),
                        "ver": "v1.0",
                        "det": json.dumps(details).replace("'", "''"),
                    },
                )
        except Exception:
            pass

        out.append(row_out)

    return out


def _dynamic_keywords_lookup(cfg: Optional[Dict[str, Any]]) -> Dict[str, List[Tuple[str, str, float]]]:
    """
    Returns: {category: [(keyword, match_type, weight), ...]}
    """
    out: Dict[str, List[Tuple[str, str, float]]] = {}
    if not cfg:
        return out
    kws = cfg.get("keywords") or {}
    if isinstance(kws, dict):
        for cat, items in (kws or {}).items():
            for it in items or []:
                try:
                    if not it.get("active", True):
                        continue
                    kw = str(it.get("keyword") or it.get("token") or "").strip()
                    if not kw:
                        continue
                    mt = str(it.get("match_type") or "fuzzy").lower()
                    wt = float(it.get("weight", 0.5))
                    out.setdefault(cat, []).append((kw, mt, wt))
                except Exception:
                    continue
    elif isinstance(kws, list):
        for it in kws:
            try:
                cat = str(it.get("category") or "").strip()
                kw = str(it.get("keyword") or it.get("token") or "").strip()
                if not cat or not kw:
                    continue
                mt = str(it.get("match_type") or "fuzzy").lower()
                wt = float(it.get("weight", 0.5))
                out.setdefault(cat, []).append((kw, mt, wt))
            except Exception:
                continue
    return out


def regex_screen(series: pd.Series, max_rows: int = 200, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Compute regex match probabilities for the given series.

    Returns a dict of pattern -> probability (0..1), adjusted by consistency.
    """
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


def classify_table_sensitivity(table_name: str, df: pd.DataFrame,
                               column_meta: Optional[List[Dict[str, Any]]] = None,
                               probability_threshold: float = 0.5) -> Dict[str, Any]:
    """
    Full pipeline per table.

    Output structure:
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
          "justification": str
        }
      ]
    }
    """
    if df is None or df.empty:
        return {"table": table_name, "schema": None, "sensitive": False, "score": 0.0, "columns": []}

    # Load dynamic configuration once per call
    cfg: Optional[Dict[str, Any]] = None
    try:
        if _load_dynamic_config is not None:
            cfg = _load_dynamic_config()
    except Exception:
        cfg = None

    features = analyze_metadata(table_name, df, column_meta, cfg=cfg)
    # Name hints used for both ML and dominant type
    name_hints: Dict[str, List[str]] = {c: list(_cached_name_hints(table_name, c)) for c in df.columns}
    # Merge in dynamic keyword categories (if any)
    try:
        if cfg:
            for c in df.columns:
                dyn_h = _name_hint_categories(c, cfg=cfg)
                if dyn_h:
                    base = set(name_hints.get(c, []))
                    name_hints[c] = list(sorted(base.union(set(dyn_h))))
    except Exception:
        pass

    probs = ml_predict(features, name_hints)

    # --- Composite multi-column analysis ---
    def _analyze_composites(df_in: pd.DataFrame, feats: Dict[str, Dict[str, Any]], hints: Dict[str, List[str]]):
        comps: List[Dict[str, Any]] = []
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
                        else:
                            present = []
                            break
                    if present:
                        boost = float(b.get("boost", 0.1))
                        comps.append({
                            "type": str(b.get("name") or "bundle"),
                            "columns": sorted(list(set(present))),
                            "risk": float(min(1.0, max(0.0, boost))),
                        })
        except Exception:
            pass
        return comps

    composites = _analyze_composites(df, features, name_hints)

    # Build column outputs
    columns_out: List[Dict[str, Any]] = []
    for c in df.columns:
        f = features.get(c, {})
        rx_probs = {k.replace("rx_", ""): float(v) for k, v in f.items() if k.startswith("rx_")}
        dom = _dominant_type(name_hints.get(c) or [], rx_probs)
        # Ensemble: combine regex and ML using weighted average, retain recall by upper-bounding with max
        rx_max = max(rx_probs.values()) if rx_probs else 0.0
        p_ml = float(probs.get(c, 0.0))
        p = float(min(1.0, 0.4 * rx_max + 0.6 * p_ml))
        p = float(max(p, rx_max, p_ml))
        # Composite boost: if column participates in a high-risk composite, lift probability
        comp_hits = [comp for comp in composites if c in comp.get("columns", [])]
        if comp_hits:
            boost = max((ch.get("risk", 0.0) for ch in comp_hits), default=0.0)
            p = float(min(1.0, max(p, 0.6*boost + 0.4*p)))
        cia = assign_cia(dom or ("PII" if p >= 0.5 else "Public"), p, cfg=cfg)
        justification_parts: List[str] = []
        if name_hints.get(c):
            justification_parts.append(f"name_hints={name_hints[c]}")
        top_rx = sorted(rx_probs.items(), key=lambda kv: kv[1], reverse=True)[:3]
        if top_rx:
            justification_parts.append(f"regex_top={[(k, round(v,3)) for k,v in top_rx]}")
        justification_parts.append(f"stats={{'uniq_ratio': {round(f.get('unique_ratio', 0.0),3)}, 'avg_len': {round(f.get('avg_len', 0.0),2)}}}")
        if comp_hits:
            justification_parts.append(f"composites={[ch.get('type') for ch in comp_hits]}")
        columns_out.append({
            "column": c,
            "sensitive": bool(p >= probability_threshold),
            "probability": round(p, 3),
            "suggested_cia": cia,
            "dominant_type": dom,
            "justification": "; ".join(justification_parts),
            "composite_hits": [ch.get("type") for ch in comp_hits],
            "related_columns": [],
        })

    # Optional: embeddings-based related column grouping and boost
    try:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            import numpy as _np  # type: ignore
            _emb_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        except Exception:
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
            for i in range(n):
                if i in used:
                    continue
                grp = [i]
                used.add(i)
                for j in range(i+1, n):
                    if j in used:
                        continue
                    sim = float(_np.dot(vecs[i], vecs[j]))
                    if sim >= 0.80:
                        grp.append(j)
                        used.add(j)
                if len(grp) >= 2:
                    groups.append(grp)
            # Apply boost and set related columns list
            for grp in groups:
                rel_names = [names[k] for k in grp]
                for idx in grp:
                    row = columns_out[idx]
                    row["related_columns"] = [n for n in rel_names if n != row["column"]]
                    # boost probability slightly for grouped sensitive columns
                    base_p = float(row.get("probability", 0.0))
                    if base_p < 0.85:
                        row["probability"] = round(float(min(1.0, 0.15 + 0.85 * base_p)), 3)
                    # refresh sensitive flag and CIA if needed
                    row["sensitive"] = bool(row["probability"] >= probability_threshold)
                    row["suggested_cia"] = assign_cia(row.get("dominant_type") or ("PII" if row["sensitive"] else "Public"), row["probability"])  # type: ignore
    except Exception:
        pass

    table_agg = aggregate_table_sensitivity(table_name, {r["column"]: r["probability"] for r in columns_out})
    out = {
        "table": table_name,
        "schema": None,
        "sensitive": bool(table_agg["sensitive"]),
        "score": float(table_agg["score"]),
        "columns": columns_out,
        "composites": composites,
        "config_version": (cfg.get("version") if cfg else None),
    }
    return out


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
    """Core sensitive data detection engine"""
    
    def __init__(self):
        self.patterns = {}
        self.keywords = {}
        self.weights = {}
        
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
