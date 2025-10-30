from typing import List, Dict, Any, Optional
import pandas as pd
import streamlit as st

from src.services.ai_classification_service import AIClassificationService
try:
    from src.services.governance_db_resolver import resolve_governance_db  # type: ignore
except Exception:
    resolve_governance_db = None  # type: ignore
try:
    from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
except Exception:
    snowflake_connector = None  # type: ignore


def _format_cia(cia: Optional[str]) -> str:
    return str(cia or "C1")


def _confidence_bar(val: int) -> str:
    v = max(0, min(100, int(val)))
    filled = int(v / 5)
    return "█" * filled + "░" * (20 - filled) + f" {v}%"


def _categories_badge(cats: List[str]) -> str:
    return ", ".join(sorted(set([str(c) for c in (cats or [])])))


def render_table_report(table_name: str, sample_size: int = 200) -> None:
    st.subheader("AI Assist: Table Sensitivity Report")
    st.caption(table_name)

    svc = AIClassificationService()

    # Prefer persisted audit if available, else live compute
    audit_row: Optional[Dict[str, Any]] = None
    try:
        if snowflake_connector is not None:
            db = None
            try:
                db = resolve_governance_db() if resolve_governance_db else None
            except Exception:
                db = None
            rows = snowflake_connector.execute_query(
                (
                    f"select sa.full_name, sa.table_sensitivity_score, sa.dominant_category, sa.sensitive_columns_count, sa.table_cia_minimum, sa.details "
                    f"from {(db + '.DATA_CLASSIFICATION_GOVERNANCE') if db else 'DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE'}.SENSITIVE_AUDIT sa "
                    f"where sa.full_name = %(f)s order by sa.CREATED_AT desc limit 1"
                ),
                {"f": table_name},
            ) or []
            audit_row = rows[0] if rows else None
    except Exception:
        audit_row = None

    table_result = svc.classify_table(table_name) if not audit_row else (audit_row.get("DETAILS") or {})
    audit_evidence = None  # evidence column may not exist in older deployments
    if isinstance(table_result, str):
        try:
            import json
            table_result = json.loads(table_result)
        except Exception:
            table_result = {}
    col_rows = svc.detect_sensitive_columns(table_name, sample_size=sample_size) or []

    feats = (table_result or {}).get("features", {})
    tbl_score = feats.get("table_sensitivity_score")
    tbl_dom = feats.get("dominant_table_category")
    sens_cols = feats.get("sensitive_columns_count")
    cia_min = feats.get("table_cia_minimum")

    # Minimal table-level grid
    table_df = pd.DataFrame([
        {
            "table_name": table_name,
            "table_sensitivity_score": tbl_score,
            "dominant_category": tbl_dom,
            "sensitive_columns_count": sens_cols,
            "table_cia_minimum": _format_cia(cia_min),
        }
    ])
    st.markdown("### Table Summary")
    st.dataframe(table_df, width='stretch', hide_index=True)

    # Minimal column-level grid
    st.markdown("### Columns")
    if not col_rows:
        st.info("No columns detected.")
        return
    cols_df = pd.DataFrame([
        {
            "Column": r.get("column"),
            "Categories": _categories_badge(r.get("categories", [])),
            "Dominant": r.get("dominant_category"),
            "Confidence": r.get("confidence"),
            "CIA": _format_cia((r.get("suggested_cia") or {}).get("confidentiality")) if isinstance(r.get("suggested_cia"), dict) else "C1",
            "BundleBoost": bool(r.get("bundle_boost", False)),
        }
        for r in col_rows
    ])
    st.dataframe(cols_df, width='stretch', hide_index=True)

    # Per-column "Why?" buttons with evidence modal
    try:
        st.markdown("#### Explain: Column Evidence")
        # Prepare a lookup from column name to evidence dict
        import json as _json
        col_evidence_map: Dict[str, Dict[str, Any]] = {}
        for r in (col_rows or []):
            try:
                col_name = r.get("column")
                if not col_name:
                    continue
                evidence = {
                    "regex_matches": r.get("regex_hits"),
                    "token_hits": r.get("token_hits"),
                    "ml_score": r.get("ml_score"),
                    "bundle_boosts": {
                        "bundles_detected": r.get("bundles_detected"),
                        "bundle_boost": r.get("bundle_boost"),
                    },
                    "negative_caps": r.get("negative_caps"),
                    "confidence_formula": r.get("confidence_breakdown") or {
                        "final_confidence": r.get("confidence"),
                    },
                    "dominant_category": r.get("dominant_category"),
                    "categories": r.get("categories"),
                }
                col_evidence_map[str(col_name)] = evidence
            except Exception:
                continue

        # Render a compact list of buttons
        for r in (col_rows or []):
            cname = str(r.get("column"))
            cols = st.columns([3, 2, 2, 1])
            with cols[0]:
                st.caption(cname)
            with cols[1]:
                st.caption(str(r.get("dominant_category")))
            with cols[2]:
                st.caption(str(r.get("confidence")))
            with cols[3]:
                if st.button("Why?", key=f"why_btn_{cname}"):
                    st.session_state["_why_title"] = f"Why is '{cname}' flagged?"
                    st.session_state["_why_json"] = _json.dumps(col_evidence_map.get(cname, {}), indent=2, default=str)
                    st.session_state["_why_open"] = True

        # Modal rendering: use st.dialog if available; else fallback to expander
        _has_dialog = hasattr(st, "dialog")

        def _render_evidence(json_text: str):
            try:
                st.json(_json.loads(json_text))
            except Exception:
                st.code(json_text, language="json")
            # Copy-to-clipboard via HTML component (works even if no native API)
            try:
                import streamlit.components.v1 as components
                components.html(
                    f"""
                    <div style='margin:6px 0;'>
                      <button onclick="navigator.clipboard.writeText(document.getElementById('evtxt').innerText);">Copy JSON to clipboard</button>
                    </div>
                    <pre id='evtxt' style='max-height:300px;overflow:auto;border:1px solid #ccc;padding:8px;background:#fafafa;'>{_json.dumps(_json.loads(json_text), indent=2)}</pre>
                    """,
                    height=360,
                )
            except Exception:
                st.code(json_text, language="json")

        if st.session_state.get("_why_open") and st.session_state.get("_why_json"):
            title = st.session_state.get("_why_title") or "Why?"
            if _has_dialog:
                @st.dialog(title)
                def _why_modal():
                    _render_evidence(st.session_state.get("_why_json", "{}"))
                    if st.button("Close"):
                        st.session_state["_why_open"] = False
                _why_modal()
            else:
                with st.expander(title, expanded=True):
                    _render_evidence(st.session_state.get("_why_json", "{}"))
                    if st.button("Close"):
                        st.session_state["_why_open"] = False
    except Exception:
        pass

    # Explainability panel
    try:
        with st.expander("View detection details"):
            details: List[Dict[str, Any]] = []
            for r in (col_rows or []):
                try:
                    cia = r.get("suggested_cia") or {}
                    details.append({
                        "Column": r.get("column"),
                        "Dominant": r.get("dominant_category"),
                        "FinalConfidence": r.get("confidence"),
                        "RegexHits": r.get("regex_hits"),
                        "PatternIDs": ", ".join([str(x) for x in (r.get("pattern_ids") or [])]),
                        "TokenHits": ", ".join([str(x) for x in (r.get("token_hits") or [])]),
                        "MLScore": r.get("ml_score"),
                        "Bundles": ", ".join([str(x) for x in (r.get("bundles_detected") or [])]),
                        "NegativeCaps": ", ".join([str(x) for x in (r.get("negative_caps") or [])]),
                        "LuhnMatch": bool(r.get("luhn_match")),
                        "BundleBoost": bool(r.get("bundle_boost")),
                        "CIA": f"C{cia.get('C', cia.get('confidentiality', ''))}/I{cia.get('I', cia.get('integrity',''))}/A{cia.get('A', cia.get('availability',''))}",
                    })
                except Exception:
                    continue
            if details:
                st.dataframe(pd.DataFrame(details), width='stretch', hide_index=True)
            else:
                st.caption("No detection details available.")

            # If audit evidence exists, render below live details
            if audit_evidence:
                try:
                    ev = audit_evidence
                    if isinstance(ev, str):
                        import json as _json
                        ev = _json.loads(ev)
                    if isinstance(ev, list) and ev:
                        st.markdown("##### Persisted Evidence (latest audit)")
                        st.dataframe(pd.DataFrame(ev), width='stretch', hide_index=True)
                except Exception:
                    pass
    except Exception:
        pass

    # Sampling details panel
    try:
        with st.expander("View sampling details"):
            meta_rows: List[Dict[str, Any]] = []
            try:
                if snowflake_connector is not None:
                    db = None
                    try:
                        db = resolve_governance_db() if resolve_governance_db else None
                    except Exception:
                        db = None
                    rows = snowflake_connector.execute_query(
                        (
                            f"select sm.TABLE_NAME, sm.SAMPLE_HASH, sm.SAMPLE_SIZE, sm.SAMPLING_METHOD, sm.CREATED_AT "
                            f"from {(db + '.DATA_CLASSIFICATION_GOVERNANCE') if db else 'DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE'}.SAMPLE_METADATA sm "
                            f"where upper(sm.TABLE_NAME) = upper(%(t)s) order by sm.CREATED_AT desc limit 1"
                        ),
                        {"t": table_name},
                    ) or []
                    meta_rows = rows
            except Exception:
                meta_rows = []
            if meta_rows:
                st.dataframe(pd.DataFrame(meta_rows), width='stretch', hide_index=True)
            else:
                st.caption("No sampling metadata available.")
    except Exception:
        pass


def render_table_selector_and_report(get_tables_fn, sample_size: int = 200):
    st.header("AI Assist")
    tables = get_tables_fn() or []
    if not tables:
        st.info("No tables available.")
        return
    table = st.selectbox("Select table", options=tables)
    if table:
        render_table_report(table, sample_size=sample_size)
