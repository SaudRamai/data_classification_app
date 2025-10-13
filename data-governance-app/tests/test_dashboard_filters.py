import os
import importlib.util
import pytest
import streamlit as st

# Dynamically load the dashboard module (filename starts with a digit)
_here = os.path.abspath(__file__)
_proj_root = os.path.dirname(os.path.dirname(os.path.dirname(_here)))
dash_path = os.path.join(_proj_root, 'src', 'pages', '1_Dashboard.py')
spec = importlib.util.spec_from_file_location('dash_mod', dash_path)
dash = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(dash)  # type: ignore


def test_apply_compliance_filter_builds_exists_clause(monkeypatch):
    # Setup session filters
    st.session_state["rt_framework"] = "SOX"
    st.session_state["rt_cstatus"] = "COMPLIANT"

    base_where = "WHERE 1=1"
    params = {"x": 1}
    where, out = dash._rt_apply_compliance_filter(base_where, params, "a.ASSET_ID", "DB.SCH.COMPLIANCE_MAPPING")

    assert "EXISTS (select 1 from DB.SCH.COMPLIANCE_MAPPING" in where
    assert "cm.ASSET_ID = a.ASSET_ID" in where
    assert out.get("fw_up") == "SOX"
    assert out.get("cstat") == "COMPLIANT"


def test_build_filters_for_respects_selected_fields(monkeypatch):
    # Fake columns for the table by monkeypatching _rt_get_table_columns
    monkeypatch.setattr(dash, "_rt_get_table_columns", lambda _: {"BUSINESS_UNIT","DATABASE_NAME","SCHEMA_NAME","TABLE_TYPE","CLASSIFICATION_TAG","RISK_LEVEL"})

    where, params = dash._rt_build_filters_for(
        sel_bu="Finance",
        sel_db="TEST_DB",
        sel_schema="PUBLIC",
        sel_asset_type="BASE TABLE",
        sel_class_status="Unclassified",
        sel_risk="High",
        start_date=None,
        end_date=None,
        table_fqn="TEST_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS",
        time_candidates=None,
    )
    assert "BUSINESS_UNIT = %(bu)s" in where
    assert "DATABASE_NAME = %(db)s" in where
    assert "SCHEMA_NAME = %(schema)s" in where
    assert "TABLE_TYPE = %(atype)s" in where
    assert "coalesce(CLASSIFICATION_TAG,'' )".replace(" ","")[:20] in where.replace(" ","")  # status condition present
    assert "RISK_LEVEL = %(risk)s" in where
    assert params["bu"] == "Finance"
    assert params["db"] == "TEST_DB"
    assert params["schema"] == "PUBLIC"
    assert params["atype"] == "BASE TABLE"
    assert params["risk"] == "High"
