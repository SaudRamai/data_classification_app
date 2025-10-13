import os
import importlib.util
import pandas as pd
import pytest

# Dynamically load the Data Assets page module (filename starts with a digit)
_here = os.path.abspath(__file__)
_proj_root = os.path.dirname(os.path.dirname(os.path.dirname(_here)))
assets_path = os.path.join(_proj_root, 'src', 'pages', '2_Data_Assets.py')
spec = importlib.util.spec_from_file_location('assets_mod', assets_path)
assets_mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(assets_mod)  # type: ignore


def test_compute_policy_fields_adds_rationale_and_reclass(monkeypatch):
    # Stub Snowflake connector to avoid DB access during compute_policy_fields()
    monkeypatch.setattr(assets_mod, 'snowflake_connector', type('X', (), {
        'execute_query': staticmethod(lambda *a, **k: []),
        'execute_non_query': staticmethod(lambda *a, **k: None),
    }))

    # Minimal input DF with PII tag and Public classification (should trigger reclass per policy 5.5.1/6.3)
    df = pd.DataFrame([
        {
            'Name': 'customers',
            'Location': 'TEST_DB.PUBLIC.CUSTOMERS',
            'Classification': 'Public',
            'CIA Score': 'C1-I1-A1',
            'Owner': 'owner@example.com',
            'Tags': 'PII=true',
            'Type': 'TABLE',
            'Rows': '100',
            'Size (MB)': 1,
            'Last Updated': '2025-01-01',
        }
    ])

    out = assets_mod.compute_policy_fields(df)

    # Columns present
    assert 'Decision Rationale' in out.columns
    assert 'Decision Notes' in out.columns
    assert 'Reclass Needed' in out.columns
    assert 'Reclass Reason' in out.columns

    # Reclassification should be needed due to PII + Public label
    assert bool(out.loc[0, 'Reclass Needed']) is True
    assert isinstance(out.loc[0, 'Reclass Reason'], str)


def test_compute_column_flags_heuristics_and_tags():
    flags_name = assets_mod._compute_column_flags('email_address')
    assert 'PII' in flags_name

    flags_tags = assets_mod._compute_column_flags('col_x', {'MYDB.GOV.PCI_TAG'})
    assert 'Regulatory' in flags_tags or 'Financial' in flags_tags  # PCI is regulatory
