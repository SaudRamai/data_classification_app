import json
import types

from src.services.ai_classification_service import AIClassificationService


def test_persist_sensitive_audit_includes_evidence(monkeypatch):
    svc = AIClassificationService()
    svc.use_snowflake = True

    calls = {"non_query": []}

    class FakeConnector:
        def execute_non_query(self, sql, params=None):
            calls["non_query"].append((sql, params))
            return None
        def execute_query(self, *args, **kwargs):
            return []

    # Monkeypatch module-level snowflake_connector used by service
    import src.services.ai_classification_service as mod
    monkeypatch.setattr(mod, "snowflake_connector", FakeConnector())

    # Build a result with column_detections carrying evidence fields
    result = {
        "features": {
            "table_sensitivity_score": 0.85,
            "dominant_table_category": "PII",
            "sensitive_columns_count": 2,
            "table_cia_minimum": "C2",
            "column_detections": [
                {
                    "column": "email",
                    "regex_hits": 3,
                    "pattern_ids": ["^.+@.+$"],
                    "token_hits": ["EMAIL"],
                    "ml_score": 0.6,
                    "bundles_detected": ["identity"],
                    "negative_caps": ["PRODUCT|ITEM"],
                    "luhn_match": False,
                }
            ],
        }
    }

    svc._persist_sensitive_audit("DB.SCHEMA.TBL", result)

    # Find the INSERT call and assert evidence param is present and JSON parseable
    insert_calls = [c for c in calls["non_query"] if "insert into data_governance.sensitive_audit" in c[0].lower()]
    assert insert_calls, "Expected an INSERT into sensitive_audit"
    sql, params = insert_calls[-1]
    assert params is not None and "e" in params, "Expected evidence JSON param 'e'"
    ev = json.loads(params["e"]) if isinstance(params["e"], str) else params["e"]
    assert isinstance(ev, list) and ev, "Evidence should be a non-empty list"
    assert ev[0].get("column") == "email"
    assert ev[0].get("regex_hits") == 3
    assert "^.+@.+$" in (ev[0].get("pattern_ids") or [])
