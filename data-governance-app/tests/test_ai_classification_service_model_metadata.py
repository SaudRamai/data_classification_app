import pandas as pd
import pytest

from src.services.ai_classification_service import AIClassificationService


def test_detect_sensitive_columns_uses_db_weights(monkeypatch):
    svc = AIClassificationService()
    # Avoid any external calls
    svc.use_snowflake = False

    # Column metadata: single column 'email'
    monkeypatch.setattr(svc, "get_column_metadata", lambda table_name: [
        {"COLUMN_NAME": "email", "DATA_TYPE": "STRING"}
    ])
    # Disable dynamic sampler
    monkeypatch.setattr(svc, "_dynamic_sample", lambda *args, **kwargs: None)
    # Provide empty sample data to eliminate regex/value evidence
    monkeypatch.setattr(svc, "get_sample_data", lambda *args, **kwargs: pd.DataFrame({"email": []}))

    # Configure sensitivity config to drive weights entirely from MODEL_METADATA
    def _fake_cfg():
        return {
            "patterns": [],  # no regex, so value evidence = 0
            "keywords": [  # name token should match column name 'EMAIL'
                {"category": "PII", "token": "email"}
            ],
            "bundles": [],
            "categories": {"PII": {"C": 3, "I": 2, "A": 2}},
            "internal_patterns": [],
            "model_metadata": {
                "weights": {"regex": 0.0, "token": 1.0, "ml": 0.0},
                "bundle_max_boost": 0.0,
                "generic_id_names_only_cap": 1.0,
                "require_multiple_evidence": False,
            },
        }

    monkeypatch.setattr(svc, "load_sensitivity_config", _fake_cfg)

    rows = svc.detect_sensitive_columns("DB.SCHEMA.TABLE", sample_size=50)
    assert rows, "Expected at least one detection row"
    r = rows[0]
    assert r["column"] == "email"
    assert r["dominant_category"] == "PII"
    # With token weight = 1.0 and a single name hit, confidence should be 100%
    assert r["confidence"] == 100
