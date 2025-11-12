import types
import builtins
import datetime as dt

import pytest

from src.services.metrics_service import MetricsService


class FakeConnector:
    def __init__(self, tables_exist=True):
        self.tables_exist = tables_exist

    def execute_query(self, sql: str, params=None):
        sql_up = (sql or "").upper()
        # INFORMATION_SCHEMA.TABLES presence checks
        if "INFORMATION_SCHEMA.TABLES" in sql_up:
            return [{"X": 1}] if self.tables_exist else []
        # Coverage total count from ASSETS
        if "FROM" in sql_up and "ASSETS" in sql_up and "COUNT(*)" in sql_up and "TAG_REFERENCES" not in sql_up:
            return [{"C": 10}]  # 10 assets in inventory
        # Coverage tagged count join TAG_REFERENCES
        if "TAG_REFERENCES" in sql_up and "ASSETS" in sql_up:
            return [{"C": 7}]  # 7 have any classification tags
        # COMPLIANCE_MAPPING canonical counts
        if "FROM" in sql_up and "COMPLIANCE_MAPPING" in sql_up and "GROUP BY" in sql_up and "FRAMEWORK_NAME" in sql_up:
            return [
                {"FW": "SOX", "CNT": 5},
                {"FW": "SOC 2", "CNT": 3},
                {"FW": "GDPR", "CNT": 4},
            ]
        # CLASSIFICATION_DECISIONS timeseries
        if "FROM" in sql_up and "CLASSIFICATION_DECISIONS" in sql_up:
            today = dt.date.today()
            return [
                {"DAY": today - dt.timedelta(days=2), "DECISIONS": 2},
                {"DAY": today - dt.timedelta(days=1), "DECISIONS": 3},
            ]
        # Overdue unclassified
        if "FROM" in sql_up and "ASSETS" in sql_up and "CLASSIFICATION_LABEL" in sql_up and "CREATED_TIMESTAMP" in sql_up:
            return [{"C": 2}]
        return []

    def execute_non_query(self, sql: str, params=None):
        return None


def test_classification_coverage_uses_inventory_and_tags(monkeypatch):
    svc = MetricsService()
    fake = FakeConnector(tables_exist=True)
    svc.connector = fake
    # also force _has_table True regardless of FQN
    monkeypatch.setattr(svc, "_has_table", lambda fqn: True)

    res = svc.classification_coverage(database="TEST_DB")
    assert res["total_assets"] == 10
    assert res["tagged_assets"] == 7
    assert res["coverage_pct"] == pytest.approx(70.0)


def test_framework_counts_prefers_compliance_mapping(monkeypatch):
    svc = MetricsService()
    fake = FakeConnector(tables_exist=True)
    svc.connector = fake
    monkeypatch.setattr(svc, "_has_table", lambda fqn: True)

    counts = svc.framework_counts(database="TEST_DB")
    assert counts["SOX"] == 5
    assert counts["SOC"] == 3
    assert counts["GDPR"] == 4
    # HIPAA/PCI not present in fake data -> 0
    assert counts["HIPAA"] == 0
    assert counts["PCI"] == 0


def test_historical_classifications_series(monkeypatch):
    svc = MetricsService()
    fake = FakeConnector(tables_exist=True)
    svc.connector = fake
    monkeypatch.setattr(svc, "_has_table", lambda fqn: True)

    rows = svc.historical_classifications(database="TEST_DB", days=7)
    assert isinstance(rows, list)
    assert len(rows) == 2
    assert set(rows[0].keys()) == {"DAY", "DECISIONS"}


def test_overdue_unclassified_count(monkeypatch):
    svc = MetricsService()
    fake = FakeConnector(tables_exist=True)
    svc.connector = fake
    monkeypatch.setattr(svc, "_has_table", lambda fqn: True)

    cnt = svc.overdue_unclassified(database="TEST_DB")
    assert cnt == 2
