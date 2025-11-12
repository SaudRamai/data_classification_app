# Compliance Page Documentation

This document explains the structure, functions, UI components, data flow, and external dependencies used in the compliance page implemented in `src/pages/4_Compliance.py`.


## Overview
- **Purpose**: Provide policy compliance monitoring, exception/workflow management, review scheduling, and audit evidence generation.
- **Primary technologies**: Streamlit (UI), Plotly (charts), Snowflake (data), internal services (compliance, exceptions, authorization).
- **Routing**: If `src/pages/_compliance_center.py:render` exists, the page delegates to it and stops early. Otherwise, the legacy compliance UI in this file renders.


## Dependencies and Imports
- **Frameworks**: `streamlit as st`, `plotly.express as px`, `pandas as pd`.
- **Theme**: `src/ui/theme.apply_global_theme()` applies a centralized UI theme and Plotly template.
- **Snowflake**: `src/connectors/snowflake_connector.snowflake_connector` executes SQL queries.
- **Settings**: `src/config/settings.settings` for defaults (e.g., database).
- **Services**:
  - `src/services/authorization_service.authz`: RBAC/identity checks.
  - `src/services/compliance_service.compliance_service`: health check, detection, scheduling, violations.
  - `src/services/exception_service.exception_service`: exception CRUD and lifecycle.
  - Other imported services are not heavily used on this page.
- **UI components**: `src/components/filters.render_data_filters()` provides sidebar dataset filters. `render_compliance_facets()` is imported but not used here.


## Page Initialization
- `st.set_page_config(page_title, page_icon, layout)`.
- `apply_global_theme()`.
- `st.title("Data Classification")` (note: title wording may be better as "Compliance").
- `render_quick_links()` for consistent navigation.
- Attempt to call `render_compliance_center()` and `st.stop()` on success.


## RBAC Guard
```python
_ident = authz.get_current_identity()
if not authz.is_consumer(_ident):
    # Warn/stop depending on session context
```
- Requires at least consumer-level access. If unauthorized, the page shows a warning/error and stops to maintain security.


## Session Context and Helpers
- `
_resolve_db() -> str | None
`:
  - Resolves the active database from `st.session_state['sf_database']`, settings, or `SELECT CURRENT_DATABASE()`.
- `
_ensure_session_database() -> str | None
`:
  - Ensures a valid database is selected; if none, chooses the first from `SHOW DATABASES` and runs `USE DATABASE`.
- `
_list_warehouses() -> list[str]
` (cached):
  - Returns accessible warehouses via `SHOW WAREHOUSES`.
- `
_apply_warehouse(wh: str | None)
`:
  - Resumes and uses the selected warehouse; stores it in session.
- `
_list_databases() -> list[str]
` (cached):
  - Returns accessible databases via `SHOW DATABASES`.
- `
_apply_database(db: str | None)
`:
  - Runs `USE DATABASE <db>` if not "All" and persists choice in session; else clears selection.
- Object existence checks:
  - `
_view_exists(db, schema, view) -> bool
` via `INFORMATION_SCHEMA.VIEWS`.
  - `
_table_exists(db, schema, table) -> bool
` via `INFORMATION_SCHEMA.TABLES`.


## Sidebar Components
- **Session** expander:
  - Warehouse select → `_apply_warehouse(wh)`.
  - Database select (with "All") → `_apply_database(sel_db)`.
- **Filters** expander:
  - `render_data_filters(key_prefix="comp_filters")` returns a dict of dataset filters (e.g., database, schema, table) stored as `sel`.


## Caching and Refresh
- Most data loaders are decorated with `@st.cache_data(ttl=300)` (5 minutes).
- **Refresh controls**:
  - "🔄 Refresh now" → `st.cache_data.clear(); st.rerun()`.
  - "🔄 Refresh Coverage & Metrics" → clear and rerun similarly.


## Data Fetching Functions
- `
get_compliance_data() -> dict
` (cached): Aggregates:
  - Users, roles, grants from `SNOWFLAKE.ACCOUNT_USAGE`.
  - Masking and row access policies counts.
  - Top 10 `TAG_REFERENCES` by usage.
- `
_get_latest_report() -> dict
` (cached): Reads most recent record from `{db}.DATA_GOVERNANCE.COMPLIANCE_REPORTS` if the table/view exists.
- `
_compute_overall_score(metrics, pending_exceptions) -> (score, expl)
`:
  - Score in [0–100] with weights:
    - 60% coverage (`metrics.coverage_rate`).
    - 25% health = `1 - violation_rate`, where `violation_rate` derives from `risk_counts` and asset totals.
    - 15% exceptions = `1 - pending_exceptions_per_asset`.
  - Returns score and a human-readable explainer.


## Main Tabs
Tabs are created as:
```python
tab_dash, tab_reviews, tab_viol = st.tabs([
  "📊 Compliance Dashboard", "🔄 Review Management", "🚨 Policy Violations"
])
```

### 1) 📊 Compliance Dashboard
- **Overall KPI**:
  - Uses `_get_latest_report()` and `exception_service.list(status="Pending")` to compute score via `_compute_overall_score`.
  - Displays: `st.metric("Overall Compliance Score", "<score>%")`.
- **Sub-tabs**:
  1. **Policy Compliance Metrics**
     - Classification Coverage: Uses `metrics.coverage_rate` if present; else computes from `{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS` using `CLASSIFICATION_TAG`.
     - Timeliness (Past Due ≥5d): Assets where `LAST_CLASSIFIED_DATE` is older than 5 days.
     - Accuracy vs Expected: Reads from `metrics.accuracy_score` or `metrics.accuracy` if available.
     - Open Exceptions: `exception_service.list(status="Pending")` count.
     - Optional: Top Tag Usage chart from `get_compliance_data()['tag_usage']`.
  2. **Classification Coverage Reports**
     - Latest by Framework: `{db}.DATA_GOVERNANCE.COMPLIANCE_COVERAGE`, iterates rows and prints totals.
     - By Business Unit: Aggregates from `ASSETS` to coverage percentage. Shows Plotly bar + table.
     - By Data Type: Similar aggregation by `TABLE_TYPE/ASSET_TYPE`.
     - Trend Over Time: Coverage rate per day from `COMPLIANCE_REPORTS` to a time series line chart.
  3. **Exception Tracking**
     - List exceptions by selectable status and limit via `exception_service.list()`.
     - Actions on selected exception: Approve, Reject (with justification), Attach Evidence URL.
  4. **Audit Ready Reports**
     - Lists recent `{db}.DATA_GOVERNANCE.COMPLIANCE_REPORTS` and provides CSV download.
     - Mentions possible PDF integration.

### 2) 🔄 Review Management
- **Schedule Reviews**
  - Inputs: Asset fully qualified name, Frequency, Owner email.
  - Schedules via `compliance_service.schedule_review(asset_full, frequency, owner)`.
- **Upcoming Reviews**
  - Reads `{db}.DATA_GOVERNANCE.REVIEW_SCHEDULES` if present.
- **Overdue Tasks**
  - Past Due Classifications: Same ≥5d rule.
  - Missed Reviews: `NEXT_RUN < current_date()` from `REVIEW_SCHEDULES`.
  - Escalation Notifications: Informational placeholder.
- **Review History**
  - `{db}.DATA_GOVERNANCE.REVIEW_HISTORY` if present. Shows latest up to 300 entries.

### 3) 🚨 Policy Violations
- **Controls**
  - Run Violation Detection: `compliance_service.detect_violations()`; role-gated to Admin/Compliance Officer.
  - Expire Past-Due Exceptions: `exception_service.expire_auto()`; role-gated similarly.
- **Open Violations**
  - `compliance_service.list_open_violations(limit=500)` with drill-down.
  - Shows violation details (JSON) and allows recording a corrective action (best-effort API call, with local capture fallback).
- **Compliance Matrix & Evidence Packs**
  - Violations: `{db}.DATA_GOVERNANCE.VIOLATIONS`.
  - Inventory join: `{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS` (FULLY_QUALIFIED_NAME, BU/Schema, classification level, CIA triad fields) – optional.
  - Applies dataset filters from `sel` (database/schema/table). Note: code references an undefined `facets` object for severity/time filtering.
  - Displays a pivot matrix: `RULE_CODE` x `BU_OR_SCHEMA` with counts.
  - Drill down by rule and BU/Schema and export an Evidence Pack ZIP containing:
    - `violations.csv` (subset)
    - `summary.json`
    - `policy_snapshot.json` (masking policy count, best-effort)
    - `audit_digest.json` (best-effort via audit service)
    - `SIGNATURES.txt` with SHA-256 hashes for integrity


## Error Handling and Resilience
- Existence checks on tables/views before querying to avoid run-time errors.
- Broad `try/except` usage showing `st.info`/`st.warning` and continuing with partial features.
- Compliance service availability (`comp_ok`) gates detection and violation listing to prevent broken UX.
- RBAC guard prevents unauthorized access to sensitive capabilities.


## Known Gaps and Recommendations
- **Undefined `facets` variable**: In the "Compliance Matrix & Evidence Packs" section, `facets` is used for severity/time filtering but is never defined. Options:
  - Use `render_compliance_facets()` and capture its return as `facets`.
  - Or integrate those facet controls into `render_data_filters(...)` and reference from `sel`.
- **Title wording**: `st.title("Data Classification")` on a compliance page might be confusing. Consider `st.title("Compliance")`.
- **Service fallbacks**: Several features depend on `compliance_service`/`exception_service`. Ensure backends and Snowflake tasks are deployed for full functionality.


## Data Flow Diagram
```mermaid
flowchart TD
    A[Sidebar: Warehouse/Database] -->|_apply_*| B[Session State]
    A --> C[render_data_filters -> sel]

    subgraph Snowflake
      D1[ACCOUNT_USAGE.*]
      D2[INFORMATION_SCHEMA.*]
      D3[{db}.DATA_GOVERNANCE.*]
      D4[{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS]
    end

    E[get_compliance_data] --> D1
    F[_get_latest_report] --> D3
    G[Coverage Queries] --> D4

    H[Compliance Service] -->|violations, detect, schedule| UI
    I[Exception Service] -->|list, approve, reject, expire| UI

    UI[Compliance Page Tabs]
    B --> UI
    C --> UI
    E --> UI
    F --> UI
    G --> UI
    H --> UI
    I --> UI
```


## KPI Definitions
- **Overall Compliance Score**: Weighted metric combining coverage, health (inverse of violation rate), and exception backlog per asset.
- **Classification Coverage**: Percentage of assets with a non-empty `CLASSIFICATION_TAG`.
- **Past Due (≥5d)**: Assets whose `LAST_CLASSIFIED_DATE` (or `CREATED_DATE`) is older than 5 days.
- **Open Exceptions**: Count of exceptions with `status = 'Pending'`.


## SQL Touchpoints (Representative)
- Users: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL`.
- Roles: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE DELETED_ON IS NULL`.
- Grants: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE DELETED_ON IS NULL`.
- Policies: counts from `ACCOUNT_USAGE.MASKING_POLICIES`, `ACCOUNT_USAGE.ROW_ACCESS_POLICIES`.
- Coverage: aggregation over `{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS` on `CLASSIFICATION_TAG`.
- Reports/Coverage snapshots/Violations/Reviews history/schedules from `{db}.DATA_GOVERNANCE.*` when present.


## File References
- Page: `src/pages/4_Compliance.py`
- Optional Center: `src/pages/_compliance_center.py`
- Theme: `src/ui/theme.py`
- Quick Links: `src/ui/quick_links.py`
- Filters: `src/components/filters.py`
- Services: `src/services/authorization_service.py`, `src/services/compliance_service.py`, `src/services/exception_service.py`, `src/services/audit_service.py`


## Version
- Generated: 2025-10-08
