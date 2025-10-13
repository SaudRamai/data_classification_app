# Compliance Page – Full Detailed Documentation

File: `src/pages/4_Compliance.py`
Generated: 2025-10-08


## 1) Purpose & Scope
- **Purpose**: Provide end-to-end policy compliance monitoring, exception and approval management, review scheduling, violations drill-down, and audit evidence generation for governed data assets in Snowflake.
- **Audience**: Compliance officers, data governance leads, platform admins, auditors.


## 2) Page Lifecycle & Routing
- `st.set_page_config(...)`, `apply_global_theme()`, `render_quick_links()` set the look-and-feel.
- If `src/pages/_compliance_center.py:render` exists, the page calls it and `st.stop()` (centralized experience).
- RBAC guard ensures at least consumer-level access using `authz`.
- Session safety helpers ensure a valid Snowflake warehouse/database to avoid “NONE” errors.
- The page renders three tabs: Dashboard, Review Management, Policy Violations.


## 3) Permissions & RBAC
- `authz.get_current_identity()` + `authz.is_consumer(identity)` gate access.
- Elevated actions (in Violations tab) require role in `{Admin, Compliance Officer}`:
  - Run violation detection: `compliance_service.detect_violations()`.
  - Expire past-due exceptions: `exception_service.expire_auto()`.


## 4) Functions – Detailed Breakdown

### 4.1 `_resolve_db() -> str | None`
- Sources DB in priority order:
  1. `st.session_state['sf_database']`
  2. `settings.SNOWFLAKE_DATABASE`
  3. `SELECT CURRENT_DATABASE()` via `snowflake_connector`
- Returns `None` if nothing resolvable.

### 4.2 `_ensure_session_database() -> str | None`
- Calls `_resolve_db()`. If empty, runs `SHOW DATABASES`, picks the first, runs `USE DATABASE <name>`, persists to `st.session_state['sf_database']`.
- Returns resolved DB (best-effort).

### 4.3 `_list_warehouses() -> list[str]` (cached)
- `SHOW WAREHOUSES` → returns array of names. Swallows errors; returns `[]` if not accessible.

### 4.4 `_apply_warehouse(wh: str | None) -> None`
- Best-effort: `ALTER WAREHOUSE <wh> RESUME` then `USE WAREHOUSE <wh>`; saves to `st.session_state['sf_warehouse']`.

### 4.5 `_list_databases() -> list[str]` (cached)
- `SHOW DATABASES` → returns array of names. Swallows errors.

### 4.6 `_apply_database(db: str | None) -> None`
- If specific DB (not "All"): runs `USE DATABASE <db>` and persists to `st.session_state['sf_database']`.
- If "All": clears explicit selection so downstream queries can resolve default/current.

### 4.7 `_view_exists(db: str | None, schema: str, view: str) -> bool`
- Queries `<db>.INFORMATION_SCHEMA.VIEWS` to check existence. Returns False on error.

### 4.8 `_table_exists(db: str | None, schema: str, table: str) -> bool`
- Queries `INFORMATION_SCHEMA.TABLES` (catalog/schema/table) to check existence. Returns False on error.

### 4.9 `get_compliance_data() -> dict` (cached)
- Returns combined snapshot:
  - `access`: counts of Users, Roles, Grants via `SNOWFLAKE.ACCOUNT_USAGE`.
  - `policies`: counts of Masking and Row Access policies via `SNOWFLAKE.ACCOUNT_USAGE`.
  - `tag_usage`: top 10 tag references (`ACCOUNT_USAGE.TAG_REFERENCES`).
- On error: returns zeros/empty arrays and shows a Streamlit error.

### 4.10 `_get_latest_report() -> dict` (cached)
- Reads most recent row from `{db}.DATA_GOVERNANCE.COMPLIANCE_REPORTS` (table or view). Returns `{}` if missing or on error.
- Expected columns: `GENERATED_AT`, `METRICS` (semi-structured JSON).

### 4.11 `_compute_overall_score(metrics, pending_exceptions=None) -> (float, str)`
- Calculates a composite score in [0, 100], rounding to 0.1 precision:
  - `60%` Coverage: `metrics.coverage_rate` (`0..1`).
  - `25%` Health: `1 - violation_rate` where `violation_rate = total_violations / max(total_assets,1)`; uses `metrics.risk_counts`.
  - `15%` Exceptions: `1 - min(pending_exceptions_per_asset, 1)`.
- Returns `(score, explanation_string)` for tooltip/help display.


## 5) Sidebar UI – Session & Filters
- **Session expander**:
  - Warehouse select box → `_apply_warehouse(wh)`.
  - Database select box (with `"All"`) → `_apply_database(sel_db)`.
- **Filters expander**:
  - `render_data_filters(key_prefix="comp_filters")` returns general dataset filters as `sel` (e.g., database, schema, table). Used downstream in violations matrix.


## 6) Caching & Refresh
- `@st.cache_data(ttl=300)` for Snowflake reads (5-minute TTL).
- **Buttons**:
  - "🔄 Refresh now" clears all cached data and `st.rerun()`.
  - "🔄 Refresh Coverage & Metrics" does the same for dashboard sections.


## 7) Main Tabs & Components

```python
"""
Dashboard (📊) | Review Management (🔄) | Policy Violations (🚨)
"""
```

### 7.1 📊 Compliance Dashboard
- **Top KPI**: `Overall Compliance Score` from `_get_latest_report()` + `exception_service.list(status="Pending")` via `_compute_overall_score(...)`.
- **Sub-tabs**:
  1) Policy Compliance Metrics
     - Classification Coverage: prefer `metrics.coverage_rate`; fallback query against `{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS` (`CLASSIFICATION_TAG <> ''`).
     - Past Due (≥5d): assets where `LAST_CLASSIFIED_DATE` (or fallback to `CREATED_DATE`) is older than 5 days.
     - Accuracy vs Expected: `metrics.accuracy_score`/`metrics.accuracy` if present.
     - Open Exceptions: count of `exception_service.list(status="Pending")`.
     - Optional Top Tag Usage bar chart using `get_compliance_data()['tag_usage']`.
  2) Classification Coverage Reports
     - Latest by Framework: `{db}.DATA_GOVERNANCE.COMPLIANCE_COVERAGE` → per-framework totals and compliant/non-compliant assets.
     - By Business Unit: aggregate coverage over `ASSETS` grouped by `BUSINESS_UNIT`.
     - By Data Type: aggregate coverage grouped by `TABLE_TYPE`/`ASSET_TYPE`.
     - Trend Over Time: daily `coverage_rate` from `COMPLIANCE_REPORTS` → line chart.
  3) Exception Tracking
     - List exceptions with Status filter and Limit.
     - Actions on selection: Approve, Reject (justification text), Attach Evidence URL (saved via `exception_service`).
  4) Audit Ready Reports
     - Table of recent `COMPLIANCE_REPORTS` with `Download CSV` button.
     - Note: PDF integration can be added via external reporting.

### 7.2 🔄 Review Management
- **Schedule Reviews**: `compliance_service.schedule_review(asset_full, frequency, owner)`.
- **Upcoming Reviews**: `{db}.DATA_GOVERNANCE.REVIEW_SCHEDULES` (if exists) sorted by `NEXT_RUN`.
- **Overdue Tasks**: three metrics
  - Past Due Classifications (≥5d) – same rule as above.
  - Missed Reviews – `NEXT_RUN < current_date()`.
  - Escalation Notifications – informational placeholder.
- **Review History**: `{db}.DATA_GOVERNANCE.REVIEW_HISTORY` ordered by `COMPLETED_AT`.

### 7.3 🚨 Policy Violations
- **Controls** (role-gated to Admin/Compliance Officer)
  - Run Violation Detection: `compliance_service.detect_violations()`.
  - Expire Past-Due Exceptions: `exception_service.expire_auto()`.
- **Open Violations**
  - `compliance_service.list_open_violations(limit=500)` with drill-in details (`DETAILS` JSON).
  - Corrective Action: text input and best-effort `compliance_service.record_corrective_action(...)`.
- **Compliance Matrix & Evidence Packs**
  - Violations: `{db}.DATA_GOVERNANCE.VIOLATIONS` (ID, RULE_CODE, SEVERITY, DESCRIPTION, ASSET_FULL_NAME, DETECTED_AT, STATUS).
  - Inventory join: `{db}.DATA_GOVERNANCE.ASSET_INVENTORY` (FULL_NAME, BU/Schema, classification level, CIA triad fields) – optional.
  - Filtering: Uses `sel` (database/schema/table). Intended severity/time facets reference an undefined `facets` variable (see Known Issues).
  - Matrix: pivot by `RULE_CODE` x `BU_OR_SCHEMA` with counts.
  - Drill-down: rule + BU/Schema selection shows subset table.
  - Evidence pack (ZIP):
    - `violations.csv` (subset), `summary.json` (context), optional `policy_snapshot.json` (masking policy count), optional `audit_digest.json` (from audit service), and `SIGNATURES.txt` (SHA-256 hashes).


## 8) Data Flow (Mermaid)
```mermaid
flowchart TD
  subgraph UI[Streamlit UI]
    A1[Sidebar: Session Controls] --> S1
    A2[Sidebar: Data Filters -> sel] --> S1
    T1[Dashboard] --> S1
    T2[Review Mgmt] --> S1
    T3[Violations] --> S1
  end

  subgraph Services
    CS[compliance_service]
    ES[exception_service]
    AUTH[authz]
  end

  subgraph Snowflake
    AU[SNOWFLAKE.ACCOUNT_USAGE]
    IS[INFORMATION_SCHEMA]
    DG[{db}.DATA_GOVERNANCE]
    DCG[{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS]
  end

  AUTH --> UI
  UI -->|warehouse/db| IS
  UI -->|metrics| AU
  UI -->|coverage/trend| DG
  UI -->|assets| DCG
  UI --> CS
  UI --> ES
```


## 9) SQL Inventory (Representative)
- Users: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL`
- Roles: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE DELETED_ON IS NULL`
- Grants: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE DELETED_ON IS NULL`
- Masking Policies: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES`
- Row Access Policies: `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES`
- Coverage (fallback): `DATA_CLASSIFICATION_GOVERNANCE.ASSETS` using `CLASSIFICATION_TAG <> ''`
- Timeliness (≥5d): compares `LAST_CLASSIFIED_DATE`/`CREATED_DATE` to `dateadd('day', -5, current_date())`
- Reports/Coverage/Violations/Review tables: `{db}.DATA_GOVERNANCE.*`


## 10) Data Dictionary (Fields Referenced)
- `ASSETS`: `BUSINESS_UNIT`, `TABLE_TYPE`, `ASSET_TYPE`, `CLASSIFICATION_TAG`, `LAST_CLASSIFIED_DATE`, `CREATED_DATE`.
- `COMPLIANCE_REPORTS`: `GENERATED_AT`, `METRICS.coverage_rate`, `METRICS.asset_counts`, `METRICS.risk_counts`.
- `VIOLATIONS`: `ID`, `RULE_CODE`, `SEVERITY`, `DESCRIPTION`, `ASSET_FULL_NAME`, `DETECTED_AT`, `STATUS`, `DETAILS`.
- `ASSET_INVENTORY`: `FULL_NAME`, `BUSINESS_UNIT`/schema, `CLASSIFICATION_LEVEL`, `CIA_CONF`, `CIA_INT`, `CIA_AVAIL`.
- Exceptions service objects: typically include `ID`, `STATUS`, `JUSTIFICATION`, `EVIDENCE_LINK`, timestamps.


## 11) Troubleshooting
- **Authorization denied**: Ensure Snowflake role mapped to `authz` has at least consumer-level access.
- **Database NONE error**: Use sidebar to pick a DB or rely on `_ensure_session_database()` which selects and `USE`’s the first.
- **No data in charts**: Confirm `{db}.DATA_GOVERNANCE.*` objects exist. The app checks with `_table_exists/_view_exists` and will display info messages if missing.
- **Compliance service unavailable**: `comp_ok=False` will disable detection/violations listing; deploy/enable backend or check service health.
- **Undefined `facets` error**: See Known Issues – add a facets renderer or remove the references.


## 12) Configuration & Environment
- Snowflake credentials/role/warehouse configured in connector settings.
- Optional default DB: `settings.SNOWFLAKE_DATABASE`.
- Streamlit caching TTL: 5 minutes.
- Evidence export requires standard Python libs (`io`, `json`, `zipfile`, `hashlib`), and optionally `audit_service`.


## 13) Known Issues & Improvements
- **Undefined `facets` variable** in Compliance Matrix filters:
  - Fix A: add `facets = render_compliance_facets()` in sidebar and wire severity/time into filtering.
  - Fix B: fold severity/time options into `render_data_filters(...)` and reference from `sel`.
- **Title mismatch**: Change `st.title("Data Classification")` to `st.title("Compliance")` for clarity.
- **Resilience**: Consider user-facing banners when `compliance_service` health check fails (currently suppressed).
- **Metrics fidelity**: Align `_compute_overall_score` weights with org policy; optionally add per-framework scores.
- **Accessibility**: Add tooltips to all KPIs and aria labels for buttons.
- **Testing**: Add unit tests for `_compute_overall_score` edge cases and integration tests for table existence branches.


## 14) UI Map
```text
Sidebar
  - Session
    - Warehouse [select]
    - Database [select, includes "All"]
  - Filters
    - Dataset filters from render_data_filters(...)

Main
  - Refresh now [button]
  - Tabs
    - 📊 Compliance Dashboard
      - Overall Compliance Score [metric]
      - Sub-tabs
        - Policy Compliance Metrics [4 KPIs + optional tag chart]
        - Classification Coverage Reports [framework, BU, data type, trend]
        - Exception Tracking [table + approve/reject/evidence]
        - Audit Ready Reports [table + CSV download]
    - 🔄 Review Management
      - Schedule Reviews [inputs + button]
      - Upcoming Reviews [table]
      - Overdue Tasks [3 metrics]
      - Review History [table]
    - 🚨 Policy Violations
      - Run Detection / Expire Exceptions [buttons]
      - Open Violations [table + drill-in]
      - Compliance Matrix & Evidence Packs [pivot + drill + ZIP]
```


## 15) File & Service References
- Page: `src/pages/4_Compliance.py`
- Optional Center: `src/pages/_compliance_center.py`
- Theme: `src/ui/theme.py`
- Quick Links: `src/ui/quick_links.py`
- Filters: `src/components/filters.py`
- Services: `src/services/authorization_service.py`, `src/services/compliance_service.py`, `src/services/exception_service.py`, `src/services/audit_service.py`
