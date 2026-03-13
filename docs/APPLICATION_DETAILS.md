# Application Technical Reference & Architecture

## 1. Introduction
This document provides a deep technical dive into the **Snowflake Data Governance & Classification Application**. It is intended for developers, architects, and data engineers who need to understand the internal mechanisms, data flow, and code structure of the application.

The application is a **Snowflake Native App** built using **Streamlit**, designed to provide end-to-end data governance capabilities, including automated PII discovery, classification workflows, compliance reporting, and data quality intelligence.

---

## 2. High-Level Architecture

### Technology Stack
*   **Frontend**: Streamlit (Python)
*   **Backend**: Snowflake (SQL, Snowpark Python)
*   **Visualization**: Plotly, Altair
*   **Data Processing**: Pandas, Snowflake Native SQL Functions

### Design Pattern
The application follows a **Service-Oriented Architecture (SOA)** within a monolithic Streamlit app structure:
*   **`pages/`**: UI Layer (View). Handles user interaction and rendering.
*   **`src/services/`**: Business Logic Layer. Contains reusable logic for classification, authorization, and compliance.
*   **`src/connectors/`**: Data Access Layer. Manages Snowflake connections and query execution.
*   **`src/components/`**: Reusable UI widgets (e.g., filters, action panels).

---

## 3. Application Modules (Page-by-Page Detail)

### 3.1 Data Assets (`pages/1_Data_Assets.py`)
This page serves as the **Master Inventory** for all data assets.
*   **Functionality**:
    *   Lists all tables/views in the governed database.
    *   Displays classification status (C/I/A scores), row counts, and ownership.
    *   **Policy Guardrails**: Implements strict validation logic (e.g., "PII data cannot be Public") using `_validate_decision_matrix`.
    *   **Batch Tagging**: Optimized fetching of Snowflake tags using batch queries to `ACCOUNT_USAGE.TAG_REFERENCES`.
*   **Key Components**:
    *   **Inventory Browser**: Main interactive data grid.
    *   **KPI Cards**: Custom CSS-styled metrics for Total Assets, Classified %, and SLA breaches.

### 3.2 Dashboard (`pages/2_Dashboard.py`)
A real-time analytics command center.
*   **Key Metrics**:
    *   **Program Maturity Score**: A composite weighted score based on coverage, accuracy, and timeliness.
    *   **Sensitivity Distribution**: Pie charts showing the ratio of Public vs. Confidential data.
    *   **Risk Profile**: Identifies "High Risk" assets (e.g., `Confidential` data accessible by `Public` roles).
*   **Implementation**:
    *   Uses highly optimized SQL queries to aggregate metrics from `ASSETS` and `CLASSIFICATION_HISTORY`.
    *   Features a "Bypass Mode" for local testing without live Snowflake connections.

### 3.3 Classification Center (`pages/3_Classification.py`)
The heart of the application's workflow.
*   **Workflow**:
    1.  **Automated Discovery**: Triggers `scan_all_pii_native.py` or AI services to detect sensitive columns.
    2.  **Task Management**: High-probability findings generate "Tasks" for human review.
    3.  **Manual Action**: Data Stewards can `Approve`, `Reject`, or `Modify` classifications.
    4.  **Tag Application**: Upon approval, system tags (`CONFIDENTIALITY_LEVEL`, etc.) are written back to Snowflake.
*   **AI Integration**:
    *   Lazy-loaded `ai_classification_service` to optimize startup time.
    *   Uses `EXTRACT_SEMANTIC_CATEGORIES` (Snowflake Native) for PII detection.

### 3.4 Compliance & Reporting (`pages/4_Compliance.py`)
Focuses on regulatory adherence (GDPR, CCPA, SOX).
*   **Features**:
    *   **Mandatory Compliance Elements**: Checks for 5-Day classification SLAs and annual review completion.
    *   **Special Categories**: specific logical checks for "Financial" (SOX) or "Personal" (GDPR) data types.
    *   **Export**: functionality to generate PDF/Excel reports for auditors.
*   **Logic**:
    *   Complex SQL CTEs (Common Table Expressions) calculate compliance percentages dynamically.

### 3.5 Data Intelligence (`pages/5_Data_Intelligence.py`)
Provides "Health Checks" and Quality Metadata.
*   **Dimensions**:
    *   **Completeness**: Checks for NULL values in critical columns.
    *   **Uniqueness**: Validates primary key constraints.
    *   **Freshness**: Tracks `LAST_ALTERED` timestamps to ensure data currency.
*   **Data Source**: Primarily queries `INFORMATION_SCHEMA` and `ACCOUNT_USAGE` views.

### 3.6 Policy Guidance (`pages/6_Policy_Guidance.py`)
A knowledge base for governance rules.
*   **Features**:
    *   **Policy Management**: Create/Edit/Upload policy documents.
    *   **Role Definitions**: Maps Snowflake Roles (e.g., `ACCOUNTADMIN`) to human-readable responsibilities.
    *   **Framework Reference**: Visual guide to the C/I/A (Confidentiality, Integrity, Availability) scoring model.

---

## 4. Key Services & Logic

### 4.1 Classification Pipeline Service (`src/services/classification_pipeline_service.py`)
The **Orchestrator** service.
*   **Responsibility**: Coordinates the flow between data scanning, AI detection, and result persistence.
*   **Logic**: Merges "Native Snowflake PII Tags" with "Custom Regex Patterns" to produce a final `Confidence Score`.

### 4.2 Authorization Service (`src/services/authorization_service.py`)
Manages RBAC (Role-Based Access Control) within the app.
*   **Roles**:
    *   `APP_ADMIN`: Full configuration access.
    *   `DATA_STEWARD`: Can classifications and edit tags.
    *   `VIEWER`: Read-only access.
*   **Bypass Logic**: Includes a dev-mode bypass to simulate roles when running locally.

### 4.3 Snowflake Connector (`src/connectors/snowflake_connector.py`)
A singleton wrapper around the Snowflake connection.
*   **Features**:
    *   Handles both **SiS** (Streamlit in Snowflake) active sessions and **Local** (User/Pass/Org) connections.
    *   Implements query caching and error handling.

---

## 5. Database Schema Reference
The application relies on the `DATA_CLASSIFICATION_GOVERNANCE` schema.

| Table Name | Description | Key Columns |
| :--- | :--- | :--- |
| **`ASSETS`** | Master registry of all tracked tables/views. | `ASSET_ID`, `ASSET_NAME`, `CLASSIFICATION_LABEL`, `PII_RELEVANT`, `CIA_SCORE` |
| **`CLASSIFICATION_AI_RESULTS`** | Raw output from PII scanners. | `COLUMN_NAME`, `SEMANTIC_CATEGORY`, `FINAL_CONFIDENCE` |
| **`CLASSIFICATION_TASKS`** | Workflow queue for human review. | `TASK_ID`, `STATUS` ('Pending', 'Approved'), `ASSIGNED_TO` |
| **`POLICIES`** | Document store for governance policies. | `POLICY_ID`, `POLICY_CONTENT`, `EFFECTIVE_DATE` |
| **`QA_REVIEWS`** | Audit log of quality assurance checks. | `ASSET_FULL_NAME`, `REVIEWED_AT`, `STATUS` |

---

## 6. Data Flow: Automated Classification

1.  **Scan**: `scan_all_pii_native.py` runs `EXTRACT_SEMANTIC_CATEGORIES` on target tables.
2.  **Ingest**: Results are parsed and stored in `CLASSIFICATION_AI_RESULTS`.
3.  **Flag**: If High Confidence PII is found, the asset in `ASSETS` table is flagged `PII_RELEVANT = TRUE`.
4.  **Task**: A task is created in `CLASSIFICATION_TASKS` for a Data Steward.
5.  **Review**: Steward opens **Page 3 (Classification)**, reviews findings, and clicks "Approve".
6.  **Tag**: System runs `ALTER TABLE ... SET TAG ...` on the Snowflake object.
7.  **Audit**: The action is logged to `CLASSIFICATION_HISTORY`.
