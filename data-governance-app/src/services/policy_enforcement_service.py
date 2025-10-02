"""
Policy Enforcement Service

Creates and applies Snowflake masking and row access policies based on
classification and sensitive category detections.

Notes:
- Uses Snowflake SQL DDL via existing connector
- Idempotent helpers attempt CREATE ... IF NOT EXISTS where possible
- Keep policies simple and parameterized for demo; tailor to your org
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


class PolicyEnforcementService:
    def __init__(self):
        pass

    # -------- Masking Policies --------
    def ensure_masking_policy(self, fully_qualified_policy: str, return_type: str = 'STRING', mask_expr_sql: Optional[str] = None) -> None:
        """Create a simple masking policy if not exists.
        fully_qualified_policy: DB.SCHEMA.POLICY_NAME
        return_type: target column type e.g., STRING, NUMBER, etc.
        mask_expr_sql: SQL expression body using (VAL, ROLE) input args.
        Example: "CASE WHEN CURRENT_ROLE() IN ('SECURITY_ADMIN','SYSADMIN') THEN VAL ELSE '***MASKED***' END"
        """
        if not mask_expr_sql:
            # Use role-in-session checks to allow multiple roles to unmask
            mask_expr_sql = (
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE '***' END"
            )
        sql = f"""
        CREATE MASKING POLICY IF NOT EXISTS {fully_qualified_policy}
        AS (VAL {return_type}) RETURNS {return_type}
        -> {mask_expr_sql}
        """
        snowflake_connector.execute_non_query(sql)

    def apply_masking_policy(self, table: str, column: str, fully_qualified_policy: str) -> None:
        sql = f"""
        ALTER TABLE {table} MODIFY COLUMN {column} SET MASKING POLICY {fully_qualified_policy}
        """
        snowflake_connector.execute_non_query(sql)

    def drop_masking_policy(self, fully_qualified_policy: str) -> None:
        sql = f"DROP MASKING POLICY IF EXISTS {fully_qualified_policy}"
        snowflake_connector.execute_non_query(sql)

    # -------- Row Access Policies --------
    def ensure_row_access_policy(self, fully_qualified_policy: str, parameter_signature: str, using_expr_sql: Optional[str] = None) -> None:
        """Create a row access policy if not exists.
        parameter_signature: e.g., "(DEPT STRING)" or "(BU STRING, GEO STRING)". Must not be empty.
        using_expr_sql: boolean SQL expression that can reference the parameters.
        Example using_expr_sql: "IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR CURRENT_ROLE() = 'SYSADMIN'"
        """
        if not parameter_signature or parameter_signature.strip() == "()":
            raise ValueError("parameter_signature must specify at least one parameter, e.g., '(DEPT STRING)'")
        if not using_expr_sql:
            using_expr_sql = "IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN')"
        sql = f"""
        CREATE ROW ACCESS POLICY IF NOT EXISTS {fully_qualified_policy}
        AS {parameter_signature} RETURNS BOOLEAN -> {using_expr_sql}
        """
        snowflake_connector.execute_non_query(sql)

    def apply_row_access_policy(self, table: str, fully_qualified_policy: str, columns: Optional[list[str]] = None) -> None:
        # Row access policies require explicit column mapping corresponding to the policy signature
        if not columns or not [str(c).strip() for c in columns]:
            raise ValueError("Row access policy application requires one or more column names matching the policy signature.")
        col_list = ", ".join([str(c).strip() for c in columns])
        sql = f"ALTER TABLE {table} ADD ROW ACCESS POLICY {fully_qualified_policy} ON ({col_list})"
        snowflake_connector.execute_non_query(sql)

    def drop_row_access_policy(self, fully_qualified_policy: str) -> None:
        sql = f"DROP ROW ACCESS POLICY IF EXISTS {fully_qualified_policy}"
        snowflake_connector.execute_non_query(sql)

    # -------- Automated Enforcement --------
    def auto_enforce_for_table(self, table: str, detections: List[Dict[str, Any]], policy_db: Optional[str] = None, policy_schema: Optional[str] = None, table_cia: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """Apply masking policies to columns if PII/Financial/Auth detected.
        detections: list from ai_classification_service.detect_sensitive_columns
        """
        policy_db = policy_db or settings.SNOWFLAKE_DATABASE
        policy_schema = policy_schema or 'DATA_GOVERNANCE'
        created: list[str] = []
        applied: list[dict] = []

        # Ensure a bundle of masking policies by type
        string_policy = f"{policy_db}.{policy_schema}.MASK_REDACT_STRING"
        number_policy = f"{policy_db}.{policy_schema}.MASK_ZERO_NUMBER"
        bool_policy = f"{policy_db}.{policy_schema}.MASK_FALSE_BOOLEAN"
        binary_policy = f"{policy_db}.{policy_schema}.MASK_NULL_BINARY"
        date_policy = f"{policy_db}.{policy_schema}.MASK_NULL_DATE"
        ts_policy = f"{policy_db}.{policy_schema}.MASK_NULL_TIMESTAMP"
        # Specialized policies for PCI/HIPAA/common PII
        pci_pan_policy = f"{policy_db}.{policy_schema}.MASK_PCI_PAN_LAST4"
        email_policy = f"{policy_db}.{policy_schema}.MASK_EMAIL_USER"
        phone_policy = f"{policy_db}.{policy_schema}.MASK_PHONE_LAST4"
        ssn_policy = f"{policy_db}.{policy_schema}.MASK_SSN_LAST4"
        hash_string_policy = f"{policy_db}.{policy_schema}.MASK_HASH_STRING"
        try:
            self.ensure_masking_policy(string_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE '***' END"
            ))
            created.append(string_policy)
        except Exception:
            pass
        try:
            self.ensure_masking_policy(number_policy, return_type='NUMBER', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE 0 END"
            ))
            created.append(number_policy)
        except Exception:
            pass
        try:
            self.ensure_masking_policy(bool_policy, return_type='BOOLEAN', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE FALSE END"
            ))
            created.append(bool_policy)
        except Exception:
            pass
        try:
            self.ensure_masking_policy(date_policy, return_type='DATE', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE TO_DATE(NULL) END"
            ))
            created.append(date_policy)
        except Exception:
            pass
        try:
            self.ensure_masking_policy(ts_policy, return_type='TIMESTAMP_NTZ', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE TO_TIMESTAMP_NTZ(NULL) END"
            ))
            created.append(ts_policy)
        except Exception:
            pass
        try:
            self.ensure_masking_policy(binary_policy, return_type='BINARY', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') "
                "OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL ELSE TO_BINARY(NULL) END"
            ))
            created.append(binary_policy)
        except Exception:
            pass

        # Specialized templates
        try:
            # Keep only last 4 digits of PAN-like values
            self.ensure_masking_policy(pci_pan_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL "
                "ELSE REGEXP_REPLACE(VAL, '(\\\d{12})(\\\d{4})', '************\\2') END"
            ))
            created.append(pci_pan_policy)
        except Exception:
            pass
        try:
            # Mask email user part, keep domain
            self.ensure_masking_policy(email_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL "
                "ELSE REGEXP_REPLACE(VAL, '(^[^@])[^@]*(@.*$)', '\\1***\\2') END"
            ))
            created.append(email_policy)
        except Exception:
            pass
        try:
            # Mask phone leave last 4
            self.ensure_masking_policy(phone_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL "
                "ELSE REGEXP_REPLACE(VAL, '(.*)(\\\d{4})$', '***-***-****') END"
            ))
            created.append(phone_policy)
        except Exception:
            pass
        try:
            # Mask SSN keep last 4
            self.ensure_masking_policy(ssn_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL "
                "ELSE REGEXP_REPLACE(VAL, '(\\\d{3})-?\\\d{2}-?(\\\d{4})', '***-**-\\2') END"
            ))
            created.append(ssn_policy)
        except Exception:
            pass
        try:
            # Hash arbitrary strings for PHI-like content
            self.ensure_masking_policy(hash_string_policy, return_type='STRING', mask_expr_sql=(
                "CASE WHEN IS_ROLE_IN_SESSION('SECURITY_ADMIN') OR IS_ROLE_IN_SESSION('SYSADMIN') OR IS_ROLE_IN_SESSION('DATA_OWNER') OR IS_ROLE_IN_SESSION('COMPLIANCE_OFFICER') THEN VAL "
                "ELSE SHA2(VAL) END"
            ))
            created.append(hash_string_policy)
        except Exception:
            pass

        # Map of Snowflake data type families to masking policies
        policy_by_type = {
            'STRING': string_policy,
            'TEXT': string_policy,
            'VARCHAR': string_policy,
            'CHAR': string_policy,
            'NUMBER': number_policy,
            'DECIMAL': number_policy,
            'INT': number_policy,
            'INTEGER': number_policy,
            'BIGINT': number_policy,
            'FLOAT': number_policy,
            'DOUBLE': number_policy,
            'BOOLEAN': bool_policy,
            'BINARY': binary_policy,
            'DATE': date_policy,
            'TIMESTAMP': ts_policy,
            'TIMESTAMP_NTZ': ts_policy,
            'TIMESTAMP_TZ': ts_policy,
            'TIMESTAMP_LTZ': ts_policy,
        }

        # Lookup column data types for the table
        def _get_column_type_map(fq_table: str) -> dict[str, str]:
            try:
                db, schema, table_only = fq_table.split('.')
            except ValueError:
                return {}
            rows = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                """,
                {"s": schema, "t": table_only},
            ) or []
            return {str(r.get('COLUMN_NAME')).upper(): str(r.get('DATA_TYPE')).upper() for r in rows}

        type_map = _get_column_type_map(table)

        # Determine masking exemptions via TAG_REFERENCES for this table/columns
        exempt_cols: set[str] = set()
        table_exempt: bool = False
        try:
            db, schema, tbl = table.split('.')
            # Column-level exemptions
            ex_rows = snowflake_connector.execute_query(
                f"""
                SELECT UPPER(COLUMN_NAME) AS COL
                FROM {db}."SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                WHERE UPPER(TAG_NAME) = 'MASKING_EXEMPT' AND UPPER(TAG_VALUE) = 'TRUE'
                  AND OBJECT_SCHEMA = %(s)s AND OBJECT_NAME = %(t)s AND COLUMN_NAME IS NOT NULL
                """,
                {"s": schema, "t": tbl},
            ) or []
            exempt_cols = {r.get('COL') for r in ex_rows if r.get('COL')}
            # Object-level exemption
            obj_rows = snowflake_connector.execute_query(
                f"""
                SELECT 1 AS X
                FROM {db}."SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                WHERE UPPER(TAG_NAME) = 'MASKING_EXEMPT' AND UPPER(TAG_VALUE) = 'TRUE'
                  AND OBJECT_SCHEMA = %(s)s AND OBJECT_NAME = %(t)s AND COLUMN_NAME IS NULL
                LIMIT 1
                """,
                {"s": schema, "t": tbl},
            ) or []
            table_exempt = bool(obj_rows)
        except Exception:
            exempt_cols = set()
            table_exempt = False

        for d in (detections or []):
            cats = set(d.get('categories') or [])
            col = (d.get('column') or '').upper()
            if not col:
                continue
            if table_exempt or (col in exempt_cols):
                continue
            if not (cats & {'PII', 'Financial', 'Auth', 'PCI', 'HIPAA', 'PHI'}):
                continue
            # Pick policy by column data type
            dtype = (type_map.get(col) or '').upper()
            chosen_policy = None
            # Column-name and category heuristics first
            if ('PCI' in cats) or any(x in col for x in ['CARD', 'PAN', 'CREDIT', 'CC_NUMBER']):
                chosen_policy = pci_pan_policy
            elif any(x in col for x in ['EMAIL']):
                chosen_policy = email_policy
            elif any(x in col for x in ['PHONE', 'MOBILE', 'TEL']):
                chosen_policy = phone_policy
            elif any(x in col for x in ['SSN', 'SOCIAL']):
                chosen_policy = ssn_policy
            elif ('HIPAA' in cats or 'PHI' in cats):
                # Default to hashing for PHI-like fields when type is string, else fallback to type policy
                if dtype.startswith('CHAR') or dtype.startswith('TEXT') or dtype.startswith('VARCHAR') or dtype.startswith('STRING'):
                    chosen_policy = hash_string_policy
            # Find best match by prefix
            if not chosen_policy:
                for key, pol in policy_by_type.items():
                    if dtype.startswith(key):
                        chosen_policy = pol
                        break
            if not chosen_policy:
                # Default to string redaction if unknown
                chosen_policy = string_policy
            try:
                self.apply_masking_policy(table, col, chosen_policy)
                applied.append({'column': col, 'policy': chosen_policy, 'datatype': dtype})
            except Exception:
                continue
        # CIA-driven default enforcement: if table Confidentiality >= 2, ensure masking is applied by data type across all columns
        try:
            if not table_exempt and isinstance(table_cia, dict) and int(table_cia.get('C', 0)) >= 2:
                already_applied_cols = {a.get('column') for a in applied}
                for col_name, dtype in (type_map or {}).items():
                    col_up = str(col_name).upper()
                    # Skip if already masked in the detection-driven loop
                    if col_up in already_applied_cols or (col_up in exempt_cols):
                        continue
                    chosen_policy = None
                    for key, pol in policy_by_type.items():
                        if (dtype or '').upper().startswith(key):
                            chosen_policy = pol
                            break
                    if not chosen_policy:
                        chosen_policy = string_policy
                    try:
                        self.apply_masking_policy(table, col_up, chosen_policy)
                        applied.append({'column': col_up, 'policy': chosen_policy, 'datatype': (dtype or '').upper(), 'reason': 'CIA>=2 default'})
                    except Exception:
                        # best-effort; continue to next column
                        continue
        except Exception:
            # Do not fail overall enforcement due to CIA-pass phase
            pass
        # Optional: apply row access policy if object tagged ROW_POLICY_REQUIRED='BU_GEO' and columns exist
        try:
            db, schema, tbl = table.split('.')
            rap_required = False
            chk = snowflake_connector.execute_query(
                f"""
                SELECT 1 AS X
                FROM {db}."SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                WHERE OBJECT_SCHEMA=%(s)s AND OBJECT_NAME=%(t)s AND COLUMN_NAME IS NULL
                  AND UPPER(TAG_NAME)='ROW_POLICY_REQUIRED' AND UPPER(TAG_VALUE)='BU_GEO'
                LIMIT 1
                """,
                {"s": schema, "t": tbl},
            ) or []
            rap_required = bool(chk)
            if rap_required:
                # Check for BU/GEO columns
                cols_up = {c.upper() for c in (type_map or {}).keys()}
                if {'BU','GEO'}.issubset(cols_up):
                    rap_name = self.ensure_bu_geo_row_access_policy()
                    try:
                        self.apply_row_access_policy(table, rap_name, columns=['BU','GEO'])
                    except Exception:
                        pass
        except Exception:
            pass

        return {'created_policies': created, 'applied': applied}

    # -------- Tag-aware Row Access Template (BU/GEO) --------
    def ensure_row_access_rules_table(self, database: Optional[str] = None) -> None:
        db = database or settings.SNOWFLAKE_DATABASE
        snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.DATA_GOVERNANCE")
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_GOVERNANCE.ROW_ACCESS_RULES (
                ROLE_NAME STRING,
                ATTRIBUTE STRING, -- 'BU' or 'GEO'
                VALUE STRING,
                UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Add a uniqueness constraint to avoid duplicates
        try:
            snowflake_connector.execute_non_query(
                f"ALTER TABLE {db}.DATA_GOVERNANCE.ROW_ACCESS_RULES ADD CONSTRAINT IF NOT EXISTS UQ_RAR UNIQUE(ROLE_NAME, ATTRIBUTE, VALUE)"
            )
        except Exception:
            pass

    def ensure_bu_geo_row_access_policy(self, policy_name: str = 'RAP_BU_GEO', database: Optional[str] = None, schema: str = 'DATA_GOVERNANCE') -> str:
        """Create a reusable row access policy that filters on BU/GEO using governance rules.
        Returns fully qualified policy name.
        The policy signature expects (BU STRING, GEO STRING) columns on target tables.
        """
        db = database or settings.SNOWFLAKE_DATABASE
        self.ensure_row_access_rules_table(db)
        fq = f"{db}.{schema}.{policy_name}"
        using_expr = (
            f"EXISTS (SELECT 1 FROM {db}.DATA_GOVERNANCE.ROW_ACCESS_RULES r "
            f"WHERE r.ROLE_NAME = CURRENT_ROLE() AND ( (r.ATTRIBUTE='BU' AND r.VALUE = BU) OR (r.ATTRIBUTE='GEO' AND r.VALUE = GEO) ) )"
        )
        # Use the generic helper with explicit signature
        self.ensure_row_access_policy(fq, parameter_signature="(BU STRING, GEO STRING)", using_expr_sql=using_expr)
        return fq


policy_enforcement_service = PolicyEnforcementService()

