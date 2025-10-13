"""
AI Classification Service for Data Governance Application.

This service integrates the machine learning classifier with Snowflake data
to provide real-time classification without external APIs.
"""
import pandas as pd
from typing import Dict, List, Any

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.ml.classifier import classifier


class AIClassificationService:
    """
    Service for AI-based data classification and compliance mapping.
    """
    
    def __init__(self):
        """Initialize the service with the classifier."""
        self.classifier = classifier
    
    def get_table_metadata(self, table_name: str) -> Dict[str, Any]:
        """
        Get metadata for a specific table.
        
        Args:
            table_name: Full table name (schema.table)
            
        Returns:
            Dictionary containing table metadata
        """
        # Parse table name
        parts = table_name.split('.')
        if len(parts) != 3:
            raise ValueError("Table name must be in format database.schema.table")
            
        database, schema, table = parts
        
        # Query INFORMATION_SCHEMA for table metadata
        query = f"""
        SELECT 
            "TABLE_CATALOG",
            "TABLE_SCHEMA",
            "TABLE_NAME",
            "TABLE_TYPE",
            "CREATED",
            "LAST_ALTERED"
        FROM {database}.INFORMATION_SCHEMA.TABLES
        WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
        """
        
        result = snowflake_connector.execute_query(query)
        return result[0] if result else {}
    
    def get_column_metadata(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get column metadata for a specific table.
        
        Args:
            table_name: Full table name (schema.table)
            
        Returns:
            List of dictionaries containing column metadata
        """
        # Parse table name
        parts = table_name.split('.')
        if len(parts) != 3:
            raise ValueError("Table name must be in format database.schema.table")
            
        database, schema, table = parts
        
        # Query INFORMATION_SCHEMA for column metadata
        query = f"""
        SELECT 
            "COLUMN_NAME",
            "DATA_TYPE",
            "IS_NULLABLE",
            "COLUMN_DEFAULT",
            "CHARACTER_MAXIMUM_LENGTH"
        FROM {database}.INFORMATION_SCHEMA.COLUMNS
        WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
        ORDER BY "ORDINAL_POSITION"
        """
        
        return snowflake_connector.execute_query(query)
    
    def get_sample_data(self, table_name: str, sample_size: int = 100) -> pd.DataFrame:
        """
        Get sample data from a table for analysis.
        
        Args:
            table_name: Full table name (schema.table)
            sample_size: Number of rows to sample
            
        Returns:
            DataFrame containing sample data
        """
        query = f"SELECT * FROM {table_name} LIMIT {sample_size}"
        
        # Execute query and convert to DataFrame
        result = snowflake_connector.execute_query(query)
        if result:
            return pd.DataFrame(result)
        else:
            return pd.DataFrame()
    
    def classify_table(self, table_name: str) -> Dict[str, Any]:
        """
        Classify a table using AI techniques.
        
        Args:
            table_name: Full table name (database.schema.table)
            
        Returns:
            Dictionary containing classification results
        """
        # Get table metadata
        table_metadata = self.get_table_metadata(table_name)
        
        if not table_metadata:
            raise ValueError(f"Table {table_name} not found")
        
        # Get sample data for analysis
        sample_data = self.get_sample_data(table_name, 50)

        # Attempt Snowflake Cortex-assisted classification if available
        cortex_result = None
        try:
            cortex_result = self._cortex_enhanced_classification(table_metadata, sample_data)
        except Exception:
            cortex_result = None

        # Fallback to local ML classifier
        base_result = self.classifier.classify_asset(table_metadata, sample_data)

        # Merge/enhance results: prefer Cortex label when confidence higher
        classification_result = base_result
        if cortex_result and cortex_result.get('confidence', 0) >= base_result.get('confidence', 0):
            classification_result = cortex_result
        else:
            # If base picked, still append any frameworks/evidence from Cortex if present
            if cortex_result:
                frs = list({*(base_result.get('compliance_frameworks') or []), *(cortex_result.get('compliance_frameworks') or [])})
                feats = base_result.get('features') or {}
                feats['cortex'] = cortex_result.get('features', {}).get('cortex_insights')
                classification_result['compliance_frameworks'] = frs
                classification_result['features'] = feats
        
        return {
            'table_name': table_name,
            'classification': classification_result['classification'],
            'compliance_frameworks': classification_result['compliance_frameworks'],
            'confidence': classification_result['confidence'],
            'features': classification_result['features']
        }
    
    def classify_multiple_tables(self, table_names: List[str]) -> List[Dict[str, Any]]:
        """
        Classify multiple tables.
        
        Args:
            table_names: List of full table names
            
        Returns:
            List of classification results
        """
        results = []
        
        for table_name in table_names:
            try:
                result = self.classify_table(table_name)
                results.append(result)
            except Exception as e:
                results.append({
                    'table_name': table_name,
                    'error': str(e),
                    'classification': 'Unknown',
                    'compliance_frameworks': [],
                    'confidence': 0.0
                })
        
        return results
    
    def get_classification_summary(self) -> Dict[str, Any]:
        """
        Get a summary of classifications across all tables.
        
        Returns:
            Dictionary containing classification summary
        """
        # Get all tables
        tables_query = f"""
        SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS "FULL_NAME"
        FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.TABLES
        WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
        ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
        LIMIT 100
        """
        
        tables_result = snowflake_connector.execute_query(tables_query)
        table_names = [t['FULL_NAME'] for t in tables_result] if tables_result else []
        
        # Classify all tables
        classifications = self.classify_multiple_tables(table_names)
        
        # Generate summary statistics
        classification_counts = {}
        framework_counts = {}
        total_classified = len([c for c in classifications if 'error' not in c])
        
        for classification in classifications:
            if 'error' not in classification:
                # Count classifications
                cls = classification['classification']
                classification_counts[cls] = classification_counts.get(cls, 0) + 1
                
                # Count frameworks
                for framework in classification['compliance_frameworks']:
                    framework_counts[framework] = framework_counts.get(framework, 0) + 1
        
        return {
            'total_tables': len(table_names),
            'total_classified': total_classified,
            'classification_distribution': classification_counts,
            'framework_distribution': framework_counts,
            'classifications': classifications
        }

    # --- Sensitive Column Detection & Compliance (AI-lite) ---
    def _sensitivity_patterns(self) -> Dict[str, Any]:
        """Return regex patterns and hints for common sensitive categories."""
        return {
            'PII': {
                'name_tokens': [
                    'SSN','SOCIAL','EMAIL','E_MAIL','E-MAIL','PHONE','MOBILE','DOB','DATE_OF_BIRTH','ADDRESS','NAME','FIRST_NAME','LAST_NAME','SURNAME','CUSTOMER','EMPLOYEE','PERSON','NATIONAL_ID','PASSPORT','PAN','AADHAAR'
                ],
                'value_regex': [
                    # email
                    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
                    # phone (loose)
                    r"^\+?[0-9\-()\s]{7,}$",
                    # SSN US (very loose)
                    r"^\d{3}-?\d{2}-?\d{4}$"
                ]
            },
            'PHI': {
                'name_tokens': ['PHI','HEALTH','MEDICAL','PATIENT','ICD','DIAGNOSIS'],
                'value_regex': []
            },
            'Financial': {
                'name_tokens': ['FINANCE','FINANCIAL','AMOUNT','INVOICE','ACCOUNT','CARD','GL','LEDGER','PAYROLL','AR','AP','IFRS','GAAP'],
                'value_regex': [
                    # Credit card (very loose Luhn-free)
                    r"^[0-9]{13,19}$"
                ]
            },
            'Auth': {
                'name_tokens': ['PASSWORD','PASSWD','TOKEN','SECRET','API_KEY','KEY','PIN','OTP'],
                'value_regex': []
            }
        }

    def detect_sensitive_columns(self, table_name: str, sample_size: int = 100) -> List[Dict[str, Any]]:
        """
        Best-effort sensitive column detection using column names + sample value regex matches.

        Returns a list of {column, categories, name_score, value_score, confidence}.
        """
        # Get columns and sample data
        cols_meta = self.get_column_metadata(table_name)
        df = self.get_sample_data(table_name, sample_size)
        patterns = self._sensitivity_patterns()

        out: List[Dict[str, Any]] = []
        if not cols_meta:
            return out

        import re
        for col in cols_meta:
            cname = str(col.get('COLUMN_NAME') or '')
            up = cname.upper()
            categories = []
            name_hits = 0
            value_hits = 0

            # Name-based signals
            for cat, spec in patterns.items():
                if any(tok in up for tok in spec.get('name_tokens', [])):
                    categories.append(cat)
                    name_hits += 1

            # Value-based signals (sample values)
            if not df.empty and cname in df.columns:
                series = df[cname].astype(str).fillna("").head(min(50, len(df)))
                for cat, spec in patterns.items():
                    vres = spec.get('value_regex', [])
                    if not vres:
                        continue
                    matched = 0
                    total = 0
                    for v in series:
                        v = v.strip()
                        if not v:
                            continue
                        total += 1
                        if any(re.match(rx, v) for rx in vres):
                            matched += 1
                    if total > 0 and matched / total >= 0.2:  # 20% threshold
                        if cat not in categories:
                            categories.append(cat)
                        value_hits += 1

            # Confidence heuristic
            confidence = min(1.0, 0.3 * name_hits + 0.5 * value_hits)

            out.append({
                'column': cname,
                'categories': sorted(set(categories)),
                'name_score': name_hits,
                'value_score': value_hits,
                'confidence': round(confidence, 2)
            })

        # Sort by confidence desc
        out.sort(key=lambda r: r['confidence'], reverse=True)
        return out

    def assess_compliance(self, classification_label: str, c_level: int, detected_categories: List[str]) -> Dict[str, Any]:
        """Assess compliance against policy minimums based on detected categories.

        Rules:
        - PII/PHI/Financial => C >= 2 (Restricted)
        - SOX/Financial reporting cues => C >= 3 for SOX-relevant
        """
        issues = []
        cls = (classification_label or 'Internal').title()
        c = int(c_level or 0)
        cats = set([str(x) for x in (detected_categories or [])])

        def ensure(min_c: int, reason: str):
            if c < min_c:
                issues.append({'min_c': min_c, 'reason': reason})

        if any(x in cats for x in ['PII','PHI','Financial']):
            ensure(2, 'PII/PHI/Financial detected requires at least Restricted (C2)')
        # Flag SOX if Financial + GAAP/IFRS present in detected categories (hard to infer from columns; keep Financial as proxy)
        if 'Financial' in cats and c < 3:
            # Elevate to C3 if context indicates SOX; here we mark as potential
            issues.append({'min_c': 3, 'reason': 'Potential SOX-relevant data; consider Confidential (C3)'})

        return {
            'label': cls,
            'c_level': c,
            'issues': issues,
            'compliant': (len([i for i in issues if i.get('min_c', 0) > c]) == 0)
        }

    # --- Value-level classification and column aggregation ---
    def classify_value(self, value: str) -> Dict[str, Any]:
        """Classify a single value using regex patterns and optional Cortex semantics.

        Returns: {"types": [..], "confidence": float, "signals": {...}}
        """
        try:
            v = (value or "").strip()
            types: List[str] = []
            conf: float = 0.0
            signals: Dict[str, Any] = {}
            pats = self._sensitivity_patterns()
            import re
            # Regex-based
            def _rx_any(rx_list: List[str]) -> bool:
                for rx in rx_list or []:
                    try:
                        if re.match(rx, v):
                            return True
                    except Exception:
                        continue
                return False
            if _rx_any(pats['PII']['value_regex']):
                types.extend(["PII"])  # specific subtype inferred below
                # Subtypes
                if re.match(r"^\d{3}-?\d{2}-?\d{4}$", v):
                    types.append("SSN")
                if re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", v):
                    types.append("Email")
                if re.match(r"^\+?[0-9\-()\s]{7,}$", v):
                    types.append("Phone")
                conf = max(conf, 0.9)
            # PAN/PCI with Luhn validation
            def _luhn_ok(num: str) -> bool:
                try:
                    s = [int(x) for x in num]
                    checksum = 0
                    dbl = False
                    for d in reversed(s):
                        if dbl:
                            d2 = d * 2
                            if d2 > 9:
                                d2 -= 9
                            checksum += d2
                        else:
                            checksum += d
                        dbl = not dbl
                    return checksum % 10 == 0
                except Exception:
                    return False
            digits = re.sub(r"[^0-9]", "", v)
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                types.extend(["Financial", "PCI"])  # validated
                conf = max(conf, 0.9)
            # Semantic hints (name/address/medical): delegate to Cortex extract if available
            try:
                if self._cortex_available():
                    # Use EXTRACT to surface entities
                    ext = snowflake_connector.execute_query("SELECT EXTRACT(%(txt)s) AS ENT", {"txt": v}) or []
                    ent = (ext[0].get('ENT') if ext else {})
                    up = v.upper()
                    if any(k in up for k in ['PATIENT','MEDICAL','HEALTH','DIAGNOSIS','RX','ICD']):
                        types.append("PHI")
                        conf = max(conf, 0.7)
                    if any(k in up for k in ['ADDRESS','STREET','CITY','ZIP']):
                        types.append("PII")
                        conf = max(conf, 0.6)
                    if any(k in up for k in ['LEDGER','GL','INVOICE','PAYROLL']):
                        types.append("Financial")
                        conf = max(conf, 0.6)
                    signals['cortex_extract'] = ent
            except Exception:
                pass
            # Fallback categorization for alphanumeric IDs
            if not types and re.match(r"^[A-Za-z0-9_-]{6,}$", v):
                # Could be identifiers; keep neutral unless patterns trigger
                types = []
                conf = max(conf, 0.2)
            return {"types": sorted(list(set(types))), "confidence": round(conf, 2), "signals": signals}
        except Exception:
            return {"types": [], "confidence": 0.0, "signals": {}}

    def classify_values_batch(self, values: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for v in values or []:
            try:
                out.append(self.classify_value(str(v)))
            except Exception:
                out.append({"types": [], "confidence": 0.0, "signals": {}})
        return out

    def _suggest_cia_from_type(self, dominant_type: str) -> Dict[str, int]:
        dt = (dominant_type or '').upper()
        C = I = A = 0
        if dt in ("PII", "PCI", "PHI", "FINANCIAL"):
            C = max(C, 2)
        if dt in ("PHI",):
            C = max(C, 3)
        if dt in ("FINANCIAL",):
            I = max(I, 2)
        return {"C": C, "I": I, "A": A}

    def aggregate_column_from_values(self, values: List[str]) -> Dict[str, Any]:
        """Aggregate value-level classifications to a column-level decision.

        Returns: {"dominant_type", "type_counts", "coverage_pct", "risk_score", "suggested_cia"}
        """
        if not values:
            return {"dominant_type": None, "type_counts": {}, "coverage_pct": 0.0, "risk_score": 0.0, "suggested_cia": {"C":0,"I":0,"A":0}}
        preds = self.classify_values_batch(values)
        from collections import Counter
        counts = Counter()
        total = 0
        any_sensitive = 0
        weight_map = {"SSN": 1.0, "PHI": 0.9, "PCI": 0.9, "PII": 0.7, "Email": 0.6, "Phone": 0.6, "Financial": 0.6}
        risk_acc = 0.0
        for p in preds:
            ts = p.get("types") or []
            if ts:
                any_sensitive += 1
            for t in ts:
                counts[t] += 1
                risk_acc += weight_map.get(str(t), 0.3) * max(0.5, float(p.get("confidence") or 0.0))
            total += 1
        # determine dominant type at a coarse category level preference
        # collapse subtypes into categories
        category_alias = {
            "SSN": "PII",
            "Email": "PII",
            "Phone": "PII",
        }
        cat_counts = Counter()
        for k, v in counts.items():
            cat = category_alias.get(str(k), str(k))
            cat_counts[cat] += v
        # Priority: PCI > PHI > PII > Financial > Auth > other, then by count
        if cat_counts:
            def _priority_key(item):
                cat, cnt = item
                order = {"PCI": 0, "PHI": 1, "PII": 2, "Financial": 3, "Auth": 4}
                return (order.get(str(cat), 9), -cnt)
            dominant_type = sorted(cat_counts.items(), key=_priority_key)[0][0]
        else:
            dominant_type = None
        coverage = (float(any_sensitive) / float(total)) if total else 0.0
        # simple normalized risk 0..1
        max_possible = float(total) * 1.0
        risk_score = min(1.0, (risk_acc / max(1.0, max_possible)))
        cia = self._suggest_cia_from_type(dominant_type or "")
        return {
            "dominant_type": dominant_type,
            "type_counts": dict(cat_counts),
            "coverage_pct": round(coverage, 2),
            "risk_score": round(risk_score, 2),
            "suggested_cia": cia,
        }

    def map_compliance_categories(self, detected_type: str) -> List[str]:
        """Return a prioritized list of frameworks for a detected category.
        Rules:
        - PCI -> PCI DSS
        - PHI -> HIPAA
        - PII -> GDPR, CCPA
        - Financial (generic) -> SOX
        - Auth/Credentials -> SOC (security)
        - Confidential catch-all -> SOC
        """
        dt = (detected_type or '').upper()
        if dt == 'PCI':
            return ["PCI DSS"]
        if dt == 'PHI':
            return ["HIPAA"]
        if dt == 'PII':
            return ["GDPR", "CCPA"]
        if dt == 'FINANCIAL':
            return ["SOX"]
        if dt == 'AUTH':
            return ["SOC"]
        if dt == 'CONFIDENTIAL':
            return ["SOC"]
        return ["Internal/Other"]

    # --- Cortex integration helpers (optional) ---
    def _cortex_available(self) -> bool:
        """Best-effort probe to check if Cortex functions are available to the current role."""
        try:
            # Probe for a known Cortex function name via INFORMATION_SCHEMA or handle lack of access gracefully
            # Fall back to a simple query if INFORMATION_SCHEMA access is restricted
            try:
                _ = snowflake_connector.execute_query(
                    f"""
                    SELECT COUNT(*) AS CNT
                    FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.FUNCTIONS
                    WHERE FUNCTION_NAME ILIKE '%CLASSIFY_TEXT%'
                    LIMIT 1
                    """
                ) or []
                # If query succeeded, assume potential availability (not definitive). We'll still guard calls.
                return True
            except Exception:
                # If we can't check functions, treat Cortex as unavailable to avoid runtime errors
                return False
        except Exception:
            return False

    def _cortex_enhanced_classification(self, table_meta: Dict[str, Any], sample_df: pd.DataFrame) -> Dict[str, Any]:
        """Use Cortex functions to improve classification from textual signals when available.
        Strategy: build small text corpus from column names and few sample rows; call CLASSIFY_TEXT/EXTRACT heuristically.
        """
        # If Cortex is not available, short-circuit gracefully to avoid UNKNOWN FUNCTION errors
        try:
            if not self._cortex_available():
                return {}
        except Exception:
            return {}
        # Select text-like columns
        text_cols: List[str] = []
        try:
            # Fetch columns again to filter textual
            db = table_meta.get('TABLE_CATALOG') or table_meta.get('TABLE_CATALOG')
            schema = table_meta.get('TABLE_SCHEMA')
            table = table_meta.get('TABLE_NAME')
            cols = snowflake_connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
                ORDER BY ORDINAL_POSITION
                """
            ) or []
            for c in cols:
                dt = (c.get('DATA_TYPE') or '').upper()
                if any(tok in dt for tok in ['CHAR', 'TEXT', 'STRING', 'VARCHAR']):
                    text_cols.append(c.get('COLUMN_NAME'))
        except Exception:
            pass
        if not sample_df.empty and not text_cols:
            # No explicit textual columns; take first few columns as text
            text_cols = sample_df.columns[:3].tolist()

        corpus: List[str] = []
        try:
            # Build corpus from column names and up to 10 sample values per text col
            corpus.extend([str(c) for c in text_cols])
            for c in text_cols:
                if c in sample_df.columns:
                    vals = sample_df[c].astype(str).dropna().head(10).tolist()
                    corpus.extend(vals)
        except Exception:
            pass

        if not corpus:
            raise ValueError("No textual signals for Cortex classification")

        # Use CLASSIFY_TEXT on concatenated text chunks; simple majority label
        labels = []
        frameworks = set()
        try:
            for chunk in corpus[:20]:
                # Map to our policy labels using a prompt classification pattern
                sql = f"SELECT CLASSIFY_TEXT('Public|Internal|Restricted|Confidential', %(txt)s) AS LBL"
                res = snowflake_connector.execute_query(sql, {"txt": chunk}) or []
                lbl = (res[0].get('LBL') if res else None) or 'Internal'
                labels.append(lbl)
                # Extract entities for framework hints
                try:
                    ext = snowflake_connector.execute_query("SELECT EXTRACT(%(txt)s) AS ENT", {"txt": chunk}) or []
                    ent = (ext[0].get('ENT') if ext else {})
                    text_up = str(chunk).upper()
                    if any(k in text_up for k in ['SSN','EMAIL','PHONE','ADDRESS','DOB','PII','CUSTOMER','PERSON','EMPLOYEE']):
                        frameworks.add('GDPR')
                    if any(k in text_up for k in ['HIPAA','PHI','MEDICAL','HEALTH']):
                        frameworks.add('HIPAA')
                    if any(k in text_up for k in ['SOX','GAAP','IFRS','AUDIT','LEDGER','PAYROLL','GL']):
                        frameworks.add('SOX')
                except Exception:
                    pass
        except Exception:
            # If Cortex functions not available, propagate to fallback
            raise

        # Compute majority label and confidence as fraction
        from collections import Counter
        cnt = Counter(labels)
        if not cnt:
            raise ValueError("Cortex produced no labels")
        best_lbl, best_n = cnt.most_common(1)[0]
        conf = float(best_n) / float(len(labels))
        return {
            'classification': best_lbl,
            'compliance_frameworks': sorted(frameworks),
            'confidence': conf,
            'features': {'cortex_insights': {'label_votes': cnt, 'samples': len(labels)}}
        }


# Global instance
ai_classification_service = AIClassificationService()