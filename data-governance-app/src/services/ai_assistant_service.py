from typing import List, Dict, Any, Optional, Tuple

import logging
from src.connectors.snowflake_connector import snowflake_connector
from src.services.decision_matrix_service import validate as dm_validate
from src.services.tagging_service import tagging_service
from src.services.audit_service import audit_service
from src.services.classification_decision_service import classification_decision_service
from src.services.governance_db_resolver import resolve_governance_db

logger = logging.getLogger(__name__)

class ai_assistant_service:
    """AI Assistant for automated data classification with semantic detection, CIA recommendation, validation, and governance tagging."""
    
    def initialize_sensitive_detection(self) -> Dict[str, Any]:
        """Initialize the sensitive detection system and return backend information.
        
        Returns:
            Dict containing backend information including:
            - backend: str - The backend being used (e.g., 'sentence-transformers')
            - categories: List[str] - List of supported sensitivity categories
            - status: str - Status message
        """
        try:
            # Check if we're using sentence-transformers
            try:
                from sentence_transformers import SentenceTransformer
                self._embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                backend = 'sentence-transformers'
            except ImportError:
                # Fallback to a simpler implementation if sentence-transformers is not available
                self._embedding_model = None
                backend = 'tfidf'  # or another fallback method
            
            # Initialize category centroids if not already done
            if not hasattr(self, '_category_centroids'):
                self._category_centroids = {
                    'PERSONAL_DATA': None,
                    'FINANCIAL_DATA': None,
                    'REGULATORY_DATA': None,
                    'PROPRIETARY_DATA': None,
                    'INTERNAL': None,
                    'PUBLIC_DATA': None
                }
            
            return {
                'backend': backend,
                'categories': list(self._category_centroids.keys()),
                'status': 'initialized',
                'model': str(self._embedding_model) if hasattr(self, '_embedding_model') else 'none'
            }
            
        except Exception as e:
            logger.error(f"Error initializing sensitive detection: {e}")
            return {
                'backend': 'none',
                'categories': [],
                'status': f'error: {str(e)}',
                'error': str(e)
            }

    # Category priority for tie-breaks: higher index = higher priority
    CATEGORY_PRIORITY = {
        'REGULATORY_DATA': 6,
        'FINANCIAL_DATA': 5,
        'PERSONAL_DATA': 4,
        'PROPRIETARY_DATA': 3,
        'INTERNAL': 2,
        'PUBLIC_DATA': 1,
    }

    # CIA mappings per category
    CIA_MAPPING = {
        'PERSONAL_DATA': (3, 2, 2),  # PII: C3 (Very High), I2 (High), A2 (Medium)
        'FINANCIAL_DATA': (3, 3, 2),  # SOX: C3 (High), I3 (Critical), A2 (Medium)
        'PROPRIETARY_DATA': (2, 2, 1),  # C2, I2, A1
        'REGULATORY_DATA': (3, 3, 2),  # SOC2/HIPAA: C3, I3, A2 (Safe default)
        'INTERNAL': (1, 1, 1),  # C1, I1, A1
        'PUBLIC_DATA': (0, 0, 0),  # C0, I0, A0
    }

    # Detection threshold
    DETECTION_THRESHOLD = 0.7

    # Map internal semantic categories to Avendra canonical categories
    _SEMANTIC_TO_AVENDRA = {
        'PII': 'PERSONAL_DATA',
        'Financial': 'FINANCIAL_DATA',
        'Regulatory': 'REGULATORY_DATA',
        'TradeSecret': 'PROPRIETARY_DATA',
        'Internal': 'INTERNAL',
        'Public': 'PUBLIC_DATA',
        'SOX': 'FINANCIAL_DATA',
        'SOC2': 'REGULATORY_DATA',
    }

    # Compliance hints per Avendra category
    _COMPLIANCE_MAP = {
        'PERSONAL_DATA': ['GDPR', 'CCPA'],
        'FINANCIAL_DATA': ['SOX'],
        'REGULATORY_DATA': ['HIPAA', 'PCI-DSS'],
        'PROPRIETARY_DATA': ['NDA', 'IP'],
        'INTERNAL': ['Internal Policy'],
        'PUBLIC_DATA': ['Public Policy'],
    }

    def run_automated_classification(self, database: str, schema: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Run automated classification on discovered assets.

        Args:
            database: Database to scan
            schema: Optional schema filter
            limit: Max assets to process

        Returns:
            List of classification results
        """
        results = []

        # 1. Table Discovery & Metadata Extraction
        assets = self._discover_assets(database, schema, limit)
        if not assets:
            logger.warning("No assets discovered")
            return results

        # 2-3. Semantic Category Detection with Fallback & Tie-Break
        for asset in assets:
            try:
                # Derive business context
                business_context = self._derive_business_context(asset)

                # Detect categories with scores
                category_scores, failure_reason, category_compliance = self._detect_semantic_categories(business_context, asset)

                # Apply fallback and tie-break logic
                category, confidence = self._apply_fallback_and_tiebreak(category_scores)

                # 4. CIA Classification Recommendation
                c, i, a = self._recommend_cia(category, category_scores)

                # 5. Validation & Policy Enforcement
                label = self._map_cia_to_label(c, i, a)
                validation_status, issues = self._validate_classification(asset['full_name'], label, c, i, a)

                # 6. Workflow Routing & Review
                route = self._determine_routing(confidence, c, category_scores)

                # 7. Apply or Queue
                application_status = self._apply_or_queue(asset['full_name'], label, c, i, a, route, category, confidence, business_context, category_scores)

                # 8. Audit Logging
                self._audit_classification(asset['full_name'], category, confidence, label, c, i, a, route, application_status, failure_reason)

                compliance = category_compliance.get(category, [])
                label_emoji_map = {
                    'Confidential': '🟥 Confidential',
                    'Restricted': '🟧 Restricted',
                    'Internal': '🟨 Internal',
                    'Public': '🟩 Public',
                }
                label_with_emoji = label_emoji_map.get(label, label)

                # Prepare SQL preview for tagging
                try:
                    sql_preview = tagging_service.generate_tag_sql_for_object(
                        asset['full_name'], 'TABLE', {
                            'DATA_CLASSIFICATION': label,
                            'CONFIDENTIALITY_LEVEL': str(c),
                            'INTEGRITY_LEVEL': str(i),
                            'AVAILABILITY_LEVEL': str(a),
                        }
                    )
                except Exception:
                    sql_preview = None

                results.append({
                    'asset': asset,
                    'business_context': business_context,
                    'category': category,
                    'confidence': confidence,
                    'c': c,
                    'i': i,
                    'a': a,
                    'label': label,
                    'label_emoji': label_with_emoji,
                    'validation_status': validation_status,
                    'issues': issues,
                    'route': route,
                    'application_status': application_status,
                    'failure_reason': failure_reason,
                    'sql_preview': sql_preview,
                    'compliance': compliance,
                })

            except Exception as e:
                logger.error(f"Failed to classify {asset['full_name']}: {e}")
                results.append({
                    'asset': asset,
                    'error': str(e),
                    'category': 'INTERNAL',
                    'confidence': 0.0,
                    'c': 1, 'i': 1, 'a': 1,
                    'label': 'Internal',
                    'validation_status': 'ERROR',
                    'route': 'ENHANCED_REVIEW',
                    'application_status': 'FAILED'
                })

        return results

    def _discover_assets(self, database: str, schema: Optional[str], limit: int) -> List[Dict[str, Any]]:
        """Discover tables and extract metadata."""
        try:
            schema_filter = f"AND TABLE_SCHEMA = %(schema)s" if schema else ""
            query = f"""
                SELECT
                    TABLE_CATALOG,
                    TABLE_SCHEMA,
                    TABLE_NAME,
                    COMMENT,
                    CREATED,
                    LAST_ALTERED
                FROM {database}.INFORMATION_SCHEMA.TABLES
                WHERE TABLE_TYPE = 'BASE TABLE'
                  AND TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
                  {schema_filter}
                ORDER BY LAST_ALTERED DESC
                LIMIT {limit}
            """
            params = {'schema': schema} if schema else {}
            rows = snowflake_connector.execute_query(query, params) or []

            assets = []
            for row in rows:
                assets.append({
                    'database': row['TABLE_CATALOG'],
                    'schema': row['TABLE_SCHEMA'],
                    'table': row['TABLE_NAME'],
                    'full_name': f"{row['TABLE_CATALOG']}.{row['TABLE_SCHEMA']}.{row['TABLE_NAME']}",
                    'comment': row.get('COMMENT'),
                    'created': row.get('CREATED'),
                    'last_altered': row.get('LAST_ALTERED')
                })
            return assets
        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")
            return []

    def _derive_business_context(self, asset: Dict[str, Any]) -> str:
        """Derive business context from metadata + glossary/policy + light samples."""
        context_parts: List[str] = []

        # Table comment/name/schema
        base_descr = []
        if asset.get('comment'):
            base_descr.append(str(asset['comment']))
        base_descr.append(f"Table {asset['table']} in schema {asset['schema']}")
        context_parts.append("; ".join(base_descr))

        # Column names and types (limited)
        columns: List[Dict[str, Any]] = []
        try:
            columns = snowflake_connector.execute_query(f"""
                SELECT COLUMN_NAME, DATA_TYPE, COMMENT
                FROM {asset['database']}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(schema)s AND TABLE_NAME = %(table)s
                ORDER BY ORDINAL_POSITION
                LIMIT 15
            """, {'schema': asset['schema'], 'table': asset['table']}) or []
            if columns:
                col_bits = []
                for col in columns[:15]:
                    desc = col.get('COLUMN_NAME')
                    if col.get('COMMENT'):
                        desc += f" ({col['COMMENT']})"
                    if col.get('DATA_TYPE'):
                        desc += f" : {col['DATA_TYPE']}"
                    col_bits.append(desc)
                context_parts.append("Columns: " + ", ".join(col_bits))
        except Exception as e:
            logger.warning(f"Failed to get column metadata for {asset['full_name']}: {e}")

        # Light sample values for top few columns (best-effort)
        try:
            sample_cols = [c.get('COLUMN_NAME') for c in (columns or []) if c.get('COLUMN_NAME')][:3]
            if sample_cols:
                cols_csv = ", ".join([f'"{c}"' for c in sample_cols])
                # Use SAMPLE ROWS correctly (Snowflake: FROM table SAMPLE (n ROWS))
                q = f"SELECT {cols_csv} FROM {asset['full_name']} SAMPLE (25 ROWS) LIMIT 5"
                sample_rows = snowflake_connector.execute_query(q) or []
                if sample_rows:
                    # Flatten a couple of sample values
                    first = sample_rows[0]
                    sv = "; ".join([f"{k}={str(v)[:64]}" for k, v in first.items() if k in sample_cols])
                    if sv:
                        context_parts.append("Samples: " + sv)
        except Exception:
            pass

        # Glossary/policy snippets (best-effort)
        try:
            use_gov = bool(getattr(self, 'use_governance_glossary', True))
            if use_gov:
                gov_db = resolve_governance_db()
                if gov_db:
                    gloss = snowflake_connector.execute_query(
                        f"SELECT TERM_NAME, DEFINITION FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.BUSINESS_GLOSSARY LIMIT 5"
                    ) or []
                    pol = snowflake_connector.execute_query(
                        f"SELECT POLICY_NAME, EXCERPT FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.POLICY_TEXT LIMIT 5"
                    ) or []
                    if gloss:
                        gtxt = "; ".join([f"{g.get('TERM_NAME')}: {str(g.get('DEFINITION') or '')[:80]}" for g in gloss[:3]])
                        context_parts.append("Glossary: " + gtxt)
                    if pol:
                        ptxt = "; ".join([f"{p.get('POLICY_NAME')}: {str(p.get('EXCERPT') or '')[:80]}" for p in pol[:2]])
                        context_parts.append("Policy: " + ptxt)
        except Exception:
            pass

        business_context = " \n".join([s for s in context_parts if s])
        return business_context or f"Table {asset['table']} in {asset['schema']} schema"

    def _detect_semantic_categories(self, business_context: str, asset: Dict[str, Any]) -> Tuple[Dict[str, float], Optional[str], Dict[str, List[str]]]:
        """Detect semantic categories with confidence scores using embeddings + fallback.
        Returns a mapping of Avendra categories to scores, failure_reason, and compliance.
        """
        scores: Dict[str, float] = {}
        compliance: Dict[str, List[str]] = {}
        failure_reason: Optional[str] = None

        try:
            # Build enriched semantic context for the asset using metadata, samples, glossary, policy
            try:
                from src.services.ai_classification_service import ai_classification_service as _ai_cls  # lazy import to avoid circulars
            except Exception:
                _ai_cls = None

            enriched = ''
            if _ai_cls is not None:
                try:
                    enriched = _ai_cls.build_enriched_context(asset['full_name'])
                except Exception:
                    enriched = ''

            # Optionally add a few per-column contexts for stronger signal
            col_ctx_blob = ''
            if _ai_cls is not None:
                try:
                    col_ctx = _ai_cls.build_column_contexts(asset['full_name'], sample_rows=5) or {}
                    if col_ctx:
                        top_cols = list(col_ctx.keys())[:3]
                        col_lines = [col_ctx[c] for c in top_cols if c in col_ctx]
                        if col_lines:
                            col_ctx_blob = "\n" + "\n".join(col_lines)
                except Exception:
                    col_ctx_blob = ''

            context = "\n".join([s for s in [business_context, enriched] if s]) + col_ctx_blob

            # Semantic embedding similarity against governance categories (MiniLM + hybrid)
            # Use enriched context directly with the governance-aware matcher
            matches = []
            if _ai_cls is not None:
                try:
                    matches = _ai_cls._get_semantic_matches_gov(context) or []
                except Exception:
                    matches = []
            for m in (matches or []):
                try:
                    src_cat = str(m.get('category') or '')
                    conf = float(m.get('confidence') or 0.0)
                    comp = m.get('compliance', [])
                except Exception:
                    continue
                # Preserve Avendra-native categories; otherwise map internal -> Avendra
                av_cat = self._SEMANTIC_TO_AVENDRA.get(src_cat, src_cat if src_cat in self.CIA_MAPPING else None)
                if not av_cat:
                    continue
                # Keep max confidence per target category
                scores[av_cat] = max(scores.get(av_cat, 0.0), conf)
                # Merge compliance
                if av_cat not in compliance:
                    compliance[av_cat] = []
                compliance[av_cat].extend(comp)
                compliance[av_cat] = list(set(compliance[av_cat]))  # dedupe

            # Keyword/pattern reinforcement on the combined context
            self._add_keyword_scores(context, scores)

            if not scores:
                failure_reason = 'no_metadata'
            else:
                max_score = max(scores.values())
                if max_score < self.DETECTION_THRESHOLD:
                    failure_reason = 'low_confidence'

        except Exception as e:
            logger.warning(f"AI classification failed for {asset['full_name']}: {e}")
            failure_reason = 'classification_error'

        return scores, failure_reason, compliance

    def _add_keyword_scores(self, text: str, scores: Dict[str, float]):
        """Add keyword-based scores."""
        text_upper = text.upper()

        # Simple keyword mappings
        keyword_mappings = {
            'PERSONAL_DATA': ['SSN', 'SOCIAL SECURITY', 'EMAIL', 'PHONE', 'ADDRESS', 'DOB', 'PERSON', 'EMPLOYEE', 'CUSTOMER'],
            'FINANCIAL_DATA': ['SALARY', 'PAYROLL', 'ACCOUNT', 'BANK', 'CREDIT', 'DEBIT', 'TRANSACTION', 'GL', 'LEDGER'],
            'REGULATORY_DATA': ['GDPR', 'CCPA', 'HIPAA', 'PCI', 'SOX', 'REGULATORY', 'COMPLIANCE'],
            'PROPRIETARY_DATA': ['PROPRIETARY', 'CONFIDENTIAL', 'TRADE SECRET', 'IP', 'INTELLECTUAL PROPERTY']
        }

        for category, keywords in keyword_mappings.items():
            if any(kw in text_upper for kw in keywords):
                scores[category] = max(scores.get(category, 0.0), 0.7)

    def _apply_fallback_and_tiebreak(self, scores: Dict[str, float]) -> Tuple[str, float]:
        """Apply fallback logic and tie-breaking."""
        if not scores:
            return 'INTERNAL', 0.0

        # Find max score
        max_score = max(scores.values())
        candidates = [cat for cat, score in scores.items() if score == max_score]

        if len(candidates) == 1:
            return candidates[0], max_score

        # Tie-break by priority
        candidates.sort(key=lambda c: self.CATEGORY_PRIORITY.get(c, 0), reverse=True)
        return candidates[0], max_score

    def _recommend_cia(self, category: str, category_scores: Dict[str, float]) -> Tuple[int, int, int]:
        """Recommend CIA levels based on category and detected sensitivities."""
        c, i, a = self.CIA_MAPPING.get(category, (1, 1, 1))

        # Additional logic for sensitive categories
        detected_cats = set(category_scores.keys())

        # PII Rule: Confidentiality must ALWAYS be C3 (Very High)
        if category == 'PERSONAL_DATA' or 'PERSONAL_DATA' in detected_cats:
            c = 3
        
        # SOX Rule: Integrity must ALWAYS be I3 (Critical)
        if category == 'FINANCIAL_DATA' or 'FINANCIAL_DATA' in detected_cats:
            i = 3
            # SOX also implies High Confidentiality (C2/C3)
            c = max(c, 2)

        # SOC2 Rule: Depends on trust principle (mapped to REGULATORY_DATA)
        # Default for REGULATORY_DATA is (3, 3, 2) which is safe.
        # If we could detect specific principles, we would adjust here.
        
        return c, i, a

    def _map_cia_to_label(self, c: int, i: int, a: int) -> str:
        """Map CIA levels to classification label."""
        levels = ['Public', 'Internal', 'Restricted', 'Confidential']
        max_level = max(c, i, a)
        return levels[min(max_level, 3)]

    def _validate_classification(self, asset_fqn: str, label: str, c: int, i: int, a: int) -> Tuple[str, List[str]]:
        """Validate classification against policy."""
        issues = []

        # Decision matrix validation
        ok, reasons = dm_validate(label, c, i, a)
        if not ok:
            issues.extend(reasons)

        # Additional checks
        try:
            # Check if asset exists
            exists = snowflake_connector.execute_query(f"SELECT 1 FROM {asset_fqn} LIMIT 1")
            if not exists:
                issues.append("Asset not found")
        except Exception:
            issues.append("Asset access failed")

        status = 'VALID' if not issues else ('REVIEW_REQUIRED' if len(issues) < 3 else 'INVALID')
        return status, issues

    def _determine_routing(self, confidence: float, c: int, category_scores: Dict[str, float]) -> str:
        """Determine workflow routing based on confidence and sensitivity."""
        sensitive = c >= 2 or any(score > 0.8 for score in category_scores.values())

        if confidence >= 0.85 and not sensitive:
            return 'AUTO_APPROVE'
        elif confidence >= 0.7:
            return 'EXPEDITED_REVIEW'
        elif confidence >= 0.5:
            return 'STANDARD_REVIEW'
        else:
            return 'ENHANCED_REVIEW'

    def _apply_or_queue(self, asset_fqn: str, label: str, c: int, i: int, a: int, route: str, category: str, confidence: float, business_context: str, category_scores: Dict[str, float]) -> str:
        """Apply tags or queue for review."""
        try:
            if route == 'AUTO_APPROVE':
                tags = {
                    'DATA_CLASSIFICATION': label,
                    'CONFIDENTIALITY_LEVEL': str(c),
                    'INTEGRITY_LEVEL': str(i),
                    'AVAILABILITY_LEVEL': str(a)
                }
                tagging_service.apply_tags_to_object(asset_fqn, 'TABLE', tags)
                self._update_governance_tables(asset_fqn, category, label, c, i, a, 'APPLIED', business_context)
                return 'APPLIED'
            else:
                # Queue for review
                rationale = f"Detected {category} with confidence {confidence:.3f}"
                if category_scores:
                    top_scores = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)[:3]
                    rationale += f". Top categories: {', '.join([f'{cat} ({score:.2f})' for cat, score in top_scores])}"
                rationale += f". Routed to {route} due to confidence and sensitivity."
                classification_decision_service.record(
                    asset_full_name=asset_fqn,
                    decision_by='AI_ASSISTANT',
                    source='AI_ASSISTANT',
                    status='Submitted',
                    label=label,
                    c=c, i=i, a=a,
                    rationale=rationale,
                    details={'route': route, 'business_context': business_context}
                )
                return 'QUEUED_FOR_REVIEW'
        except Exception as e:
            logger.error(f"Failed to apply/queue {asset_fqn}: {e}")
            return 'FAILED'

    def _update_governance_tables(self, asset_fqn: str, category: str, label: str, c: int, i: int, a: int, status: str, business_context: str):
        """Update governance tables with classification results."""
        try:
            db = resolve_governance_db()
            if not db:
                return

            # Update ASSETS table
            snowflake_connector.execute_non_query(f"""
                MERGE INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS t
                USING (
                    SELECT %(fqn)s AS FULLY_QUALIFIED_NAME,
                           %(cat)s AS CATEGORY,
                           %(label)s AS CLASSIFICATION_LABEL,
                           %(c)s AS CONFIDENTIALITY_LEVEL,
                           %(i)s AS INTEGRITY_LEVEL,
                           %(a)s AS AVAILABILITY_LEVEL,
                           %(status)s AS STATUS,
                           %(context)s AS BUSINESS_PURPOSE
                ) s
                ON t.FULLY_QUALIFIED_NAME = s.FULLY_QUALIFIED_NAME
                WHEN MATCHED THEN UPDATE SET
                    CLASSIFICATION_LABEL = s.CLASSIFICATION_LABEL,
                    CONFIDENTIALITY_LEVEL = s.CONFIDENTIALITY_LEVEL,
                    INTEGRITY_LEVEL = s.INTEGRITY_LEVEL,
                    AVAILABILITY_LEVEL = s.AVAILABILITY_LEVEL,
                    LAST_MODIFIED_TIMESTAMP = CURRENT_TIMESTAMP(),
                    BUSINESS_PURPOSE = s.BUSINESS_PURPOSE
                WHEN NOT MATCHED THEN INSERT (
                    ASSET_ID, FULLY_QUALIFIED_NAME, ASSET_TYPE, CLASSIFICATION_LABEL,
                    CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
                    BUSINESS_PURPOSE, CREATED_TIMESTAMP
                ) VALUES (
                    UUID_STRING(), s.FULLY_QUALIFIED_NAME, 'TABLE', s.CLASSIFICATION_LABEL,
                    s.CONFIDENTIALITY_LEVEL, s.INTEGRITY_LEVEL, s.AVAILABILITY_LEVEL,
                    s.BUSINESS_PURPOSE, CURRENT_TIMESTAMP()
                )
            """, {
                'fqn': asset_fqn,
                'cat': category,
                'label': label,
                'c': c, 'i': i, 'a': a,
                'status': status,
                'context': business_context
            })
        except Exception as e:
            logger.error(f"Failed to update governance tables for {asset_fqn}: {e}")

    def _audit_classification(self, asset_fqn: str, category: str, confidence: float, label: str, c: int, i: int, a: int, route: str, status: str, failure_reason: Optional[str] = None):
        """Log classification event to audit."""
        try:
            audit_service.log(
                user_id='AI_ASSISTANT',
                action='AI_CLASSIFICATION',
                resource_type='ASSET',
                resource_id=asset_fqn,
                details={
                    'category': category,
                    'confidence': confidence,
                    'label': label,
                    'cia': f"{c}/{i}/{a}",
                    'route': route,
                    'status': status,
                    'failure_reason': failure_reason
                }
            )
        except Exception as e:
            logger.error(f"Audit logging failed for {asset_fqn}: {e}")

# Singleton instance
ai_assistant_service = ai_assistant_service()