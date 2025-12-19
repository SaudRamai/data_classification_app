"""
Comprehensive Detection Methods for Snowflake-native AI Assistant System

This module implements the complete pipeline for automatic data asset discovery,
semantic category detection, CIA classification, and governance tagging with
full validation, review routing, and audit logging.
"""

import sys
import os
import json
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timezone
from collections import defaultdict
import logging

# Add project root to path
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.connectors.snowflake_connector import snowflake_connector
from src.services.ai_classification_service import ai_classification_service
from src.services.tagging_service import tagging_service
from src.services.classification_decision_service import classification_decision_service
from src.services.audit_service import audit_service
from src.services.exception_service import exception_service
from src.config.settings import settings

logger = logging.getLogger(__name__)

class ComprehensiveDetectionService:
    """
    Snowflake-native AI assistant system for automatic data classification.

    Implements the complete pipeline:
    1. Table Discovery & Metadata Extraction
    2. Semantic Category Detection
    3. Fallback & Tie-Break Logic
    4. CIA Classification Recommendation
    5. Validation & Policy Enforcement
    6. Workflow Routing & Review
    7. Snowflake Tagging & Metadata Updates
    8. Audit Logging & Monitoring
    """

    def __init__(self):
        """Initialize the comprehensive detection service."""
        self.ai_service = ai_classification_service
        self.tagging_service = tagging_service
        self.classification_decision_service = classification_decision_service
        self.audit_service = audit_service
        self.exception_service = exception_service

        # Configuration loaded from governance tables
        self._config = self._load_configuration()

        # Category priority for tie-breaking (Regulatory > Financial > Personal > Proprietary > Internal)
        self.category_priority = {
            'REGULATORY_DATA': 1,
            'FINANCIAL_DATA': 2,
            'PERSONAL_DATA': 3,
            'PROPRIETARY_DATA': 4,
            'INTERNAL': 5
        }

        # CIA classification matrix per category
        self.cia_matrix = {
            'PERSONAL_DATA': {'C': 'C2+', 'I': 'I3', 'A': 'A2'},
            'FINANCIAL_DATA': {'C': 'C2+', 'I': 'I3', 'A': 'A2'},
            'PROPRIETARY_DATA': {'C': 'C2', 'I': 'I2', 'A': 'A1'},
            'REGULATORY_DATA': {'C': 'C3', 'I': 'I3', 'A': 'A2'},
            'INTERNAL': {'C': 'C1', 'I': 'I1', 'A': 'A1'}
        }

    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from governance tables."""
        config = {
            'semantic_patterns': {},
            'keyword_patterns': {},
            'exclusion_patterns': {},
            'sensitivity_categories': {},
            'risk_assessments': {},
            'workflow_routing': {},
            'audit_settings': {}
        }

        try:
            if snowflake_connector:
                # Load semantic patterns - use correct table name
                try:
                    semantic_rows = snowflake_connector.execute_query("""
                        SELECT CATEGORY, PATTERN, EMBEDDING_VECTOR, THRESHOLD
                        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SEMANTIC_PATTERNS
                        WHERE IS_ACTIVE = TRUE
                    """) or []
                    config['semantic_patterns'] = {row['CATEGORY']: row for row in semantic_rows}
                except Exception:
                    logger.warning("SEMANTIC_PATTERNS table not available")

                # Load keyword patterns - use correct table name
                try:
                    keyword_rows = snowflake_connector.execute_query("""
                        SELECT CATEGORY, KEYWORD, PATTERN_TYPE, WEIGHT
                        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.KEYWORD_PATTERNS
                        WHERE IS_ACTIVE = TRUE
                    """) or []
                    config['keyword_patterns'] = {row['CATEGORY']: row for row in keyword_rows}
                except Exception:
                    logger.warning("KEYWORD_PATTERNS table not available")

                # Load exclusion patterns - use correct table name
                try:
                    exclusion_rows = snowflake_connector.execute_query("""
                        SELECT CATEGORY, PATTERN
                        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.EXCLUSION_PATTERNS
                        WHERE IS_ACTIVE = TRUE
                    """) or []
                    config['exclusion_patterns'] = {row['CATEGORY']: row for row in exclusion_rows}
                except Exception:
                    logger.warning("EXCLUSION_PATTERNS table not available")

                # Load sensitivity categories with thresholds - use correct table name
                try:
                    category_rows = snowflake_connector.execute_query("""
                        SELECT CATEGORY, CONFIDENCE_THRESHOLD, CIA_REQUIREMENTS
                        FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
                        WHERE IS_ACTIVE = TRUE
                    """) or []
                    config['sensitivity_categories'] = {row['CATEGORY']: row for row in category_rows}
                except Exception:
                    logger.warning("SENSITIVITY_CATEGORIES table not available")

        except Exception as e:
            logger.warning(f"Failed to load configuration from governance tables: {e}")

        return config

    # 1️⃣ Table Discovery & Metadata Extraction
    def discover_and_extract_metadata(self, database: str, schema_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query INFORMATION_SCHEMA.TABLES and INFORMATION_SCHEMA.COLUMNS to extract metadata.
        Enrich with governance metadata from ASSETS table.
        Preprocess text fields for semantic analysis.

        Returns unified metadata CTE containing contextual text for each asset.
        """
        try:
            # Base metadata query
            base_query = """
                SELECT
                    t.TABLE_CATALOG,
                    t.TABLE_SCHEMA,
                    t.TABLE_NAME,
                    t.TABLE_TYPE,
                    t.COMMENT as TABLE_COMMENT,
                    t.CREATED as CREATED_DATE,
                    c.COLUMN_NAME,
                    c.DATA_TYPE,
                    c.COLUMN_DEFAULT,
                    c.IS_NULLABLE,
                    c.COMMENT as COLUMN_COMMENT,
                    c.ORDINAL_POSITION
                FROM {database}.INFORMATION_SCHEMA.TABLES t
                LEFT JOIN {database}.INFORMATION_SCHEMA.COLUMNS c
                    ON t.TABLE_CATALOG = c.TABLE_CATALOG
                    AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
                    AND t.TABLE_NAME = c.TABLE_NAME
                WHERE t.TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA', 'SNOWFLAKE')
            """

            if schema_filter:
                base_query += f" AND t.TABLE_SCHEMA = '{schema_filter}'"

            base_query += " ORDER BY t.TABLE_CATALOG, t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION"

            metadata_rows = snowflake_connector.execute_query(base_query.format(database=database)) or []

            # Enrich with governance metadata
            enriched_metadata = []
            for row in metadata_rows:
                asset_key = f"{row['TABLE_CATALOG']}.{row['TABLE_SCHEMA']}.{row['TABLE_NAME']}"

                # Get governance metadata
                gov_metadata = self._get_governance_metadata(asset_key)

                # Preprocess text fields for semantic analysis
                contextual_text = self._preprocess_text_fields(row, gov_metadata)

                enriched_row = {
                    'asset_path': asset_key,
                    'table_metadata': row,
                    'governance_metadata': gov_metadata,
                    'contextual_text': contextual_text,
                    'processed_at': datetime.now(timezone.utc).isoformat()
                }

                enriched_metadata.append(enriched_row)

            return enriched_metadata

        except Exception as e:
            logger.error(f"Failed to discover and extract metadata: {e}")
            return []

    def _get_governance_metadata(self, asset_path: str) -> Dict[str, Any]:
        """Enrich context using governance metadata tables."""
        try:
            gov_query = """
                SELECT
                    BUSINESS_UNIT,
                    DATA_OWNER,
                    DATA_STEWARD,
                    CLASSIFICATION_LEVEL,
                    CIA_CONF,
                    CIA_INT,
                    CIA_AVAIL,
                    USAGE_FREQUENCY,
                    ROW_COUNT,
                    DESCRIPTION,
                    TAGS
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                WHERE FULL_NAME = %(asset_path)s
                LIMIT 1
            """

            gov_rows = snowflake_connector.execute_query(gov_query, {'asset_path': asset_path}) or []
            return gov_rows[0] if gov_rows else {}

        except Exception as e:
            logger.warning(f"Failed to get governance metadata for {asset_path}: {e}")
            return {}

    def _preprocess_text_fields(self, table_row: Dict[str, Any], gov_metadata: Dict[str, Any]) -> str:
        """Preprocess text fields (lowercase, tokenize, lemmatize, deduplicate)."""
        text_parts = []

        # Table and column names
        if table_row.get('TABLE_NAME'):
            text_parts.append(table_row['TABLE_NAME'].lower())
        if table_row.get('COLUMN_NAME'):
            text_parts.append(table_row['COLUMN_NAME'].lower())

        # Comments and descriptions
        if table_row.get('TABLE_COMMENT'):
            text_parts.append(table_row['TABLE_COMMENT'].lower())
        if table_row.get('COLUMN_COMMENT'):
            text_parts.append(table_row['COLUMN_COMMENT'].lower())
        if gov_metadata.get('DESCRIPTION'):
            text_parts.append(gov_metadata['DESCRIPTION'].lower())

        # Business context
        if gov_metadata.get('BUSINESS_UNIT'):
            text_parts.append(gov_metadata['BUSINESS_UNIT'].lower())
        if gov_metadata.get('DATA_OWNER'):
            text_parts.append(gov_metadata['DATA_OWNER'].lower())

        # Combine and preprocess
        combined_text = ' '.join(text_parts)

        # Tokenize, lowercase, remove punctuation, deduplicate
        tokens = re.findall(r'\b\w+\b', combined_text.lower())
        unique_tokens = list(set(tokens))

        return ' '.join(unique_tokens)

    # 2️⃣ Semantic Category Detection
    def detect_semantic_categories(self, metadata_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect special data categories using NLP and semantic reasoning.
        Load configuration from SEMANTIC_PATTERNS, KEYWORD_PATTERNS, EXCLUSION_PATTERNS.
        Perform token/phrase matching, semantic similarity, and exclusion filtering.
        Aggregate multilayer scores and apply thresholds from SENSITIVITY_CATEGORIES.
        """
        results = []

        for metadata in metadata_list:
            asset_path = metadata['asset_path']
            contextual_text = metadata['contextual_text']

            # Initialize scores for each category
            category_scores = defaultdict(float)

            # Token/phrase matching (keyword-based detection)
            keyword_scores = self._perform_keyword_matching(contextual_text)
            for category, score in keyword_scores.items():
                category_scores[category] += score * 0.6  # Weight for keyword matching

            # Semantic similarity (cosine similarity embeddings)
            semantic_scores = self._perform_semantic_similarity(contextual_text)
            for category, score in semantic_scores.items():
                category_scores[category] += score * 0.4  # Weight for semantic similarity

            # Exclusion rule filtering
            filtered_scores = self._apply_exclusion_rules(category_scores, contextual_text)

            # Apply thresholds from SENSITIVITY_CATEGORIES
            final_category = self._apply_category_thresholds(filtered_scores)

            result = {
                'asset_path': asset_path,
                'category_scores': dict(filtered_scores),
                'detected_category': final_category,
                'confidence_score': max(filtered_scores.values()) if filtered_scores else 0.0,
                'detection_method': 'semantic_analysis'
            }

            results.append(result)

        return results

    def _perform_keyword_matching(self, text: str) -> Dict[str, float]:
        """Perform token/phrase matching using keyword patterns."""
        scores = defaultdict(float)

        for category, pattern_data in self._config['keyword_patterns'].items():
            keyword = pattern_data.get('KEYWORD', '').lower()
            pattern_type = pattern_data.get('PATTERN_TYPE', 'exact')
            weight = pattern_data.get('WEIGHT', 1.0)

            if pattern_type == 'exact':
                if keyword in text:
                    scores[category] += weight
            elif pattern_type == 'regex':
                if re.search(keyword, text, re.IGNORECASE):
                    scores[category] += weight
            elif pattern_type == 'fuzzy':
                # Simple fuzzy matching - contains with some tolerance
                if keyword in text or self._fuzzy_match(keyword, text):
                    scores[category] += weight * 0.8

        return dict(scores)

    def _perform_semantic_similarity(self, text: str) -> Dict[str, float]:
        """Perform semantic similarity using embeddings."""
        scores = {}

        try:
            # Use AI service for semantic matching if available
            if hasattr(self.ai_service, 'get_semantic_matches'):
                # Pass a valid category list understood by ai_classification_service
                candidate_categories = ['PII', 'Financial', 'Regulatory', 'TradeSecret', 'Internal', 'Public']
                matches = self.ai_service.get_semantic_matches(text, candidate_categories)
                # Map returned categories to this module's taxonomy
                cat_map = {
                    'PII': 'PERSONAL_DATA',
                    'Financial': 'FINANCIAL_DATA',
                    'Regulatory': 'REGULATORY_DATA',
                    'TradeSecret': 'PROPRIETARY_DATA',
                    'Internal': 'INTERNAL',
                    'Public': 'PUBLIC_DATA',
                }
                for match in matches:
                    raw_cat = (match.get('category') or '').strip()
                    mapped_cat = cat_map.get(raw_cat, raw_cat.upper())
                    confidence = float(match.get('confidence', 0.0) or 0.0)
                    if mapped_cat and confidence > 0:
                        # Keep the max confidence per category
                        prev = scores.get(mapped_cat, 0.0)
                        if confidence > prev:
                            scores[mapped_cat] = confidence
        except Exception as e:
            logger.warning(f"Semantic similarity failed: {e}")

        return scores

    def _apply_exclusion_rules(self, scores: Dict[str, float], text: str) -> Dict[str, float]:
        """Apply exclusion patterns to filter false positives."""
        filtered_scores = scores.copy()

        for category, exclusion_data in self._config['exclusion_patterns'].items():
            pattern = exclusion_data.get('PATTERN', '')
            if pattern and re.search(pattern, text, re.IGNORECASE):
                # Reduce score for categories that match exclusion patterns
                if category in filtered_scores:
                    filtered_scores[category] *= 0.5

        return filtered_scores

    def _apply_category_thresholds(self, scores: Dict[str, float]) -> Optional[str]:
        """Apply thresholds from SENSITIVITY_CATEGORIES."""
        if not scores:
            return None

        for category, threshold_data in self._config['sensitivity_categories'].items():
            threshold = threshold_data.get('CONFIDENCE_THRESHOLD', 0.7)
            if scores.get(category, 0.0) >= threshold:
                return category

        return None

    def _fuzzy_match(self, keyword: str, text: str, threshold: float = 0.8) -> bool:
        """Simple fuzzy matching implementation."""
        # Basic implementation - can be enhanced with proper fuzzy matching library
        keyword_words = set(keyword.split())
        text_words = set(text.split())

        if not keyword_words:
            return False

        intersection = keyword_words.intersection(text_words)
        return len(intersection) / len(keyword_words) >= threshold

    # 3️⃣ Fallback & Tie-Break Logic
    def apply_fallback_logic(self, detection_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Guarantee classification coverage, even when no strong semantic match is found.
        Apply fallback rules and tie-breaking logic.
        """
        processed_results = []

        for result in detection_results:
            category_scores = result.get('category_scores', {})
            detected_category = result.get('detected_category')

            # Fallback Rule 1: If no category exceeds threshold → classify as INTERNAL
            if not detected_category or max(category_scores.values()) < 0.5:
                detected_category = 'INTERNAL'
                result['fallback_reason'] = 'no_category_above_threshold'

            # Fallback Rule 2: Tie-breaking by priority
            elif len([s for s in category_scores.values() if s >= 0.5]) > 1:
                # Multiple categories above threshold - use priority
                candidates = [cat for cat, score in category_scores.items() if score >= 0.5]
                detected_category = min(candidates, key=lambda x: self.category_priority.get(x, 99))
                result['fallback_reason'] = 'tie_break_by_priority'

            # Fallback Rule 3: Infer from schema/table name
            if detected_category == 'INTERNAL' and 'fallback_reason' in result:
                inferred_category = self._infer_from_names(result['asset_path'])
                if inferred_category:
                    detected_category = inferred_category
                    result['fallback_reason'] = 'inferred_from_names'

            # Fallback Rule 4: Inherit from governed domain
            if detected_category == 'INTERNAL':
                inherited_category = self._inherit_from_domain(result['asset_path'])
                if inherited_category:
                    detected_category = inherited_category
                    result['fallback_reason'] = 'inherited_from_domain'

            result['final_category'] = detected_category
            processed_results.append(result)

        return processed_results

    def _infer_from_names(self, asset_path: str) -> Optional[str]:
        """Infer category from schema/table/column names."""
        path_parts = asset_path.lower().split('.')

        inference_rules = {
            'employee': 'PERSONAL_DATA',
            'customer': 'PERSONAL_DATA',
            'patient': 'PERSONAL_DATA',
            'user': 'PERSONAL_DATA',
            'person': 'PERSONAL_DATA',
            'contact': 'PERSONAL_DATA',
            'financial': 'FINANCIAL_DATA',
            'payment': 'FINANCIAL_DATA',
            'invoice': 'FINANCIAL_DATA',
            'salary': 'FINANCIAL_DATA',
            'account': 'FINANCIAL_DATA',
            'audit': 'REGULATORY_DATA',
            'compliance': 'REGULATORY_DATA',
            'gdpr': 'REGULATORY_DATA',
            'hipaa': 'REGULATORY_DATA',
            'pci': 'REGULATORY_DATA'
        }

        for part in path_parts:
            for keyword, category in inference_rules.items():
                if keyword in part:
                    return category

        return None

    def _inherit_from_domain(self, asset_path: str) -> Optional[str]:
        """Inherit default category from governed domain."""
        try:
            # Query governance tables for domain mappings
            domain_query = """
                SELECT DEFAULT_CATEGORY
                FROM DATA_CLASSIFICATION_DB.DATA_GOVERNANCE.DOMAIN_MAPPINGS
                WHERE DOMAIN_NAME = %(domain)s
                AND IS_ACTIVE = TRUE
                LIMIT 1
            """

            # Extract domain from asset path (simplified - could be more sophisticated)
            domain = asset_path.split('.')[1] if len(asset_path.split('.')) > 1 else None

            if domain:
                rows = snowflake_connector.execute_query(domain_query, {'domain': domain}) or []
                if rows:
                    return rows[0].get('DEFAULT_CATEGORY')

        except Exception as e:
            logger.warning(f"Failed to inherit from domain for {asset_path}: {e}")

        return None

    # 4️⃣ CIA Classification Recommendation
    def recommend_cia_levels(self, classification_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Assign CIA levels per detected or fallback category.
        Integrate with RISK_ASSESSMENTS for weighted adjustments.
        """
        results = []

        for result in classification_results:
            category = result.get('final_category', 'INTERNAL')

            # Base CIA levels from matrix
            base_cia = self.cia_matrix.get(category, self.cia_matrix['INTERNAL'])

            # Apply risk assessment adjustments
            adjusted_cia = self._adjust_cia_for_risk(base_cia, result)

            # Flag downgrade below policy minimums
            policy_check = self._validate_policy_minimums(category, adjusted_cia)

            result.update({
                'cia_levels': adjusted_cia,
                'policy_compliant': policy_check['compliant'],
                'policy_violations': policy_check['violations'],
                'risk_adjustments': policy_check.get('adjustments', [])
            })

            results.append(result)

        return results

    def _adjust_cia_for_risk(self, base_cia: Dict[str, str], result: Dict[str, Any]) -> Dict[str, str]:
        """Integrate with RISK_ASSESSMENTS for weighted adjustments."""
        try:
            asset_path = result['asset_path']

            # Query risk assessments
            risk_query = """
                SELECT RISK_LEVEL, CIA_ADJUSTMENTS
                FROM DATA_CLASSIFICATION_DB.DATA_GOVERNANCE.RISK_ASSESSMENTS
                WHERE ASSET_PATH = %(asset_path)s
                AND IS_ACTIVE = TRUE
                LIMIT 1
            """

            risk_rows = snowflake_connector.execute_query(risk_query, {'asset_path': asset_path}) or []

            if risk_rows:
                risk_level = risk_rows[0].get('RISK_LEVEL', 'MEDIUM')
                adjustments = risk_rows[0].get('CIA_ADJUSTMENTS', {})

                # Apply adjustments based on risk level
                if risk_level == 'HIGH':
                    # Increase confidentiality for high-risk assets
                    if base_cia['C'] in ['C1', 'C2']:
                        base_cia['C'] = 'C3'
                elif risk_level == 'LOW':
                    # Can potentially decrease for low-risk, but policy minimums apply
                    pass

                # Apply specific adjustments
                for component, adjustment in adjustments.items():
                    if component in base_cia and adjustment:
                        base_cia[component] = adjustment

        except Exception as e:
            logger.warning(f"Failed to adjust CIA for risk: {e}")

        return base_cia

    def _validate_policy_minimums(self, category: str, cia_levels: Dict[str, str]) -> Dict[str, Any]:
        """Validate CIA levels against policy minimums."""
        violations = []
        compliant = True

        # Category-specific minimums
        minimums = {
            'PERSONAL_DATA': {'C': 'C2', 'I': 'I3', 'A': 'A2'},
            'FINANCIAL_DATA': {'C': 'C2', 'I': 'I3', 'A': 'A2'},
            'PROPRIETARY_DATA': {'C': 'C2', 'I': 'I2', 'A': 'A1'},
            'REGULATORY_DATA': {'C': 'C3', 'I': 'I3', 'A': 'A2'},
            'INTERNAL': {'C': 'C1', 'I': 'I1', 'A': 'A1'}
        }

        required_minimums = minimums.get(category, minimums['INTERNAL'])

        # Compare levels (C1 < C2 < C3, I1 < I2 < I3, A1 < A2)
        level_order = {'C1': 1, 'C2': 2, 'C3': 3, 'I1': 1, 'I2': 2, 'I3': 3, 'A1': 1, 'A2': 2}

        for component in ['C', 'I', 'A']:
            current_level = cia_levels.get(component, 'C1')
            minimum_level = required_minimums.get(component, 'C1')

            current_value = level_order.get(current_level, 1)
            minimum_value = level_order.get(minimum_level, 1)

            if current_value < minimum_value:
                violations.append({
                    'component': component,
                    'current': current_level,
                    'required': minimum_level,
                    'violation': f'{component} level below policy minimum'
                })
                compliant = False

        return {
            'compliant': compliant,
            'violations': violations
        }

    # 5️⃣ Validation & Policy Enforcement
    def validate_and_enforce_policy(self, cia_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enforce classification policy and validate data integrity.
        Check table existence, permissions, CIA compliance, owner validation.
        """
        validated_results = []

        for result in cia_results:
            asset_path = result['asset_path']
            validation_status = 'VALID'
            validation_errors = []

            try:
                # Check table existence and permissions
                existence_check = self._validate_table_existence(asset_path)
                if not existence_check['exists']:
                    validation_errors.append(f"Table does not exist: {asset_path}")
                    validation_status = 'INVALID'

                if not existence_check['accessible']:
                    validation_errors.append(f"Insufficient permissions for: {asset_path}")
                    validation_status = 'INVALID'

                # Validate CIA compliance
                if result.get('policy_compliant') == False:
                    validation_errors.extend([v['violation'] for v in result.get('policy_violations', [])])
                    validation_status = 'REVIEW_REQUIRED'

                # Validate owner email format
                owner_check = self._validate_owner_email(asset_path)
                if not owner_check['valid']:
                    validation_errors.append(f"Invalid owner email: {owner_check['owner']}")
                    validation_status = 'REVIEW_REQUIRED'

                # Additional business rationale check for manual overrides
                if result.get('manual_override'):
                    rationale_check = self._validate_business_rationale(result)
                    if not rationale_check['valid']:
                        validation_errors.append("Missing or insufficient business rationale for override")
                        validation_status = 'REVIEW_REQUIRED'

            except Exception as e:
                validation_errors.append(f"Validation error: {str(e)}")
                validation_status = 'INVALID'

            result.update({
                'validation_status': validation_status,
                'validation_errors': validation_errors,
                'validated_at': datetime.now(timezone.utc).isoformat()
            })

            validated_results.append(result)

        return validated_results

    def _validate_table_existence(self, asset_path: str) -> Dict[str, bool]:
        """Check table existence and Snowflake role permissions."""
        try:
            parts = asset_path.split('.')
            if len(parts) != 3:
                return {'exists': False, 'accessible': False}

            database, schema, table = parts

            # Check existence
            existence_query = f"""
                SELECT COUNT(*) as CNT
                FROM {database}.INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = %(schema)s AND TABLE_NAME = %(table)s
            """

            existence_rows = snowflake_connector.execute_query(existence_query,
                {'schema': schema, 'table': table}) or []

            exists = existence_rows[0]['CNT'] > 0 if existence_rows else False

            # Check accessibility (try a simple SELECT)
            accessible = False
            if exists:
                try:
                    test_query = f"SELECT 1 FROM {database}.{schema}.{table} LIMIT 1"
                    snowflake_connector.execute_query(test_query)
                    accessible = True
                except Exception:
                    accessible = False

            return {'exists': exists, 'accessible': accessible}

        except Exception as e:
            logger.warning(f"Table existence check failed for {asset_path}: {e}")
            return {'exists': False, 'accessible': False}

    def _validate_owner_email(self, asset_path: str) -> Dict[str, Any]:
        """Validate owner email format."""
        try:
            owner_query = """
                SELECT DATA_OWNER
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                WHERE FULL_NAME = %(asset_path)s
                LIMIT 1
            """

            owner_rows = snowflake_connector.execute_query(owner_query, {'asset_path': asset_path}) or []

            if owner_rows:
                owner_email = owner_rows[0].get('DATA_OWNER', '')
                # Check @avendra.com format
                if '@avendra.com' in owner_email.lower():
                    return {'valid': True, 'owner': owner_email}
                else:
                    return {'valid': False, 'owner': owner_email}
            else:
                return {'valid': False, 'owner': None}

        except Exception as e:
            logger.warning(f"Owner validation failed for {asset_path}: {e}")
            return {'valid': False, 'owner': None}

    def _validate_business_rationale(self, result: Dict[str, Any]) -> Dict[str, bool]:
        """Validate business rationale for manual overrides."""
        rationale = result.get('business_rationale', '').strip()
        return {
            'valid': len(rationale) >= 50  # Require minimum length rationale
        }

    # 6️⃣ Workflow Routing & Review
    def route_for_review(self, validated_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Route classifications for approval based on confidence and sensitivity.
        Create workflow tasks with SLA tracking.
        """
        routed_results = []

        for result in validated_results:
            confidence = result.get('confidence_score', 0.0)
            category = result.get('final_category', 'INTERNAL')
            validation_status = result.get('validation_status', 'VALID')

            # Determine routing based on confidence and risk level
            routing_decision = self._calculate_routing_decision(confidence, category, validation_status)

            # Create workflow task if needed
            if routing_decision['requires_review']:
                task_id = self._create_workflow_task(result, routing_decision)
                result['workflow_task_id'] = task_id
                result['sla_hours'] = routing_decision['sla_hours']

                # Send notifications
                self._send_review_notifications(result, routing_decision)

            result.update({
                'routing_decision': routing_decision,
                'routed_at': datetime.now(timezone.utc).isoformat()
            })

            routed_results.append(result)

        return routed_results

    def _calculate_routing_decision(self, confidence: float, category: str, validation_status: str) -> Dict[str, Any]:
        """Calculate routing decision based on confidence, risk level, and SLA."""
        # Confidence levels
        if confidence >= 0.9:
            confidence_level = 'HIGH'
        elif confidence >= 0.7:
            confidence_level = 'MEDIUM'
        else:
            confidence_level = 'LOW'

        # Risk level based on category
        risk_mapping = {
            'REGULATORY_DATA': 'HIGH',
            'PERSONAL_DATA': 'HIGH',
            'FINANCIAL_DATA': 'HIGH',
            'PROPRIETARY_DATA': 'MEDIUM',
            'INTERNAL': 'LOW'
        }
        risk_level = risk_mapping.get(category, 'MEDIUM')

        # Routing logic
        if confidence_level == 'HIGH' and risk_level == 'LOW':
            routing_type = 'AUTO_APPROVE'
            sla_hours = 0
            requires_review = False
        elif confidence_level == 'HIGH' and risk_level == 'HIGH':
            routing_type = 'EXPEDITED_REVIEW'
            sla_hours = 24  # 1 day
            requires_review = True
        elif confidence_level == 'MEDIUM':
            routing_type = 'STANDARD_REVIEW'
            sla_hours = 48  # 2 days
            requires_review = True
        else:  # LOW confidence
            routing_type = 'ENHANCED_REVIEW'
            sla_hours = 72  # 3+ days
            requires_review = True

        # Override for validation issues
        if validation_status in ['REVIEW_REQUIRED', 'INVALID']:
            routing_type = 'ENHANCED_REVIEW'
            sla_hours = max(sla_hours, 72)
            requires_review = True

        return {
            'confidence_level': confidence_level,
            'risk_level': risk_level,
            'routing_type': routing_type,
            'sla_hours': sla_hours,
            'requires_review': requires_review,
            'review_priority': 'HIGH' if risk_level == 'HIGH' else 'MEDIUM'
        }

    def _create_workflow_task(self, result: Dict[str, Any], routing_decision: Dict[str, Any]) -> Optional[str]:
        """Create workflow task with SLA tracking."""
        try:
            task_data = {
                'asset_path': result['asset_path'],
                'classification_category': result.get('final_category'),
                'cia_levels': result.get('cia_levels'),
                'confidence_score': result.get('confidence_score'),
                'routing_type': routing_decision['routing_type'],
                'sla_hours': routing_decision['sla_hours'],
                'priority': routing_decision['review_priority'],
                'validation_status': result.get('validation_status'),
                'validation_errors': result.get('validation_errors', []),
                'created_at': datetime.now(timezone.utc).isoformat()
            }

            # Insert into workflow tasks table
            task_query = """
                INSERT INTO DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_WORKFLOW_TASKS
                (ASSET_PATH, TASK_DATA, STATUS, CREATED_AT, DUE_AT)
                VALUES (%(asset_path)s, %(task_data)s, 'PENDING', CURRENT_TIMESTAMP(),
                        DATEADD(HOUR, %(sla_hours)s, CURRENT_TIMESTAMP()))
            """

            snowflake_connector.execute_non_query(task_query, {
                'asset_path': result['asset_path'],
                'task_data': json.dumps(task_data),
                'sla_hours': routing_decision['sla_hours']
            })

            # Return task identifier (simplified - in practice would return actual task ID)
            return f"TASK_{result['asset_path'].replace('.', '_')}_{int(datetime.now().timestamp())}"

        except Exception as e:
            logger.error(f"Failed to create workflow task: {e}")
            return None

    def _send_review_notifications(self, result: Dict[str, Any], routing_decision: Dict[str, Any]):
        """Send notifications to reviewers."""
        try:
            # Get reviewers for this category/routing type
            reviewer_query = """
                SELECT REVIEWER_EMAIL, NOTIFICATION_METHOD
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.REVIEWER_ASSIGNMENTS
                WHERE CATEGORY = %(category)s
                AND ROUTING_TYPE = %(routing_type)s
                AND IS_ACTIVE = TRUE
            """

            reviewers = snowflake_connector.execute_query(reviewer_query, {
                'category': result.get('final_category'),
                'routing_type': routing_decision['routing_type']
            }) or []

            # Send notifications (implementation depends on notification service)
            for reviewer in reviewers:
                email = reviewer.get('REVIEWER_EMAIL')
                method = reviewer.get('NOTIFICATION_METHOD', 'EMAIL')

                # Placeholder for notification sending
                logger.info(f"Would send {method} notification to {email} for asset {result['asset_path']}")

        except Exception as e:
            logger.warning(f"Failed to send review notifications: {e}")

    # 7️⃣ Snowflake Tagging & Metadata Updates
    def apply_tagging_and_updates(self, routed_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply classification results and CIA tags directly in Snowflake.
        Update governance tables with latest classification & status.
        """
        tagged_results = []

        for result in routed_results:
            asset_path = result['asset_path']
            category = result.get('final_category', 'INTERNAL')
            cia_levels = result.get('cia_levels', {})
            validation_status = result.get('validation_status', 'VALID')

            try:
                # Parse asset path
                parts = asset_path.split('.')
                if len(parts) != 3:
                    raise ValueError(f"Invalid asset path format: {asset_path}")

                database, schema, table = parts

                # Apply tags to table
                self._apply_table_tags(database, schema, table, category, cia_levels)

                # Update governance tables
                self._update_governance_tables(result)

                # Record classification decision
                self._record_classification_decision(result)

                result['tagging_status'] = 'SUCCESS'
                result['tagged_at'] = datetime.now(timezone.utc).isoformat()

            except Exception as e:
                logger.error(f"Failed to apply tagging for {asset_path}: {e}")
                result['tagging_status'] = 'FAILED'
                result['tagging_error'] = str(e)

            tagged_results.append(result)

        return tagged_results

    def _apply_table_tags(self, database: str, schema: str, table: str,
                         category: str, cia_levels: Dict[str, str]):
        """Apply classification and CIA tags to Snowflake table."""
        try:
            # Map category to classification label
            label_mapping = {
                'PERSONAL_DATA': 'Confidential',
                'FINANCIAL_DATA': 'Confidential',
                'PROPRIETARY_DATA': 'Restricted',
                'REGULATORY_DATA': 'Confidential',
                'INTERNAL': 'Internal'
            }
            classification_label = label_mapping.get(category, 'Internal')

            # Apply tags
            tag_commands = [
                f"ALTER TABLE {database}.{schema}.{table} SET TAG classification_label = '{category}'",
                f"ALTER TABLE {database}.{schema}.{table} SET TAG confidentiality_level = '{cia_levels.get('C', 'C1')}'",
                f"ALTER TABLE {database}.{schema}.{table} SET TAG integrity_level = '{cia_levels.get('I', 'I1')}'",
                f"ALTER TABLE {database}.{schema}.{table} SET TAG availability_level = '{cia_levels.get('A', 'A1')}'"
            ]

            for cmd in tag_commands:
                snowflake_connector.execute_non_query(cmd)

        except Exception as e:
            logger.error(f"Failed to apply table tags: {e}")
            raise

    def _update_governance_tables(self, result: Dict[str, Any]):
        """Update ASSETS and CLASSIFICATION_AUDIT tables."""
        try:
            asset_path = result['asset_path']
            category = result.get('final_category')
            cia_levels = result.get('cia_levels', {})
            validation_status = result.get('validation_status')

            # Determine if the asset contains PII, financial data, etc.
            category_upper = str(category).upper() if category else ''
            
            # Check if category is in PII-related categories
            contains_pii = 1 if any(pii_term in category_upper for pii_term in 
                                 ['PII', 'PERSONAL', 'IDENTIFIABLE', 'PRIVATE', 'SENSITIVE']) else 0
            
            # Check if category is financial data
            contains_financial = 1 if any(fin_term in category_upper for fin_term in 
                                       ['FINANCIAL', 'PAYMENT', 'TRANSACTION', 'BANK', 'CREDIT']) else 0
            
            # Check if category is SOX relevant
            sox_relevant = 1 if any(sox_term in category_upper for sox_term in 
                                 ['FINANCIAL', 'ACCOUNTING', 'AUDIT', 'SOX', 'REPORTING']) else 0
            
            # Check if category is SOC2 relevant
            soc_relevant = 1 if any(soc_term in category_upper for soc_term in 
                                 ['PII', 'PERSONAL', 'SECURITY', 'PRIVACY', 'CONFIDENTIAL']) else 0
            
            # Check if category is regulatory data
            regulatory_data = 1 if any(reg_term in category_upper for reg_term in 
                                    ['REGULATORY', 'COMPLIANCE', 'LEGAL', 'GOVERNANCE', 'REQUIREMENT']) else 0

            # Update ASSETS table
            assets_update = """
                UPDATE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                SET CLASSIFICATION_TAG = %(category)s,
                    CIA_CONF = %(c_level)s,
                    CIA_INT = %(i_level)s,
                    CIA_AVAIL = %(a_level)s,
                    RISK_SCORE = %(risk_score)s,
                    LAST_CLASSIFIED_DATE = CURRENT_DATE(),
                    LAST_MODIFIED_DATE = CURRENT_TIMESTAMP(),
                    TAGS = %(tags)s,
                    CONTAINS_PII = %(contains_pii)s,
                    CONTAINS_FINANCIAL_DATA = %(contains_financial)s,
                    SOX_RELEVANT = %(sox_relevant)s,
                    SOC_RELEVANT = %(soc_relevant)s,
                    REGULATORY_DATA = %(regulatory_data)s
                WHERE FULL_NAME = %(asset_path)s
            """

            # Calculate risk score based on category
            risk_scores = {
                'REGULATORY_DATA': 9,
                'PERSONAL_DATA': 8,
                'FINANCIAL_DATA': 7,
                'PROPRIETARY_DATA': 5,
                'INTERNAL': 2
            }
            risk_score = risk_scores.get(category, 2)

            snowflake_connector.execute_non_query(assets_update, {
                'category': category,
                'c_level': cia_levels.get('C', 'C1').replace('C', ''),
                'i_level': cia_levels.get('I', 'I1').replace('I', ''),
                'a_level': cia_levels.get('A', 'A1').replace('A', ''),
                'risk_score': risk_score,
                'tags': json.dumps(result.get('routing_decision', {})),
                'contains_pii': contains_pii,
                'contains_financial': contains_financial,
                'sox_relevant': sox_relevant,
                'soc_relevant': soc_relevant,
                'regulatory_data': regulatory_data,
                'asset_path': asset_path
            })

        except Exception as e:
            logger.error(f"Failed to update governance tables: {e}")
            raise

    def _record_classification_decision(self, result: Dict[str, Any]):
        """Record classification decision in audit table."""
        try:
            decision_data = {
                'asset_path': result['asset_path'],
                'category': result.get('final_category'),
                'cia_levels': result.get('cia_levels'),
                'confidence': result.get('confidence_score'),
                'validation_status': result.get('validation_status'),
                'routing_decision': result.get('routing_decision'),
                'detection_method': result.get('detection_method'),
                'fallback_reason': result.get('fallback_reason'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

            audit_insert = """
                INSERT INTO DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AUDIT
                (DATASET_NAME, PREV_C, PREV_I, PREV_A, NEW_C, NEW_I, NEW_A,
                 OWNER, CLASSIFICATION_LEVEL, SUBMITTED_AT, APPROVED_AT, RISK, COMMENTS)
                SELECT %(dataset)s, NULL, NULL, NULL,
                       %(new_c)s, %(new_i)s, %(new_a)s,
                       %(owner)s, %(level)s, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(),
                       %(risk)s, %(comments)s
            """

            cia = result.get('cia_levels', {})
            snowflake_connector.execute_non_query(audit_insert, {
                'dataset': result['asset_path'],
                'new_c': cia.get('C', 'C1').replace('C', ''),
                'new_i': cia.get('I', 'I1').replace('I', ''),
                'new_a': cia.get('A', 'A1').replace('A', ''),
                'owner': 'SYSTEM_AI_ASSISTANT',
                'level': result.get('final_category'),
                'risk': 'Medium',
                'comments': json.dumps(decision_data)
            })

        except Exception as e:
            logger.error(f"Failed to record classification decision: {e}")
            raise

    # 8️⃣ Audit Logging & Monitoring
    def log_audit_events(self, tagged_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enable traceability and operational visibility.
        Log scans, detections, validations, tagging, and review decisions.
        """
        logged_results = []

        for result in tagged_results:
            try:
                # Log comprehensive audit trail
                audit_events = [
                    {
                        'event_type': 'SCAN_COMPLETED',
                        'asset_path': result['asset_path'],
                        'details': {
                            'detection_method': result.get('detection_method'),
                            'confidence_score': result.get('confidence_score'),
                            'category_scores': result.get('category_scores')
                        }
                    },
                    {
                        'event_type': 'CLASSIFICATION_APPLIED',
                        'asset_path': result['asset_path'],
                        'details': {
                            'final_category': result.get('final_category'),
                            'cia_levels': result.get('cia_levels'),
                            'validation_status': result.get('validation_status')
                        }
                    },
                    {
                        'event_type': 'TAGGING_COMPLETED',
                        'asset_path': result['asset_path'],
                        'details': {
                            'tagging_status': result.get('tagging_status'),
                            'tagged_at': result.get('tagged_at')
                        }
                    }
                ]

                if result.get('workflow_task_id'):
                    audit_events.append({
                        'event_type': 'REVIEW_ROUTED',
                        'asset_path': result['asset_path'],
                        'details': {
                            'task_id': result['workflow_task_id'],
                            'routing_decision': result.get('routing_decision'),
                            'sla_hours': result.get('sla_hours')
                        }
                    })

                # Insert audit events
                for event in audit_events:
                    self._insert_audit_event(event)

                # Update metrics for dashboard
                self._update_dashboard_metrics(result)

                result['audit_logged'] = True

            except Exception as e:
                logger.error(f"Failed to log audit events for {result['asset_path']}: {e}")
                result['audit_logged'] = False
                result['audit_error'] = str(e)

            logged_results.append(result)

        return logged_results

    def _insert_audit_event(self, event: Dict[str, Any]):
        """Insert audit event into CLASSIFICATION_AUDIT_LOG."""
        try:
            audit_insert = """
                INSERT INTO DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AUDIT_LOG
                (EVENT_TYPE, ASSET_PATH, DETAILS, CREATED_AT)
                VALUES (%(event_type)s, %(asset_path)s, %(details)s, CURRENT_TIMESTAMP())
            """

            snowflake_connector.execute_non_query(audit_insert, {
                'event_type': event['event_type'],
                'asset_path': event['asset_path'],
                'details': json.dumps(event['details'])
            })

        except Exception as e:
            logger.error(f"Failed to insert audit event: {e}")
            raise

    def _update_dashboard_metrics(self, result: Dict[str, Any]):
        """Update metrics for governance dashboard."""
        try:
            # Update detection accuracy
            accuracy_update = """
                UPDATE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.DASHBOARD_METRICS
                SET DETECTION_ACCURACY = (
                    SELECT AVG(CASE WHEN VALIDATION_STATUS = 'VALID' THEN 1.0 ELSE 0.0 END)
                    FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AUDIT
                    WHERE CREATED_AT >= DATEADD(DAY, -30, CURRENT_DATE())
                ),
                LAST_UPDATED = CURRENT_TIMESTAMP()
                WHERE METRIC_NAME = 'DETECTION_ACCURACY'
            """

            snowflake_connector.execute_non_query(accuracy_update)

            # Update policy compliance rate
            compliance_update = """
                UPDATE DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.DASHBOARD_METRICS
                SET POLICY_COMPLIANCE_RATE = (
                    SELECT AVG(CASE WHEN VALIDATION_STATUS = 'VALID' THEN 1.0 ELSE 0.0 END)
                    FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                    WHERE LAST_CLASSIFIED_DATE >= DATEADD(DAY, -30, CURRENT_DATE())
                ),
                LAST_UPDATED = CURRENT_TIMESTAMP()
                WHERE METRIC_NAME = 'POLICY_COMPLIANCE_RATE'
            """

            snowflake_connector.execute_non_query(compliance_update)

        except Exception as e:
            logger.warning(f"Failed to update dashboard metrics: {e}")

    # 9️⃣ Security, Error Handling & Scalability
    def execute_full_pipeline(self, database: str, schema_filter: Optional[str] = None,
                            max_assets: int = 1000) -> Dict[str, Any]:
        """
        Execute the complete AI assistant pipeline with security, error handling, and scalability.
        """
        start_time = datetime.now(timezone.utc)
        run_id = f"PIPELINE_{int(start_time.timestamp())}"

        try:
            logger.info(f"Starting AI assistant pipeline run {run_id} for database {database}")

            # 1. Table Discovery & Metadata Extraction
            logger.info("Step 1: Discovering and extracting metadata...")
            metadata_list = self.discover_and_extract_metadata(database, schema_filter)
            metadata_list = metadata_list[:max_assets]  # Limit for scalability

            if not metadata_list:
                return {'run_id': run_id, 'status': 'NO_ASSETS_FOUND', 'assets_processed': 0}

            # 2. Semantic Category Detection
            logger.info(f"Step 2: Detecting semantic categories for {len(metadata_list)} assets...")
            detection_results = self.detect_semantic_categories(metadata_list)

            # 3. Fallback & Tie-Break Logic
            logger.info("Step 3: Applying fallback and tie-break logic...")
            fallback_results = self.apply_fallback_logic(detection_results)

            # 4. CIA Classification Recommendation
            logger.info("Step 4: Recommending CIA classification levels...")
            cia_results = self.recommend_cia_levels(fallback_results)

            # 5. Validation & Policy Enforcement
            logger.info("Step 5: Validating and enforcing policies...")
            validated_results = self.validate_and_enforce_policy(cia_results)

            # 6. Workflow Routing & Review
            logger.info("Step 6: Routing for review...")
            routed_results = self.route_for_review(validated_results)

            # 7. Snowflake Tagging & Metadata Updates
            logger.info("Step 7: Applying tags and updating metadata...")
            tagged_results = self.apply_tagging_and_updates(routed_results)

            # 8. Audit Logging & Monitoring
            logger.info("Step 8: Logging audit events...")
            final_results = self.log_audit_events(tagged_results)

            # Calculate success metrics
            end_time = datetime.now(timezone.utc)
            duration_seconds = (end_time - start_time).total_seconds()

            success_count = len([r for r in final_results if r.get('tagging_status') == 'SUCCESS'])
            total_assets = len(final_results)
            detection_accuracy = success_count / total_assets if total_assets > 0 else 0.0

            # Count classifications
            category_counts = defaultdict(int)
            for r in final_results:
                category = r.get('final_category', 'UNKNOWN')
                category_counts[category] += 1

            # SLA compliance (simplified - would need actual review tracking)
            sla_compliant = len([r for r in final_results if not r.get('routing_decision', {}).get('requires_review', False)])

            success_metrics = {
                'run_id': run_id,
                'database': database,
                'schema_filter': schema_filter,
                'total_assets_processed': total_assets,
                'successful_classifications': success_count,
                'detection_accuracy': round(detection_accuracy, 3),
                'classification_distribution': dict(category_counts),
                'sla_compliant_count': sla_compliant,
                'duration_seconds': round(duration_seconds, 2),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'status': 'COMPLETED'
            }

            # Log final summary
            logger.info(f"Pipeline completed: {success_metrics}")

            return success_metrics

        except Exception as e:
            error_msg = f"Pipeline execution failed: {str(e)}"
            logger.error(error_msg)

            # Log failure
            try:
                failure_metrics = {
                    'run_id': run_id,
                    'database': database,
                    'status': 'FAILED',
                    'error': str(e),
                    'end_time': datetime.now(timezone.utc).isoformat()
                }
                self._insert_audit_event({
                    'event_type': 'PIPELINE_FAILED',
                    'asset_path': f"{database}.{schema_filter or '*'}",
                    'details': failure_metrics
                })
            except Exception:
                pass

            return {
                'run_id': run_id,
                'status': 'FAILED',
                'error': str(e),
                'database': database
            }


# Global instance
comprehensive_detection_service = ComprehensiveDetectionService()
