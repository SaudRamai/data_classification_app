"""
Governance Rules Loader Service (View-Based)

This service loads all classification rules and metadata from Snowflake VIEWS
that dynamically derive rules from existing governance tables:
- SENSITIVITY_CATEGORIES
- SENSITIVE_KEYWORDS  
- SENSITIVE_PATTERNS

This approach eliminates the need for separate rule tables and ensures
all logic is derived from your core governance data.

Author: AI Classification System
Date: 2025-12-04
Version: 2.0 (View-Based)
"""

import logging
import json
from typing import List, Dict, Any, Optional
from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)


class GovernanceRulesLoaderV2:
    """Service for loading all governance rules from dynamic views."""

    def __init__(self, governance_db: str = "DATA_CLASSIFICATION_DB", governance_schema: str = "DATA_CLASSIFICATION_GOVERNANCE"):
        """
        Initialize the governance rules loader.

        Args:
            governance_db: Name of the governance database
            governance_schema: Name of the governance schema
        """
        self.governance_db = governance_db
        self.governance_schema = governance_schema
        self._cache: Dict[str, Any] = {}
        self._cache_enabled = True

    def _execute_query(self, query: str) -> List[Dict[str, Any]]:
        """
        Execute a query and return results as list of dictionaries.

        Args:
            query: SQL query to execute

        Returns:
            List of dictionaries representing query results
        """
        try:
            result = snowflake_connector.execute_query(query)
            
            # Handle different return types from Snowflake connector
            if result is None:
                return []
            
            if isinstance(result, list):
                return result
            
            if hasattr(result, 'fetchall'):
                # Cursor object
                columns = [desc[0] for desc in result.description]
                rows = result.fetchall()
                return [dict(zip(columns, row)) for row in rows]
            
            # Single row result
            if isinstance(result, dict):
                return [result]
            
            logger.warning(f"Unexpected query result type: {type(result)}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            logger.debug(f"Query: {query}")
            return []

    def load_classification_rules(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Load all classification rules from VW_CLASSIFICATION_RULES view.
        This view combines keywords and patterns with category metadata.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of classification rules
        """
        cache_key = "classification_rules"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached classification rules")
            return self._cache[cache_key]

        query = f"""
            SELECT
                RULE_TYPE,
                RULE_ID,
                RULE_PATTERN,
                MATCH_TYPE,
                CATEGORY_ID,
                CATEGORY_NAME,
                POLICY_GROUP,
                CONFIDENTIALITY_LEVEL,
                INTEGRITY_LEVEL,
                AVAILABILITY_LEVEL,
                DETECTION_THRESHOLD,
                RULE_WEIGHT,
                CATEGORY_WEIGHT,
                MULTI_LABEL,
                RULE_DESCRIPTION,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.VW_CLASSIFICATION_RULES
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, CATEGORY_NAME, RULE_TYPE
        """

        try:
            rules = self._execute_query(query)
            logger.info(f"Loaded {len(rules)} classification rules from VW_CLASSIFICATION_RULES")
            
            if self._cache_enabled:
                self._cache[cache_key] = rules
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to load classification rules: {e}")
            return []

    def load_context_aware_rules(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Load context-aware adjustment rules from VW_CONTEXT_AWARE_RULES view.
        These rules boost/reduce scores based on table and column context.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of context-aware rules
        """
        cache_key = "context_aware_rules"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached context-aware rules")
            return self._cache[cache_key]

        query = f"""
            SELECT
                POLICY_GROUP,
                KEYWORD_STRING,
                RULE_TYPE,
                ACTION_TYPE,
                ACTION_FACTOR,
                DESCRIPTION
            FROM {self.governance_db}.{self.governance_schema}.VW_CONTEXT_AWARE_RULES
            ORDER BY POLICY_GROUP, RULE_TYPE, ACTION_FACTOR DESC
        """

        try:
            rules = self._execute_query(query)
            logger.info(f"Loaded {len(rules)} context-aware rules from VW_CONTEXT_AWARE_RULES")
            
            # Group by rule type for easier access
            rules_by_type: Dict[str, List[Dict[str, Any]]] = {}
            for rule in rules:
                rule_type = rule.get('RULE_TYPE', 'UNKNOWN')
                if rule_type not in rules_by_type:
                    rules_by_type[rule_type] = []
                rules_by_type[rule_type].append(rule)
            
            if self._cache_enabled:
                self._cache[cache_key] = rules_by_type
            
            return rules_by_type
            
        except Exception as e:
            logger.error(f"Failed to load context-aware rules: {e}")
            return {}

    def load_tiebreaker_keywords(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load tiebreaker keywords from VW_TIEBREAKER_KEYWORDS view.
        Used for intelligent tiebreaking when scores are identical.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping policy group to list of keyword dictionaries
        """
        cache_key = "tiebreaker_keywords"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached tiebreaker keywords")
            return self._cache[cache_key]

        query = f"""
            SELECT
                POLICY_GROUP,
                KEYWORD,
                WEIGHT,
                CATEGORY_NAME,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.VW_TIEBREAKER_KEYWORDS
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, WEIGHT DESC, KEYWORD
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} tiebreaker keywords from VW_TIEBREAKER_KEYWORDS")
            
            # Group by policy group
            keywords_by_group: Dict[str, List[Dict[str, Any]]] = {}
            for row in results:
                policy_group = row.get('POLICY_GROUP', '').upper()
                if policy_group not in keywords_by_group:
                    keywords_by_group[policy_group] = []
                keywords_by_group[policy_group].append({
                    'keyword': row.get('KEYWORD', '').lower(),
                    'weight': float(row.get('WEIGHT', 1.0)),
                    'category': row.get('CATEGORY_NAME', '')
                })
            
            if self._cache_enabled:
                self._cache[cache_key] = keywords_by_group
            
            return keywords_by_group
            
        except Exception as e:
            logger.error(f"Failed to load tiebreaker keywords: {e}")
            return {}

    def load_address_context_indicators(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Load address context indicators from VW_ADDRESS_CONTEXT_INDICATORS view.
        Used to distinguish physical addresses (PII) from network addresses (SOC2).

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of address context indicators
        """
        cache_key = "address_context_indicators"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached address context indicators")
            return self._cache[cache_key]

        query = f"""
            SELECT
                CONTEXT_TYPE,
                INDICATOR_TYPE,
                INDICATOR_KEYWORD,
                EXPECTED_POLICY_GROUP,
                BOOST_FACTOR,
                SUPPRESS_POLICY_GROUPS,
                SUPPRESS_FACTOR,
                DESCRIPTION
            FROM {self.governance_db}.{self.governance_schema}.VW_ADDRESS_CONTEXT_INDICATORS
            ORDER BY CONTEXT_TYPE, INDICATOR_TYPE
        """

        try:
            indicators = self._execute_query(query)
            logger.info(f"Loaded {len(indicators)} address context indicators from VW_ADDRESS_CONTEXT_INDICATORS")
            
            if self._cache_enabled:
                self._cache[cache_key] = indicators
            
            return indicators
            
        except Exception as e:
            logger.error(f"Failed to load address context indicators: {e}")
            return []

    def load_exclusion_patterns(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Load exclusion patterns from VW_EXCLUSION_PATTERNS view.
        Used to identify non-sensitive fields and reduce false positives.
        
        New structure: Each row represents ONE keyword with its exclusion type and factors.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping exclusion type to exclusion pattern details with keyword list
        """
        cache_key = "exclusion_patterns"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached exclusion patterns")
            return self._cache[cache_key]

        query = f"""
            SELECT
                EXCLUSION_TYPE,
                KEYWORD_PARSED,
                REDUCE_PII_FACTOR,
                REDUCE_SOX_FACTOR,
                REDUCE_SOC2_FACTOR,
                DESCRIPTION
            FROM {self.governance_db}.{self.governance_schema}.VW_EXCLUSION_PATTERNS
            ORDER BY EXCLUSION_TYPE, KEYWORD_PARSED
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} exclusion pattern records from VW_EXCLUSION_PATTERNS")
            
            # Group by EXCLUSION_TYPE
            exclusion_patterns: Dict[str, Dict[str, Any]] = {}
            
            for row in results:
                exc_type = row.get('EXCLUSION_TYPE', 'UNKNOWN')
                keyword = row.get('KEYWORD_PARSED', '').lower().strip()
                
                if not keyword:
                    continue
                
                # Initialize exclusion type if not exists
                if exc_type not in exclusion_patterns:
                    exclusion_patterns[exc_type] = {
                        'exclusion_type': exc_type,
                        'keywords': [],
                        'reduce_pii_factor': float(row.get('REDUCE_PII_FACTOR', 0.5)),
                        'reduce_sox_factor': float(row.get('REDUCE_SOX_FACTOR', 0.5)),
                        'reduce_soc2_factor': float(row.get('REDUCE_SOC2_FACTOR', 0.5)),
                        'description': row.get('DESCRIPTION', '')
                    }
                
                # Add keyword to list (avoid duplicates)
                if keyword not in exclusion_patterns[exc_type]['keywords']:
                    exclusion_patterns[exc_type]['keywords'].append(keyword)
            
            # Log summary
            for exc_type, pattern in exclusion_patterns.items():
                logger.info(f"  - {exc_type}: {len(pattern['keywords'])} keywords")
            
            if self._cache_enabled:
                self._cache[cache_key] = exclusion_patterns
            
            return exclusion_patterns
            
        except Exception as e:
            logger.error(f"Failed to load exclusion patterns: {e}")
            return {}

    def load_policy_group_keywords(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load keywords grouped by policy group from VW_POLICY_GROUP_KEYWORDS view.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping policy group to list of keywords
        """
        cache_key = "policy_group_keywords"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached policy group keywords")
            return self._cache[cache_key]

        query = f"""
            SELECT
                POLICY_GROUP,
                KEYWORD_STRING,
                MATCH_TYPE,
                SENSITIVITY_WEIGHT,
                CATEGORY_NAME,
                DETECTION_THRESHOLD,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.VW_POLICY_GROUP_KEYWORDS
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, SENSITIVITY_WEIGHT DESC, KEYWORD_STRING
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} policy group keywords from VW_POLICY_GROUP_KEYWORDS")
            
            # Group by policy group
            keywords_by_group: Dict[str, List[Dict[str, Any]]] = {}
            for row in results:
                policy_group = row.get('POLICY_GROUP', '').upper()
                if policy_group not in keywords_by_group:
                    keywords_by_group[policy_group] = []
                keywords_by_group[policy_group].append({
                    'keyword': row.get('KEYWORD_STRING', '').lower(),
                    'match_type': row.get('MATCH_TYPE', 'CONTAINS').upper(),
                    'weight': float(row.get('SENSITIVITY_WEIGHT', 0.5)),
                    'category': row.get('CATEGORY_NAME', ''),
                    'threshold': float(row.get('DETECTION_THRESHOLD', 0.5))
                })
            
            if self._cache_enabled:
                self._cache[cache_key] = keywords_by_group
            
            return keywords_by_group
            
        except Exception as e:
            logger.error(f"Failed to load policy group keywords: {e}")
            return {}

    def load_category_scoring_weights(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Load category scoring weights from VW_CATEGORY_SCORING_WEIGHTS view.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping category name to scoring weights
        """
        cache_key = "category_scoring_weights"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached category scoring weights")
            return self._cache[cache_key]

        query = f"""
            SELECT
                CATEGORY_ID,
                CATEGORY_NAME,
                POLICY_GROUP,
                WEIGHT_EMBEDDING,
                WEIGHT_KEYWORD,
                WEIGHT_PATTERN,
                DETECTION_THRESHOLD,
                MULTI_LABEL,
                CONFIDENTIALITY_LEVEL,
                INTEGRITY_LEVEL,
                AVAILABILITY_LEVEL,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.VW_CATEGORY_SCORING_WEIGHTS
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, CATEGORY_NAME
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} category scoring weights from VW_CATEGORY_SCORING_WEIGHTS")
            
            # Convert to dictionary keyed by category name
            weights_by_category: Dict[str, Dict[str, Any]] = {}
            for row in results:
                cat_name = row.get('CATEGORY_NAME', '').upper()
                weights_by_category[cat_name] = {
                    'category_id': row.get('CATEGORY_ID'),
                    'policy_group': row.get('POLICY_GROUP', '').upper(),
                    'weight_embedding': float(row.get('WEIGHT_EMBEDDING', 0.6)),
                    'weight_keyword': float(row.get('WEIGHT_KEYWORD', 0.25)),
                    'weight_pattern': float(row.get('WEIGHT_PATTERN', 0.15)),
                    'detection_threshold': float(row.get('DETECTION_THRESHOLD', 0.5)),
                    'multi_label': bool(row.get('MULTI_LABEL', True)),
                    'confidentiality_level': int(row.get('CONFIDENTIALITY_LEVEL', 1)),
                    'integrity_level': int(row.get('INTEGRITY_LEVEL', 1)),
                    'availability_level': int(row.get('AVAILABILITY_LEVEL', 1))
                }
            
            if self._cache_enabled:
                self._cache[cache_key] = weights_by_category
            
            return weights_by_category
            
        except Exception as e:
            logger.error(f"Failed to load category scoring weights: {e}")
            return {}

    def load_category_metadata(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Load complete category metadata from VW_CATEGORY_METADATA view.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping category name to complete metadata
        """
        cache_key = "category_metadata"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached category metadata")
            return self._cache[cache_key]

        query = f"""
            SELECT
                CATEGORY_ID,
                CATEGORY_NAME,
                DESCRIPTION,
                POLICY_GROUP,
                CONFIDENTIALITY_LEVEL,
                INTEGRITY_LEVEL,
                AVAILABILITY_LEVEL,
                DETECTION_THRESHOLD,
                WEIGHT_EMBEDDING,
                WEIGHT_KEYWORD,
                WEIGHT_PATTERN,
                MULTI_LABEL,
                IS_ACTIVE,
                KEYWORD_COUNT,
                PATTERN_COUNT
            FROM {self.governance_db}.{self.governance_schema}.VW_CATEGORY_METADATA
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, CATEGORY_NAME
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} category metadata records from VW_CATEGORY_METADATA")
            
            # Convert to dictionary keyed by category name
            metadata_by_category: Dict[str, Dict[str, Any]] = {}
            for row in results:
                cat_name = row.get('CATEGORY_NAME', '').upper()
                metadata_by_category[cat_name] = {
                    'category_id': row.get('CATEGORY_ID'),
                    'category_name': cat_name,
                    'description': row.get('DESCRIPTION', ''),
                    'policy_group': row.get('POLICY_GROUP', '').upper(),
                    'confidentiality_level': int(row.get('CONFIDENTIALITY_LEVEL', 1)),
                    'integrity_level': int(row.get('INTEGRITY_LEVEL', 1)),
                    'availability_level': int(row.get('AVAILABILITY_LEVEL', 1)),
                    'detection_threshold': float(row.get('DETECTION_THRESHOLD', 0.5)),
                    'weight_embedding': float(row.get('WEIGHT_EMBEDDING', 0.6)),
                    'weight_keyword': float(row.get('WEIGHT_KEYWORD', 0.25)),
                    'weight_pattern': float(row.get('WEIGHT_PATTERN', 0.15)),
                    'multi_label': bool(row.get('MULTI_LABEL', True)),
                    'keyword_count': int(row.get('KEYWORD_COUNT', 0)),
                    'pattern_count': int(row.get('PATTERN_COUNT', 0))
                }
            
            if self._cache_enabled:
                self._cache[cache_key] = metadata_by_category
            
            return metadata_by_category
            
        except Exception as e:
            logger.error(f"Failed to load category metadata: {e}")
            return {}

    def refresh_all_rules(self) -> None:
        """Refresh all governance rules from database (clear cache and reload)."""
        logger.info("Refreshing all governance rules from views")
        self._cache.clear()
        
        # Reload all rules
        self.load_classification_rules(force_refresh=True)
        self.load_context_aware_rules(force_refresh=True)
        self.load_tiebreaker_keywords(force_refresh=True)
        self.load_address_context_indicators(force_refresh=True)
        self.load_exclusion_patterns(force_refresh=True)
        self.load_policy_group_keywords(force_refresh=True)
        self.load_category_scoring_weights(force_refresh=True)
        self.load_category_metadata(force_refresh=True)
        
        logger.info("All governance rules refreshed successfully")

    def clear_cache(self) -> None:
        """Clear the internal cache."""
        self._cache.clear()
        logger.debug("Cache cleared")

    def enable_cache(self) -> None:
        """Enable caching of governance rules."""
        self._cache_enabled = True
        logger.debug("Cache enabled")

    def disable_cache(self) -> None:
        """Disable caching of governance rules."""
        self._cache_enabled = False
        self._cache.clear()
        logger.debug("Cache disabled and cleared")


# Global singleton instance
governance_rules_loader = GovernanceRulesLoaderV2()
