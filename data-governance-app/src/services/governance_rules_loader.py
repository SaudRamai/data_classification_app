"""
Governance Rules Loader Service

This service provides centralized loading of all classification rules and metadata
from Snowflake governance tables. It eliminates hard-coded logic by sourcing all
sensitivity rules, patterns, and category mappings dynamically from the database.

Author: AI Classification System
Date: 2025-12-04
"""

import logging
import json
from typing import List, Dict, Any, Optional
from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)


class GovernanceRulesLoader:
    """Service for loading all governance rules and metadata from Snowflake."""

    def __init__(self, governance_db: str = "GOVERNANCE_DB", governance_schema: str = "GOVERNANCE_SCHEMA"):
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
        Load all active classification rules from CLASSIFICATION_RULES table.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of classification rules sorted by priority
        """
        cache_key = "classification_rules"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached classification rules")
            return self._cache[cache_key]

        query = f"""
            SELECT
                RULE_ID,
                RULE_NAME,
                RULE_TYPE,
                PRIORITY,
                MATCH_SCOPE,
                MATCH_KEYWORDS,
                MATCH_PATTERN,
                MATCH_LOGIC,
                EXCLUDE_KEYWORDS,
                EXCLUDE_PATTERN,
                TARGET_POLICY_GROUP,
                ACTION_TYPE,
                ACTION_FACTOR,
                SECONDARY_POLICY_GROUP,
                SECONDARY_ACTION_TYPE,
                SECONDARY_ACTION_FACTOR,
                DESCRIPTION,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.CLASSIFICATION_RULES
            WHERE IS_ACTIVE = TRUE
            ORDER BY PRIORITY ASC, RULE_ID
        """

        try:
            rules = self._execute_query(query)
            logger.info(f"Loaded {len(rules)} classification rules from database")
            
            # Parse JSON fields
            for rule in rules:
                if rule.get('MATCH_KEYWORDS'):
                    try:
                        rule['MATCH_KEYWORDS_PARSED'] = json.loads(rule['MATCH_KEYWORDS'])
                    except json.JSONDecodeError:
                        rule['MATCH_KEYWORDS_PARSED'] = []
                
                if rule.get('EXCLUDE_KEYWORDS'):
                    try:
                        rule['EXCLUDE_KEYWORDS_PARSED'] = json.loads(rule['EXCLUDE_KEYWORDS'])
                    except json.JSONDecodeError:
                        rule['EXCLUDE_KEYWORDS_PARSED'] = []
            
            if self._cache_enabled:
                self._cache[cache_key] = rules
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to load classification rules: {e}")
            return []

    def load_tiebreaker_keywords(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load tiebreaker keywords grouped by policy group.

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
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.TIEBREAKER_KEYWORDS
            WHERE IS_ACTIVE = TRUE
            ORDER BY POLICY_GROUP, WEIGHT DESC, KEYWORD
        """

        try:
            results = self._execute_query(query)
            logger.info(f"Loaded {len(results)} tiebreaker keywords from database")
            
            # Group by policy group
            keywords_by_group: Dict[str, List[Dict[str, Any]]] = {}
            for row in results:
                policy_group = row.get('POLICY_GROUP', '').upper()
                if policy_group not in keywords_by_group:
                    keywords_by_group[policy_group] = []
                keywords_by_group[policy_group].append({
                    'keyword': row.get('KEYWORD', '').lower(),
                    'weight': float(row.get('WEIGHT', 1.0))
                })
            
            if self._cache_enabled:
                self._cache[cache_key] = keywords_by_group
            
            return keywords_by_group
            
        except Exception as e:
            logger.error(f"Failed to load tiebreaker keywords: {e}")
            return {}

    def load_address_context_registry(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Load address context registry for distinguishing physical vs network addresses.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of address context rules
        """
        cache_key = "address_context_registry"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached address context registry")
            return self._cache[cache_key]

        query = f"""
            SELECT
                CONTEXT_ID,
                CONTEXT_TYPE,
                INDICATOR_TYPE,
                INDICATOR_KEYWORD,
                BOOST_POLICY_GROUP,
                BOOST_FACTOR,
                SUPPRESS_POLICY_GROUP,
                SUPPRESS_FACTOR,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.ADDRESS_CONTEXT_REGISTRY
            WHERE IS_ACTIVE = TRUE
            ORDER BY CONTEXT_TYPE, INDICATOR_TYPE
        """

        try:
            registry = self._execute_query(query)
            logger.info(f"Loaded {len(registry)} address context rules from database")
            
            if self._cache_enabled:
                self._cache[cache_key] = registry
            
            return registry
            
        except Exception as e:
            logger.error(f"Failed to load address context registry: {e}")
            return []

    def load_generic_exclusions(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Load generic exclusion patterns for non-sensitive fields.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            List of generic exclusion rules
        """
        cache_key = "generic_exclusions"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached generic exclusions")
            return self._cache[cache_key]

        query = f"""
            SELECT
                EXCLUSION_ID,
                EXCLUSION_NAME,
                EXCLUSION_TYPE,
                KEYWORDS,
                REDUCE_PII_FACTOR,
                REDUCE_SOX_FACTOR,
                REDUCE_SOC2_FACTOR,
                EXCEPTION_KEYWORDS,
                IS_ACTIVE
            FROM {self.governance_db}.{self.governance_schema}.GENERIC_EXCLUSIONS
            WHERE IS_ACTIVE = TRUE
            ORDER BY EXCLUSION_TYPE
        """

        try:
            exclusions = self._execute_query(query)
            logger.info(f"Loaded {len(exclusions)} generic exclusion rules from database")
            
            # Parse JSON fields
            for exclusion in exclusions:
                if exclusion.get('KEYWORDS'):
                    try:
                        exclusion['KEYWORDS_PARSED'] = json.loads(exclusion['KEYWORDS'])
                    except json.JSONDecodeError:
                        exclusion['KEYWORDS_PARSED'] = []
                
                if exclusion.get('EXCEPTION_KEYWORDS'):
                    try:
                        exclusion['EXCEPTION_KEYWORDS_PARSED'] = json.loads(exclusion['EXCEPTION_KEYWORDS'])
                    except json.JSONDecodeError:
                        exclusion['EXCEPTION_KEYWORDS_PARSED'] = []
            
            if self._cache_enabled:
                self._cache[cache_key] = exclusions
            
            return exclusions
            
        except Exception as e:
            logger.error(f"Failed to load generic exclusions: {e}")
            return []

    def load_sensitivity_categories(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Load sensitivity category metadata from SENSITIVITY_CATEGORIES table.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping category name to category metadata
        """
        cache_key = "sensitivity_categories"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached sensitivity categories")
            return self._cache[cache_key]

        # Try different possible schema locations
        possible_schemas = [
            f"{self.governance_db}.{self.governance_schema}",
            f"{self.governance_db}.DATA_CLASSIFICATION_GOVERNANCE",
            "DATA_CLASSIFICATION_GOVERNANCE"
        ]

        categories_dict = {}
        
        for schema_fqn in possible_schemas:
            query = f"""
                SELECT
                    CATEGORY_ID,
                    CATEGORY_NAME,
                    DESCRIPTION,
                    CONFIDENTIALITY_LEVEL,
                    INTEGRITY_LEVEL,
                    AVAILABILITY_LEVEL,
                    DETECTION_THRESHOLD,
                    IS_ACTIVE,
                    POLICY_GROUP,
                    WEIGHT_EMBEDDING,
                    WEIGHT_KEYWORD,
                    WEIGHT_PATTERN,
                    MULTI_LABEL
                FROM {schema_fqn}.SENSITIVITY_CATEGORIES
                WHERE IS_ACTIVE = TRUE
            """

            try:
                categories = self._execute_query(query)
                if categories:
                    logger.info(f"Loaded {len(categories)} sensitivity categories from {schema_fqn}")
                    
                    # Convert to dictionary keyed by category name
                    for cat in categories:
                        cat_name = cat.get('CATEGORY_NAME', '').upper()
                        categories_dict[cat_name] = {
                            'category_id': cat.get('CATEGORY_ID'),
                            'category_name': cat_name,
                            'description': cat.get('DESCRIPTION', ''),
                            'confidentiality_level': int(cat.get('CONFIDENTIALITY_LEVEL', 1)),
                            'integrity_level': int(cat.get('INTEGRITY_LEVEL', 1)),
                            'availability_level': int(cat.get('AVAILABILITY_LEVEL', 1)),
                            'detection_threshold': float(cat.get('DETECTION_THRESHOLD', 0.5)),
                            'policy_group': cat.get('POLICY_GROUP', '').upper(),
                            'weight_embedding': float(cat.get('WEIGHT_EMBEDDING', 0.6)),
                            'weight_keyword': float(cat.get('WEIGHT_KEYWORD', 0.25)),
                            'weight_pattern': float(cat.get('WEIGHT_PATTERN', 0.15)),
                            'multi_label': bool(cat.get('MULTI_LABEL', True))
                        }
                    
                    if self._cache_enabled:
                        self._cache[cache_key] = categories_dict
                    
                    return categories_dict
                    
            except Exception as e:
                logger.debug(f"Could not load from {schema_fqn}: {e}")
                continue
        
        logger.warning("Failed to load sensitivity categories from any schema location")
        return {}

    def load_sensitive_keywords(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load sensitive keywords grouped by category.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping category name to list of keyword dictionaries
        """
        cache_key = "sensitive_keywords"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached sensitive keywords")
            return self._cache[cache_key]

        # Try different possible schema locations
        possible_schemas = [
            f"{self.governance_db}.{self.governance_schema}",
            f"{self.governance_db}.DATA_CLASSIFICATION_GOVERNANCE",
            "DATA_CLASSIFICATION_GOVERNANCE"
        ]

        keywords_by_category = {}
        
        for schema_fqn in possible_schemas:
            query = f"""
                SELECT
                    k.KEYWORD_ID,
                    k.CATEGORY_ID,
                    k.KEYWORD_STRING,
                    k.MATCH_TYPE,
                    k.SENSITIVITY_WEIGHT,
                    k.IS_ACTIVE,
                    c.CATEGORY_NAME
                FROM {schema_fqn}.SENSITIVE_KEYWORDS k
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                    ON k.CATEGORY_ID = c.CATEGORY_ID
                WHERE k.IS_ACTIVE = TRUE
                ORDER BY c.CATEGORY_NAME, k.KEYWORD_STRING
            """

            try:
                results = self._execute_query(query)
                if results:
                    logger.info(f"Loaded {len(results)} sensitive keywords from {schema_fqn}")
                    
                    # Group by category
                    for row in results:
                        cat_name = row.get('CATEGORY_NAME', '').upper()
                        if cat_name not in keywords_by_category:
                            keywords_by_category[cat_name] = []
                        keywords_by_category[cat_name].append({
                            'keyword_id': row.get('KEYWORD_ID'),
                            'keyword': row.get('KEYWORD_STRING', '').lower(),
                            'match_type': row.get('MATCH_TYPE', 'CONTAINS').upper(),
                            'weight': float(row.get('SENSITIVITY_WEIGHT', 0.5))
                        })
                    
                    if self._cache_enabled:
                        self._cache[cache_key] = keywords_by_category
                    
                    return keywords_by_category
                    
            except Exception as e:
                logger.debug(f"Could not load from {schema_fqn}: {e}")
                continue
        
        logger.warning("Failed to load sensitive keywords from any schema location")
        return {}

    def load_sensitive_patterns(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load sensitive patterns grouped by category.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping category name to list of pattern dictionaries
        """
        cache_key = "sensitive_patterns"
        
        if not force_refresh and self._cache_enabled and cache_key in self._cache:
            logger.debug("Returning cached sensitive patterns")
            return self._cache[cache_key]

        # Try different possible schema locations
        possible_schemas = [
            f"{self.governance_db}.{self.governance_schema}",
            f"{self.governance_db}.DATA_CLASSIFICATION_GOVERNANCE",
            "DATA_CLASSIFICATION_GOVERNANCE"
        ]

        patterns_by_category = {}
        
        for schema_fqn in possible_schemas:
            query = f"""
                SELECT
                    p.PATTERN_ID,
                    p.CATEGORY_ID,
                    p.PATTERN_NAME,
                    p.PATTERN_REGEX,
                    p.DESCRIPTION,
                    p.SENSITIVITY_WEIGHT,
                    p.IS_ACTIVE,
                    c.CATEGORY_NAME
                FROM {schema_fqn}.SENSITIVE_PATTERNS p
                JOIN {schema_fqn}.SENSITIVITY_CATEGORIES c
                    ON p.CATEGORY_ID = c.CATEGORY_ID
                WHERE p.IS_ACTIVE = TRUE
                ORDER BY c.CATEGORY_NAME, p.PATTERN_NAME
            """

            try:
                results = self._execute_query(query)
                if results:
                    logger.info(f"Loaded {len(results)} sensitive patterns from {schema_fqn}")
                    
                    # Group by category
                    for row in results:
                        cat_name = row.get('CATEGORY_NAME', '').upper()
                        if cat_name not in patterns_by_category:
                            patterns_by_category[cat_name] = []
                        patterns_by_category[cat_name].append({
                            'pattern_id': row.get('PATTERN_ID'),
                            'pattern_name': row.get('PATTERN_NAME', ''),
                            'pattern_regex': row.get('PATTERN_REGEX', ''),
                            'description': row.get('DESCRIPTION', ''),
                            'weight': float(row.get('SENSITIVITY_WEIGHT', 0.5))
                        })
                    
                    if self._cache_enabled:
                        self._cache[cache_key] = patterns_by_category
                    
                    return patterns_by_category
                    
            except Exception as e:
                logger.debug(f"Could not load from {schema_fqn}: {e}")
                continue
        
        logger.warning("Failed to load sensitive patterns from any schema location")
        return {}

    def refresh_all_rules(self) -> None:
        """Refresh all governance rules from database (clear cache and reload)."""
        logger.info("Refreshing all governance rules from database")
        self._cache.clear()
        
        # Reload all rules
        self.load_classification_rules(force_refresh=True)
        self.load_tiebreaker_keywords(force_refresh=True)
        self.load_address_context_registry(force_refresh=True)
        self.load_generic_exclusions(force_refresh=True)
        self.load_sensitivity_categories(force_refresh=True)
        self.load_sensitive_keywords(force_refresh=True)
        self.load_sensitive_patterns(force_refresh=True)
        
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
governance_rules_loader = GovernanceRulesLoader()
