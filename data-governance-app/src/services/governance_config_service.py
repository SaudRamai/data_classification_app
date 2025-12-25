"""
Unified Governance Configuration Service

Consolidates governance DB resolution, rules loading, and seeding/refresh
into a single service and public interface.

Public API:
- resolve_context(force_refresh: bool = False) -> dict
- load_config(force_refresh: bool = False) -> dict
- refresh(database: Optional[str] = None, sql_file: Optional[str] = None) -> dict
- clear_cache() -> None

This service is the single source of truth for governance configuration.
Legacy modules (governance_db_resolver, governance_rules_loader, seed_governance_service)
have been inlined here.
"""
from __future__ import annotations

import logging
import json
import os
import re
import pathlib
from typing import Any, Dict, Optional, List, Iterable

try:
    import streamlit as st
except Exception:
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

# Constants for governance resolution
EXPECTED_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
EXPECTED_TABLES = ("ASSETS", "CLASSIFICATION_HISTORY", "RECLASSIFICATION_REQUESTS")
INVALID_DB_VALUES = {"NONE", "NULL", "UNKNOWN", "(NONE)"}

# Constants for seeding
_here = pathlib.Path(str(__file__)).resolve()
SQL_FILE_DEFAULT = str(_here.parent.parent.parent / "sql" / "011_seed_sensitivity_config.sql")
SEED_TABLES = [
    "SENSITIVE_PATTERNS",
    "SENSITIVE_KEYWORDS",
    "SENSITIVITY_CATEGORIES",
    "SENSITIVITY_THRESHOLDS",
    "SENSITIVE_BUNDLES",
    "COMPLIANCE_MAPPING",
    "SENSITIVITY_MODEL_CONFIG",
]


class GovernanceRulesLoader:
    """Service for loading all governance rules from dynamic views (V2 - Enhanced)."""

    def __init__(self, governance_db: str, governance_schema: str = "DATA_CLASSIFICATION_GOVERNANCE"):
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

    def load_context_aware_rules(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load context-aware adjustment rules from VW_CONTEXT_AWARE_RULES view.
        These rules boost/reduce scores based on table and column context.

        Args:
            force_refresh: If True, bypass cache and reload from database

        Returns:
            Dictionary mapping rule type to list of rules
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
                policy_group = str(row.get('POLICY_GROUP', '')).upper()
                if policy_group not in keywords_by_group:
                    keywords_by_group[policy_group] = []
                keywords_by_group[policy_group].append({
                    'keyword': str(row.get('KEYWORD', '')).lower(),
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
                keyword = str(row.get('KEYWORD_PARSED', '')).lower().strip()
                
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
                policy_group = str(row.get('POLICY_GROUP', '')).upper()
                if policy_group not in keywords_by_group:
                    keywords_by_group[policy_group] = []
                keywords_by_group[policy_group].append({
                    'keyword': str(row.get('KEYWORD_STRING', '')).lower(),
                    'match_type': str(row.get('MATCH_TYPE', 'CONTAINS')).upper(),
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
                cat_name = str(row.get('CATEGORY_NAME', '')).upper()
                weights_by_category[cat_name] = {
                    'category_id': row.get('CATEGORY_ID'),
                    'policy_group': str(row.get('POLICY_GROUP', '')).upper(),
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
                cat_name = str(row.get('CATEGORY_NAME', '')).upper()
                metadata_by_category[cat_name] = {
                    'category_id': row.get('CATEGORY_ID'),
                    'category_name': cat_name,
                    'description': row.get('DESCRIPTION', ''),
                    'policy_group': str(row.get('POLICY_GROUP', '')).upper(),
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



class GovernanceConfigService:
    def __init__(self) -> None:
        self._cache: Dict[str, Any] = {}
        self._loader: Optional[GovernanceRulesLoader] = None
        self._db: Optional[str] = None
        self._schema: str = "DATA_CLASSIFICATION_GOVERNANCE"

    def _has_any_table(self, db: str, tables: Iterable[str]) -> bool:
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT count(*) as CNT FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME IN ({", ".join(["%(t" + str(i) + ")s" for i in range(len(list(tables)))])})
                """,
                {"sc": self._schema, **{f"t{i}": t for i, t in enumerate(tables)}},
            ) or []
            return int(rows[0].get("CNT", 0)) > 0
        except Exception:
            return False

    def _resolve_db_internal(self) -> str:
        """Resolve governance DB using session -> settings -> current_db -> probe."""
        # 1) Streamlit Session
        if st is not None:
            try:
                v = st.session_state.get("sf_database")
                if v and str(v).strip().upper() not in INVALID_DB_VALUES:
                    return str(v).strip()
            except Exception: pass

        # 2) Settings
        try:
            conf = getattr(settings, "SNOWFLAKE_DATABASE", None)
            if conf and str(conf).strip().upper() not in INVALID_DB_VALUES:
                return str(conf).strip()
        except Exception: pass

        # 3) Current DB Probe
        try:
            rows = snowflake_connector.execute_query("SELECT current_database() as DB") or []
            db = rows[0].get("DB")
            if db and str(db).strip().upper() not in INVALID_DB_VALUES:
                if self._has_any_table(str(db), EXPECTED_TABLES):
                    return str(db)
        except Exception: pass

        # 4) Global Probe
        try:
            db_rows = snowflake_connector.execute_query("SHOW DATABASES") or []
            names = [r.get("name") or r.get("NAME") for r in db_rows if (r.get("name") or r.get("NAME"))]
            for name in names:
                if name and self._has_any_table(str(name), EXPECTED_TABLES):
                    return str(name)
        except Exception: pass

        return "DATA_CLASSIFICATION_DB"

    def resolve_context(self, force_refresh: bool = False) -> Dict[str, Any]:
        if not force_refresh and self._db:
            return {"database": self._db, "schema": self._schema, "method": "CACHE"}

        db = self._resolve_db_internal()
        self._db = db
        self._loader = GovernanceRulesLoader(governance_db=db, governance_schema=self._schema)
        logger.info(f"GovConfig: Context resolved to {db}.{self._schema}")
        return {"database": db, "schema": self._schema, "method": "RESOLVED"}

    def _ensure_loader(self) -> GovernanceRulesLoader:
        if self._loader is None:
            self.resolve_context()
        assert self._loader is not None
        return self._loader

    @property
    def loader(self) -> GovernanceRulesLoader:
        """Returns the active governance rules loader."""
        return self._ensure_loader()

    def load_config(self, force_refresh: bool = False) -> Dict[str, Any]:
        if not force_refresh and self._cache.get("loaded"):
            return dict(self._cache)

        loader = self._ensure_loader()
        ctx = self.resolve_context(force_refresh=force_refresh)
        
        bundle: Dict[str, Any] = {
            "database": ctx["database"],
            "schema": ctx["schema"],
        }
        try:
            bundle["rules"] = loader.load_classification_rules(force_refresh)
            bundle["context_rules"] = loader.load_context_aware_rules(force_refresh)
            bundle["tiebreakers"] = loader.load_tiebreaker_keywords(force_refresh)
            bundle["address_indicators"] = loader.load_address_context_indicators(force_refresh)
            bundle["exclusions"] = loader.load_exclusion_patterns(force_refresh)
            bundle["policy_group_keywords"] = loader.load_policy_group_keywords(force_refresh)
            bundle["category_weights"] = loader.load_category_scoring_weights(force_refresh)
            bundle["category_metadata"] = loader.load_category_metadata(force_refresh)
            bundle["loaded"] = True
            self._cache = dict(bundle)
        except Exception as e:
            logger.error(f"GovConfig: Failed to load config bundle: {e}")
            bundle["loaded"] = False
            self._cache = dict(bundle)
        return dict(self._cache)

    def refresh(self, database: Optional[str] = None, sql_file: Optional[str] = None) -> Dict[str, Any]:
        """Inlined seeding logic from seed_governance_service."""
        db = database or self._db or self._resolve_db_internal()
        if db:
            snowflake_connector.execute_non_query(f"CREATE DATABASE IF NOT EXISTS {db}")
            snowflake_connector.execute_non_query(f"USE DATABASE {db}")
        
        path = sql_file or SQL_FILE_DEFAULT
        try:
            with open(path, "r", encoding="utf-8") as f:
                sql_text = f.read()
            # Split and execute
            statements = [s.strip() for s in sql_text.split(";") if s.strip()]
            success, failures = 0, []
            for s in statements:
                try:
                    snowflake_connector.execute_non_query(s)
                    success += 1
                except Exception as e:
                    failures.append(f"{str(e)} | STMT: {s[:100]}...")
            
            # Post-step: fix IS_ACTIVE
            for t in ["SENSITIVE_PATTERNS", "SENSITIVE_KEYWORDS", "SENSITIVITY_CATEGORIES"]:
                try:
                    snowflake_connector.execute_non_query(
                        f"UPDATE {db}.{self._schema}.{t} SET IS_ACTIVE = TRUE WHERE COALESCE(IS_ACTIVE, FALSE) = FALSE"
                    )
                except Exception: pass
            
            # Clear caches
            self.clear_cache()
            self.load_config(force_refresh=True)
            
            return {
                "seed": {"success": success, "failures": len(failures), "details": failures},
                "config": {"loaded": self._cache.get("loaded", False)}
            }
        except Exception as e:
            logger.error(f"GovConfig: Refresh failed: {e}")
            return {"error": str(e)}

    def clear_cache(self) -> None:
        self._cache.clear()
        if self._loader: self._loader.clear_cache()


governance_config_service = GovernanceConfigService()
