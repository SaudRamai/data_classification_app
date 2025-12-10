"""
Data Classification Governance Views Setup and Test Script

This script:
1. Creates/updates all governance views in Snowflake
2. Validates that all views are working correctly
3. Tests the governance_rules_loader_v2 service
4. Generates a comprehensive report

Author: AI Classification System
Date: 2025-12-05
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, List

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import required services
try:
    from src.connectors.snowflake_connector import snowflake_connector
    from src.services.governance_rules_loader_v2 import governance_rules_loader
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    sys.exit(1)


class GovernanceViewsSetup:
    """Setup and validate all governance views."""

    def __init__(self, governance_db: str = "DATA_CLASSIFICATION_DB", 
                 governance_schema: str = "DATA_CLASSIFICATION_GOVERNANCE"):
        self.governance_db = governance_db
        self.governance_schema = governance_schema
        self.results: Dict[str, Any] = {}

    def execute_sql_file(self, sql_file_path: str) -> bool:
        """
        Execute SQL script file.
        
        Args:
            sql_file_path: Path to SQL file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            sql_path = Path(sql_file_path)
            if not sql_path.exists():
                logger.error(f"SQL file not found: {sql_file_path}")
                return False

            logger.info(f"Reading SQL file: {sql_file_path}")
            with open(sql_path, 'r', encoding='utf-8') as f:
                sql_content = f.read()

            # Split into individual statements (simple split on semicolon)
            statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
            
            logger.info(f"Found {len(statements)} SQL statements to execute")
            
            success_count = 0
            for i, statement in enumerate(statements, 1):
                # Skip comments and USE statements for now
                if statement.startswith('--') or statement.upper().startswith('USE'):
                    continue
                    
                if 'CREATE OR REPLACE VIEW' in statement.upper():
                    # Extract view name for logging
                    view_name = "UNKNOWN"
                    if 'VW_' in statement:
                        start = statement.upper().index('VW_')
                        end = statement.index(' ', start) if ' ' in statement[start:] else len(statement)
                        view_name = statement[start:end].split()[0]
                    
                    logger.info(f"Creating view: {view_name}")
                    try:
                        snowflake_connector.execute_query(statement)
                        logger.info(f"✓ Successfully created: {view_name}")
                        success_count += 1
                    except Exception as e:
                        logger.error(f"✗ Failed to create {view_name}: {e}")
                        
            logger.info(f"Successfully created {success_count} views")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Failed to execute SQL file: {e}")
            return False

    def verify_views(self) -> Dict[str, int]:
        """
        Verify all views exist and have data.
        
        Returns:
            Dictionary mapping view name to row count
        """
        views = [
            'VW_CLASSIFICATION_RULES',
            'VW_POLICY_GROUP_KEYWORDS',
            'VW_CONTEXT_AWARE_RULES',
            'VW_TIEBREAKER_KEYWORDS',
            'VW_EXCLUSION_PATTERNS',
            'VW_CATEGORY_METADATA',
            'VW_ADDRESS_CONTEXT_INDICATORS',
            'VW_CATEGORY_MAPPING_VALIDATION',
            'VW_CATEGORY_SCORING_WEIGHTS'
        ]
        
        view_counts: Dict[str, int] = {}
        
        logger.info("\n" + "="*80)
        logger.info("VERIFYING GOVERNANCE VIEWS")
        logger.info("="*80)
        
        for view_name in views:
            try:
                query = f"""
                    SELECT COUNT(*) as CNT 
                    FROM {self.governance_db}.{self.governance_schema}.{view_name}
                """
                result = snowflake_connector.execute_query(query)
                
                if result:
                    count = result[0]['CNT'] if isinstance(result, list) else result.get('CNT', 0)
                    view_counts[view_name] = count
                    status = "✓" if count > 0 else "⚠"
                    logger.info(f"{status} {view_name}: {count} rows")
                else:
                    view_counts[view_name] = 0
                    logger.warning(f"✗ {view_name}: No data returned")
                    
            except Exception as e:
                view_counts[view_name] = -1
                logger.error(f"✗ {view_name}: ERROR - {e}")
        
        self.results['view_counts'] = view_counts
        return view_counts

    def test_governance_loader(self) -> Dict[str, Any]:
        """
        Test the governance_rules_loader_v2 service.
        
        Returns:
            Dictionary with test results
        """
        logger.info("\n" + "="*80)
        logger.info("TESTING GOVERNANCE RULES LOADER")
        logger.info("="*80)
        
        test_results: Dict[str, Any] = {}
        
        # Test 1: Load classification rules
        try:
            logger.info("\nTest 1: Loading classification rules...")
            rules = governance_rules_loader.load_classification_rules(force_refresh=True)
            test_results['classification_rules_count'] = len(rules)
            logger.info(f"✓ Loaded {len(rules)} classification rules")
            
            if rules:
                # Show sample
                sample = rules[0]
                logger.info(f"  Sample rule: {sample.get('RULE_TYPE')} - {sample.get('RULE_PATTERN')} ({sample.get('POLICY_GROUP')})")
        except Exception as e:
            test_results['classification_rules_error'] = str(e)
            logger.error(f"✗ Failed to load classification rules: {e}")

        # Test 2: Load context-aware rules
        try:
            logger.info("\nTest 2: Loading context-aware rules...")
            context_rules = governance_rules_loader.load_context_aware_rules(force_refresh=True)
            test_results['context_rules_types'] = list(context_rules.keys())
            total_rules = sum(len(rules) for rules in context_rules.values())
            logger.info(f"✓ Loaded {total_rules} context-aware rules in {len(context_rules)} categories")
            
            for rule_type, rules in context_rules.items():
                logger.info(f"  - {rule_type}: {len(rules)} rules")
        except Exception as e:
            test_results['context_rules_error'] = str(e)
            logger.error(f"✗ Failed to load context-aware rules: {e}")

        # Test 3: Load tiebreaker keywords
        try:
            logger.info("\nTest 3: Loading tiebreaker keywords...")
            tiebreakers = governance_rules_loader.load_tiebreaker_keywords(force_refresh=True)
            test_results['tiebreaker_groups'] = list(tiebreakers.keys())
            total_keywords = sum(len(kws) for kws in tiebreakers.values())
            logger.info(f"✓ Loaded {total_keywords} tiebreaker keywords for {len(tiebreakers)} policy groups")
            
            for group, keywords in tiebreakers.items():
                logger.info(f"  - {group}: {len(keywords)} keywords")
        except Exception as e:
            test_results['tiebreaker_error'] = str(e)
            logger.error(f"✗ Failed to load tiebreaker keywords: {e}")

        # Test 4: Load address context indicators
        try:
            logger.info("\nTest 4: Loading address context indicators...")
            indicators = governance_rules_loader.load_address_context_indicators(force_refresh=True)
            test_results['address_indicators_count'] = len(indicators)
            logger.info(f"✓ Loaded {len(indicators)} address context indicators")
            
            if indicators:
                sample = indicators[0]
                logger.info(f"  Sample: {sample.get('CONTEXT_TYPE')} - {sample.get('INDICATOR_KEYWORD')}")
        except Exception as e:
            test_results['address_indicators_error'] = str(e)
            logger.error(f"✗ Failed to load address context indicators: {e}")

        # Test 5: Load exclusion patterns
        try:
            logger.info("\nTest 5: Loading exclusion patterns...")
            exclusions = governance_rules_loader.load_exclusion_patterns(force_refresh=True)
            test_results['exclusion_patterns_count'] = len(exclusions)
            logger.info(f"✓ Loaded {len(exclusions)} exclusion patterns")
            
            for exclusion in exclusions:
                exc_type = exclusion.get('EXCLUSION_TYPE', 'UNKNOWN')
                keywords = exclusion.get('KEYWORDS_PARSED', [])
                logger.info(f"  - {exc_type}: {len(keywords)} keywords")
        except Exception as e:
            test_results['exclusion_patterns_error'] = str(e)
            logger.error(f"✗ Failed to load exclusion patterns: {e}")

        # Test 6: Load policy group keywords
        try:
            logger.info("\nTest 6: Loading policy group keywords...")
            pg_keywords = governance_rules_loader.load_policy_group_keywords(force_refresh=True)
            test_results['policy_group_keywords_groups'] = list(pg_keywords.keys())
            total_keywords = sum(len(kws) for kws in pg_keywords.values())
            logger.info(f"✓ Loaded {total_keywords} keywords for {len(pg_keywords)} policy groups")
            
            for group, keywords in pg_keywords.items():
                logger.info(f"  - {group}: {len(keywords)} keywords")
        except Exception as e:
            test_results['policy_group_keywords_error'] = str(e)
            logger.error(f"✗ Failed to load policy group keywords: {e}")

        # Test 7: Load category metadata
        try:
            logger.info("\nTest 7: Loading category metadata...")
            metadata = governance_rules_loader.load_category_metadata(force_refresh=True)
            test_results['category_metadata_count'] = len(metadata)
            logger.info(f"✓ Loaded metadata for {len(metadata)} categories")
            
            if metadata:
                # Show sample
                sample_cat = list(metadata.keys())[0]
                sample_data = metadata[sample_cat]
                logger.info(f"  Sample: {sample_cat} - {sample_data.get('policy_group')} " +
                          f"(Keywords: {sample_data.get('keyword_count')}, Patterns: {sample_data.get('pattern_count')})")
        except Exception as e:
            test_results['category_metadata_error'] = str(e)
            logger.error(f"✗ Failed to load category metadata: {e}")

        # Test 8: Load category scoring weights
        try:
            logger.info("\nTest 8: Loading category scoring weights...")
            weights = governance_rules_loader.load_category_scoring_weights(force_refresh=True)
            test_results['scoring_weights_count'] = len(weights)
            logger.info(f"✓ Loaded scoring weights for {len(weights)} categories")
        except Exception as e:
            test_results['scoring_weights_error'] = str(e)
            logger.error(f"✗ Failed to load category scoring weights: {e}")

        self.results['loader_tests'] = test_results
        return test_results

    def diagnostic_check_data_quality(self) -> Dict[str, Any]:
        """
        Run diagnostic queries to check data quality of patterns and keywords.
        
        Returns:
            Dictionary with diagnostic results
        """
        logger.info("\n" + "="*80)
        logger.info("RUNNING DATA QUALITY DIAGNOSTICS")
        logger.info("="*80)
        
        diagnostics: Dict[str, Any] = {}
        
        # Diagnostic 1: Check for problematic patterns and keywords
        try:
            logger.info("\nDiagnostic 1: Checking patterns and keywords quality...")
            
            query = f"""
                -- Check for problematic patterns
                SELECT 
                    'PATTERNS' AS RULE_TYPE,
                    COUNT(*) AS TOTAL,
                    COUNT(CASE WHEN PATTERN_REGEX LIKE '%%' THEN 1 END) AS BROKEN_PATTERNS,
                    COUNT(CASE WHEN SENSITIVITY_WEIGHT < 0.5 THEN 1 END) AS LOW_WEIGHT,
                    LISTAGG(
                        CASE WHEN PATTERN_REGEX LIKE '%%' THEN PATTERN_NAME END, 
                        ', '
                    ) AS BROKEN_PATTERN_NAMES
                FROM {self.governance_db}.{self.governance_schema}.SENSITIVE_PATTERNS
                WHERE IS_ACTIVE = TRUE
                GROUP BY RULE_TYPE
                
                UNION ALL
                
                -- Check for problematic keywords
                SELECT 
                    'KEYWORDS' AS RULE_TYPE,
                    COUNT(*) AS TOTAL,
                    COUNT(CASE WHEN LENGTH(KEYWORD_STRING) < 3 THEN 1 END) AS SHORT_KEYWORDS,
                    COUNT(CASE WHEN SENSITIVITY_WEIGHT < 0.5 THEN 1 END) AS LOW_WEIGHT,
                    LISTAGG(
                        CASE WHEN LENGTH(KEYWORD_STRING) < 3 THEN KEYWORD_STRING END, 
                        ', '
                    ) AS SHORT_KEYWORD_NAMES
                FROM {self.governance_db}.{self.governance_schema}.SENSITIVE_KEYWORDS
                WHERE IS_ACTIVE = TRUE
                GROUP BY RULE_TYPE
            """
            
            results = snowflake_connector.execute_query(query)
            
            if results:
                for result in results:
                    rule_type = result.get('RULE_TYPE', 'UNKNOWN')
                    total = result.get('TOTAL', 0)
                    
                    if rule_type == 'PATTERNS':
                        broken = result.get('BROKEN_PATTERNS', 0)
                        low_weight = result.get('LOW_WEIGHT', 0)
                        broken_names = result.get('BROKEN_PATTERN_NAMES', '')
                        
                        logger.info(f"\n📊 Patterns Summary:")
                        logger.info(f"  - Total active patterns: {total}")
                        logger.info(f"  - Broken patterns (%%): {broken}")
                        logger.info(f"  - Low weight patterns (< 0.5): {low_weight}")
                        
                        if broken > 0 and broken_names:
                            logger.warning(f"  ⚠ Broken patterns: {broken_names}")
                        
                        diagnostics['patterns'] = {
                            'total': total,
                            'broken': broken,
                            'low_weight': low_weight,
                            'broken_names': broken_names
                        }
                    
                    elif rule_type == 'KEYWORDS':
                        short = result.get('SHORT_KEYWORDS', 0)
                        low_weight = result.get('LOW_WEIGHT', 0)
                        short_names = result.get('SHORT_KEYWORD_NAMES', '')
                        
                        logger.info(f"\n📊 Keywords Summary:")
                        logger.info(f"  - Total active keywords: {total}")
                        logger.info(f"  - Short keywords (< 3 chars): {short}")
                        logger.info(f"  - Low weight keywords (< 0.5): {low_weight}")
                        
                        if short > 0 and short_names:
                            logger.warning(f"  ⚠ Short keywords: {short_names}")
                        
                        diagnostics['keywords'] = {
                            'total': total,
                            'short': short,
                            'low_weight': low_weight,
                            'short_names': short_names
                        }
                
                logger.info("\n✓ Data quality diagnostics completed")
            
        except Exception as e:
            logger.error(f"✗ Failed to run pattern/keyword diagnostics: {e}")
            diagnostics['error'] = str(e)
        
        # Diagnostic 2: View final classification rules distribution
        try:
            logger.info("\nDiagnostic 2: Checking classification rules distribution...")
            
            query = f"""
                SELECT 
                    RULE_TYPE,
                    CATEGORY_NAME,
                    POLICY_GROUP,
                    COUNT(*) AS RULE_COUNT,
                    ROUND(AVG(RULE_WEIGHT), 2) AS AVG_WEIGHT,
                    LISTAGG(DISTINCT PRIORITY_TIER, ', ') AS PRIORITY_TIERS,
                    MIN(RULE_WEIGHT) AS MIN_WEIGHT,
                    MAX(RULE_WEIGHT) AS MAX_WEIGHT
                FROM {self.governance_db}.{self.governance_schema}.VW_CLASSIFICATION_RULES
                WHERE IS_ACTIVE = TRUE
                GROUP BY RULE_TYPE, CATEGORY_NAME, POLICY_GROUP
                ORDER BY POLICY_GROUP, CATEGORY_NAME, RULE_TYPE
            """
            
            results = snowflake_connector.execute_query(query)
            
            if results:
                logger.info(f"\n📊 Classification Rules Distribution ({len(results)} categories):")
                logger.info(f"\n{'Policy Group':<12} {'Category':<30} {'Type':<10} {'Count':<7} {'Avg Wt':<8} {'Min':<6} {'Max':<6}")
                logger.info("-" * 90)
                
                for result in results[:20]:  # Show first 20
                    policy = result.get('POLICY_GROUP', '')[:12]
                    category = result.get('CATEGORY_NAME', '')[:30]
                    rule_type = result.get('RULE_TYPE', '')[:10]
                    count = result.get('RULE_COUNT', 0)
                    avg_wt = result.get('AVG_WEIGHT', 0.0)
                    min_wt = result.get('MIN_WEIGHT', 0.0)
                    max_wt = result.get('MAX_WEIGHT', 0.0)
                    
                    logger.info(f"{policy:<12} {category:<30} {rule_type:<10} {count:<7} {avg_wt:<8.2f} {min_wt:<6.2f} {max_wt:<6.2f}")
                
                if len(results) > 20:
                    logger.info(f"... and {len(results) - 20} more categories")
                
                diagnostics['rule_distribution'] = results
                logger.info("\n✓ Rule distribution analysis completed")
            
        except Exception as e:
            logger.error(f"✗ Failed to run rule distribution analysis: {e}")
        
        self.results['diagnostics'] = diagnostics
        return diagnostics

    def check_mapping_validation(self) -> List[Dict[str, Any]]:
        """
        Check for any mapping validation issues.
        
        Returns:
            List of validation issues found
        """
        logger.info("\n" + "="*80)
        logger.info("CHECKING MAPPING VALIDATION")
        logger.info("="*80)
        
        try:
            query = f"""
                SELECT 
                    ISSUE_TYPE,
                    KEYWORD_STRING,
                    CATEGORY_NAME,
                    POLICY_GROUP,
                    RECOMMENDED_ACTION
                FROM {self.governance_db}.{self.governance_schema}.VW_CATEGORY_MAPPING_VALIDATION
                LIMIT 50
            """
            
            issues = snowflake_connector.execute_query(query)
            
            if issues:
                logger.warning(f"⚠ Found {len(issues)} mapping validation issues:")
                for issue in issues[:10]:  # Show first 10
                    logger.warning(f"  - {issue.get('ISSUE_TYPE')}: {issue.get('KEYWORD_STRING')} " +
                                 f"in {issue.get('CATEGORY_NAME')} ({issue.get('POLICY_GROUP')})")
                    logger.warning(f"    → {issue.get('RECOMMENDED_ACTION')}")
            else:
                logger.info("✓ No mapping validation issues found")
            
            self.results['mapping_issues'] = issues if issues else []
            return issues if issues else []
            
        except Exception as e:
            logger.error(f"✗ Failed to check mapping validation: {e}")
            return []

    def generate_report(self) -> str:
        """
        Generate a comprehensive setup report.
        
        Returns:
            Report as markdown string
        """
        report = "# Governance Views Setup Report\n\n"
        report += f"**Date:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # View counts
        if 'view_counts' in self.results:
            report += "## View Status\n\n"
            report += "| View Name | Row Count | Status |\n"
            report += "|-----------|-----------|--------|\n"
            for view, count in self.results['view_counts'].items():
                status = "✓ OK" if count > 0 else ("⚠ Empty" if count == 0 else "✗ Error")
                report += f"| {view} | {count} | {status} |\n"
            report += "\n"
        
        # Loader test results
        if 'loader_tests' in self.results:
            report += "## Governance Loader Tests\n\n"
            tests = self.results['loader_tests']
            
            for key, value in tests.items():
                if not key.endswith('_error'):
                    report += f"- **{key}**: {value}\n"
                else:
                    report += f"- ⚠ **{key}**: {value}\n"
            report += "\n"
        
        # Mapping issues
        if 'mapping_issues' in self.results:
            issues = self.results['mapping_issues']
            report += f"## Mapping Validation Issues ({len(issues)} found)\n\n"
            
            if issues:
                report += "| Issue Type | Keyword | Category | Policy Group | Action |\n"
                report += "|------------|---------|----------|--------------|--------|\n"
                for issue in issues[:20]:  # Limit to 20 in report
                    report += f"| {issue.get('ISSUE_TYPE')} | {issue.get('KEYWORD_STRING')} | "
                    report += f"{issue.get('CATEGORY_NAME')} | {issue.get('POLICY_GROUP')} | "
                    report += f"{issue.get('RECOMMENDED_ACTION')} |\n"
            else:
                report += "✓ No mapping validation issues found.\n"
            report += "\n"
        
        # Summary
        report += "## Summary\n\n"
        
        view_counts = self.results.get('view_counts', {})
        total_views = len(view_counts)
        ok_views = sum(1 for count in view_counts.values() if count > 0)
        
        report += f"- **Total Views**: {total_views}\n"
        report += f"- **Views with Data**: {ok_views}\n"
        report += f"- **Views Empty/Error**: {total_views - ok_views}\n"
        
        loader_tests = self.results.get('loader_tests', {})
        error_count = sum(1 for key in loader_tests.keys() if key.endswith('_error'))
        
        report += f"- **Loader Tests Passed**: {len(loader_tests) - error_count}\n"
        report += f"- **Loader Tests Failed**: {error_count}\n"
        
        if ok_views == total_views and error_count == 0:
            report += "\n**✓ All systems operational!**\n"
        else:
            report += "\n**⚠ Some issues detected - please review above.**\n"
        
        return report


def main():
    """Main execution function."""
    logger.info("="*80)
    logger.info("GOVERNANCE VIEWS SETUP AND VALIDATION")
    logger.info("="*80)
    
    setup = GovernanceViewsSetup()
    
    # Step 1: Execute SQL file to create views
    sql_file = "sql/CREATE_ALL_GOVERNANCE_VIEWS.sql"
    logger.info(f"\nStep 1: Creating views from {sql_file}")
    
    if setup.execute_sql_file(sql_file):
        logger.info("✓ Views creation completed")
    else:
        logger.warning("⚠ Views creation may have issues - continuing with validation...")
    
    # Step 2: Verify views
    logger.info("\nStep 2: Verifying views")
    setup.verify_views()
    
    # Step 3: Test governance loader
    logger.info("\nStep 3: Testing governance rules loader")
    setup.test_governance_loader()
    
    # Step 3.5: Run data quality diagnostics
    logger.info("\nStep 3.5: Running data quality diagnostics")
    setup.diagnostic_check_data_quality()
    
    # Step 4: Check mapping validation
    logger.info("\nStep 4: Checking mapping validation")
    setup.check_mapping_validation()
    
    # Step 5: Generate report
    logger.info("\nStep 5: Generating report")
    report = setup.generate_report()
    
    # Save report
    report_file = "GOVERNANCE_VIEWS_SETUP_REPORT.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"\n{'='*80}")
    logger.info(f"Report saved to: {report_file}")
    logger.info(f"{'='*80}\n")
    
    # Print report to console
    print("\n" + report)


if __name__ == "__main__":
    main()
