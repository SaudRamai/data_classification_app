"""
AI Classification Pipeline - Comprehensive Debugger
Implements systematic checkpoint validation per debugging framework
"""

import logging
import sys
from typing import Dict, List, Any, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class PipelineDebugger:
    """Systematic debugging of AI classification pipeline"""
    
    def __init__(self):
        self.service = None
        self.checkpoints_passed = []
        self.checkpoints_failed = []
        
    def run_full_diagnostic(self) -> Dict[str, Any]:
        """Execute complete diagnostic flowchart"""
        
        print("=" * 80)
        print("AI CLASSIFICATION PIPELINE - COMPREHENSIVE DIAGNOSTIC")
        print("=" * 80)
        print()
        
        results = {
            'checkpoints': {},
            'failure_modes': {},
            'recommended_fixes': []
        }
        
        # CHECKPOINT 1: Asset Discovery
        print("🔍 CHECKPOINT 1: Asset Discovery")
        print("-" * 80)
        cp1_result = self.checkpoint_1_asset_discovery()
        results['checkpoints']['asset_discovery'] = cp1_result
        
        if not cp1_result['passed']:
            results['recommended_fixes'].append({
                'priority': 'CRITICAL',
                'issue': 'Asset discovery failed',
                'fix': cp1_result['fix']
            })
            print()
            print("❌ CRITICAL FAILURE - Cannot proceed without assets")
            return results
        
        # CHECKPOINT 2: Pipeline Execution Path
        print()
        print("🔍 CHECKPOINT 2: Pipeline Execution Path")
        print("-" * 80)
        cp2_result = self.checkpoint_2_execution_path()
        results['checkpoints']['execution_path'] = cp2_result
        
        # FAILURE MODE A: Governance Metadata
        print()
        print("🔍 FAILURE MODE A: Governance Metadata Loading")
        print("-" * 80)
        fm_a_result = self.failure_mode_a_governance_metadata()
        results['failure_modes']['governance_metadata'] = fm_a_result
        
        if not fm_a_result['passed']:
            results['recommended_fixes'].append({
                'priority': 'HIGH',
                'issue': 'Governance metadata not loading',
                'fix': fm_a_result['fix']
            })
        
        # FAILURE MODE B: Embedding Initialization
        print()
        print("🔍 FAILURE MODE B: Embedding Initialization")
        print("-" * 80)
        fm_b_result = self.failure_mode_b_embeddings()
        results['failure_modes']['embeddings'] = fm_b_result
        
        if not fm_b_result['passed']:
            results['recommended_fixes'].append({
                'priority': 'MEDIUM',
                'issue': 'Embeddings not initialized',
                'fix': fm_b_result['fix']
            })
        
        # FAILURE MODE C: Policy Mapping
        print()
        print("🔍 FAILURE MODE C: Policy Mapping")
        print("-" * 80)
        fm_c_result = self.failure_mode_c_policy_mapping()
        results['failure_modes']['policy_mapping'] = fm_c_result
        
        if not fm_c_result['passed']:
            results['recommended_fixes'].append({
                'priority': 'CRITICAL',
                'issue': 'Policy mapping returns OTHER instead of PII/SOX/SOC2',
                'fix': fm_c_result['fix']
            })
        
        # FAILURE MODE D: Confidence Scores
        print()
        print("🔍 FAILURE MODE D: Confidence Scoring")
        print("-" * 80)
        fm_d_result = self.failure_mode_d_confidence()
        results['failure_modes']['confidence_scores'] = fm_d_result
        
        if not fm_d_result['passed']:
            results['recommended_fixes'].append({
                'priority': 'HIGH',
                'issue': 'Confidence scores too low',
                'fix': fm_d_result['fix']
            })
        
        # CHECKPOINT 3: Results Filtering
        print()
        print("🔍 CHECKPOINT 3: Results Filtering")
        print("-" * 80)
        cp3_result = self.checkpoint_3_filtering(
            cp1_result.get('sample_asset'),
            fm_a_result.get('categories_loaded', 0),
            fm_c_result.get('policy_map', {})
        )
        results['checkpoints']['filtering'] = cp3_result
        
        # FINAL SUMMARY
        print()
        print("=" * 80)
        print("DIAGNOSTIC SUMMARY")
        print("=" * 80)
        
        total_checks = len(results['checkpoints']) + len(results['failure_modes'])
        passed_checks = sum(1 for v in list(results['checkpoints'].values()) + list(results['failure_modes'].values()) if v.get('passed'))
        
        print(f"Checks Passed: {passed_checks}/{total_checks}")
        print()
        
        if results['recommended_fixes']:
            print("🔧 RECOMMENDED FIXES (in priority order):")
            print()
            for fix in sorted(results['recommended_fixes'], key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['priority'], 3)):
                print(f"  [{fix['priority']}] {fix['issue']}")
                print(f"    → {fix['fix']}")
                print()
        else:
            print("✅ ALL CHECKS PASSED - Pipeline should be working!")
            print()
        
        return results
    
    def checkpoint_1_asset_discovery(self) -> Dict[str, Any]:
        """CHECKPOINT 1: Verify asset discovery is working"""
        result = {
            'passed': False,
            'message': '',
            'assets_found': 0,
            'sample_asset': None,
            'fix': ''
        }
        
        try:
            # Import service
            from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
            self.service = AIClassificationPipelineService()
            
            # Get active database
            db = self.service._get_active_database()
            print(f"  Active Database: {db}")
            
            if not db or db.upper() in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
                result['message'] = "❌ No valid database configured"
                result['fix'] = "Set active database in global filters or config"
                print(f"  {result['message']}")
                return result
            
            print(f"  ✓ Database: {db}")
            
            # Try to discover assets
            try:
                assets = self.service._discover_assets(db)
                result['assets_found'] = len(assets)
                
                if assets:
                    result['sample_asset'] = assets[0]
                    result['passed'] = True
                    result['message'] = f"✓ Discovered {len(assets)} tables"
                    print(f"  {result['message']}")
                    
                    # Show sample
                    print(f"  Sample asset: {assets[0].get('schema')}.{assets[0].get('table')}")
                    
                    if len(assets) > 5:
                        print(f"  Others: {', '.join([f'{a.get(\"schema\")}.{a.get(\"table\")}' for a in assets[1:6]])}")
                else:
                    result['message'] = "❌ No tables discovered"
                    result['fix'] = "Check INFORMATION_SCHEMA.TABLES access and schema/table filters"
                    print(f"  {result['message']}")
                    
            except Exception as e:
                result['message'] = f"❌ Asset discovery failed: {e}"
                result['fix'] = "Check Snowflake permissions for INFORMATION_SCHEMA.TABLES"
                print(f"  {result['message']}")
                
        except Exception as e:
            result['message'] = f"❌ Service initialization failed: {e}"
            result['fix'] = "Check service imports and dependencies"
            print(f"  {result['message']}")
        
        return result
    
    def checkpoint_2_execution_path(self) -> Dict[str, Any]:
        """CHECKPOINT 2: Trace which classification method is being called"""
        result = {
            'passed': True,
            'message': '',
            'method': ''
        }
        
        try:
            # Check which method _classify_assets_local calls
            import inspect
            
            if self.service:
                method_code = inspect.getsource(self.service._classify_assets_local)
                
                if '_run_governance_driven_pipeline' in method_code:
                    result['method'] = '_run_governance_driven_pipeline'
                    result['message'] = "✓ Using governance-driven pipeline"
                    print(f"  {result['message']}")
                else:
                    result['method'] = 'unknown'
                    result['message'] = "⚠️ Classification path unclear"
                    result['passed'] = False
                    print(f"  {result['message']}")
        
        except Exception as e:
            result['message'] = f"⚠️ Could not inspect execution path: {e}"
            result['passed'] = False
            print(f"  {result['message']}")
        
        return result
    
    def failure_mode_a_governance_metadata(self) -> Dict[str, Any]:
        """FAILURE MODE A: Check governance metadata loading"""
        result = {
            'passed': False,
            'message': '',
            'categories_loaded': 0,
            'centroids_created': 0,
            'keywords_loaded': 0,
            'patterns_loaded': 0,
            'fix': ''
        }
        
        try:
            if not self.service:
                result['message'] = "❌ Service not initialized"
                return result
            
            # Initialize embeddings (loads governance metadata)
            self.service._init_local_embeddings()
            
            # Check what was loaded
            centroids = getattr(self.service, '_category_centroids', {})
            keywords = getattr(self.service, '_category_keywords', {})
            patterns = getattr(self.service, '_category_patterns', {})
            
            result['categories_loaded'] = len(centroids)
            result['centroids_created'] = len([c for c in centroids.values() if c is not None])
            result['keywords_loaded'] = sum(len(kws) for kws in keywords.values())
            result['patterns_loaded'] = sum(len(pats) for pats in patterns.values())
            
            print(f"  Categories loaded: {result['categories_loaded']}")
            print(f"  Centroids created: {result['centroids_created']}")
            print(f"  Keywords loaded: {result['keywords_loaded']}")
            print(f"  Patterns loaded: {result['patterns_loaded']}")
            
            if result['categories_loaded'] == 0:
                result['message'] = "❌ No categories loaded from governance tables"
                result['fix'] = "Run: .agent/diagnose_governance_tables.sql to check SENSITIVITY_CATEGORIES table"
                print(f"  {result['message']}")
            elif result['centroids_created'] == 0:
                result['message'] = "⚠️ Categories loaded but no centroids created"
                result['fix'] = "Check DESCRIPTION fields in SENSITIVITY_CATEGORIES (must not be empty)"
                result['passed'] = True  # Can still work with keywords
                print(f"  {result['message']}")
            else:
                result['message'] = f"✓ Governance metadata loaded successfully"
                result['passed'] = True
                print(f"  {result['message']}")
            
            # Show categories
            if centroids:
                print(f"  Categories: {', '.join(list(centroids.keys())[:5])}" + 
                      (f" (+{len(centroids)-5} more)" if len(centroids) > 5 else ""))
        
        except Exception as e:
            result['message'] = f"❌ Governance metadata loading failed: {e}"
            result['fix'] = "Check Snowflake governance database access and table permissions"
            print(f"  {result['message']}")
            import traceback
            traceback.print_exc()
        
        return result
    
    def failure_mode_b_embeddings(self) -> Dict[str, Any]:
        """FAILURE MODE B: Check embedding initialization"""
        result = {
            'passed': False,
            'message': '',
            'embedder_available': False,
            'backend': 'none',
            'fix': ''
        }
        
        try:
            if not self.service:
                result['message'] = "❌ Service not initialized"
                return result
            
            embedder = getattr(self.service, '_embedder', None)
            backend = getattr(self.service, '_embed_backend', 'none')
            
            result['embedder_available'] = embedder is not None
            result['backend'] = backend
            
            print(f"  Embedder available: {result['embedder_available']}")
            print(f"  Backend: {backend}")
            
            if embedder is None:
                result['message'] = "⚠️ Embeddings not available (using keyword-only mode)"
                result['fix'] = "Install sentence-transformers: pip install sentence-transformers"
                result['passed'] = True  # Not critical, can work without
                print(f"  {result['message']}")
            elif backend == 'none':
                result['message'] = "⚠️ Embedding backend not initialized"
                result['fix'] = "Check _init_local_embeddings() for errors"
                result['passed'] = True  # Not critical
                print(f"  {result['message']}")
            else:
                result['message'] = "✓ Embeddings initialized successfully"
                result['passed'] = True
                print(f"  {result['message']}")
                
                # Test embedding
                try:
                    test_vec = embedder.encode(["test"], normalize_embeddings=True)
                    dim = len(test_vec[0])
                    print(f"  Test embedding dimension: {dim}")
                except Exception as e:
                    print(f"  ⚠️ Embedding test failed: {e}")
        
        except Exception as e:
            result['message'] = f"❌ Embedding check failed: {e}"
            print(f"  {result['message']}")
        
        return result
    
    def failure_mode_c_policy_mapping(self) -> Dict[str, Any]:
        """FAILURE MODE C: Check policy mapping"""
        result = {
            'passed': False,
            'message': '',
            'policy_map': {},
            'fix': ''
        }
        
        try:
            if not self.service:
                result['message'] = "❌ Service not initialized"
                return result
            
            policy_map = getattr(self.service, '_policy_group_by_category', {})
            result['policy_map'] = policy_map
            
            print(f"  Policy mappings: {len(policy_map)} categories")
            
            if not policy_map:
                result['message'] = "❌ NO POLICY MAPPING - Categories won't map to PII/SOX/SOC2"
                result['fix'] = "Update SENSITIVITY_CATEGORIES descriptions to include 'personal', 'financial', or 'security' keywords"
                print(f"  {result['message']}")
                print(f"  This is CRITICAL - all detections will be filtered out!")
            else:
                result['message'] = f"✓ Policy mapping configured"
                result['passed'] = True
                print(f"  {result['message']}")
                
                # Show mappings
                for cat, policy in list(policy_map.items())[:5]:
                    print(f"    {cat} → {policy}")
                
                if len(policy_map) > 5:
                    print(f"    (+{len(policy_map)-5} more)")
                
                # Test mapping with sample categories
                print(f"  Testing mapping logic:")
                test_categories = ['CUSTOMER_DATA', 'FINANCIAL_INFO', 'SECURITY_LOG']
                for test_cat in test_categories:
                    mapped = self.service._map_category_to_policy_group(test_cat)
                    symbol = "✓" if mapped in {'PII', 'SOX', 'SOC2'} else "✗"
                    print(f"    {symbol} '{test_cat}' → '{mapped}'")
        
        except Exception as e:
            result['message'] = f"❌ Policy mapping check failed: {e}"
            print(f"  {result['message']}")
        
        return result
    
    def failure_mode_d_confidence(self) -> Dict[str, Any]:
        """FAILURE MODE D: Check confidence scoring"""
        result = {
            'passed': False,
            'message': '',
            'sample_scores': {},
            'fix': ''
        }
        
        try:
            if not self.service:
                result['message'] = "❌ Service not initialized"
                return result
            
            # Test scoring on sample text with PII indicators
            test_cases = [
                ("Column: customer_email | Type: VARCHAR | Comment: Customer email addresses", "PII"),
                ("Column: ssn | Type: VARCHAR | Comment: Social Security Number", "PII"),
                ("Column: account_balance | Type: NUMBER | Comment: Account balance in USD", "SOX"),
                ("Column: login_password | Type: VARCHAR | Comment: User login password hash", "SOC2"),
            ]
            
            print(f"  Testing confidence scoring on sample data:")
            
            all_passed = True
            for text, expected_type in test_cases:
                try:
                    scores = self.service._compute_governance_scores(text)
                    
                    if scores:
                        best_cat, best_score = max(scores.items(), key=lambda x: x[1])
                        mapped = self.service._map_category_to_policy_group(best_cat)
                        
                        # Check if it would pass filtering
                        would_pass = (mapped in {'PII', 'SOX', 'SOC2'}) and (best_score >= 0.25)
                        
                        symbol = "✓" if would_pass else "✗"
                        print(f"    {symbol} {text[:50]}...")
                        print(f"       → {best_cat} ({best_score:.3f}) → {mapped} | {'PASS' if would_pass else 'FILTERED'}")
                        
                        result['sample_scores'][text[:30]] = {
                            'category': best_cat,
                            'confidence': best_score,
                            'mapped': mapped,
                            'would_pass': would_pass
                        }
                        
                        if not would_pass:
                            all_passed = False
                    else:
                        print(f"    ✗ {text[:50]}...")
                        print(f"       → NO SCORES (would be filtered)")
                        all_passed = False
                
                except Exception as e:
                    print(f"    ✗ Scoring failed: {e}")
                    all_passed = False
            
            if all_passed:
                result['message'] = "✓ Confidence scoring working correctly"
                result['passed'] = True
            else:
                result['message'] = "⚠️ Some detections have low confidence or mapping issues"
                result['fix'] = "Lower confidence threshold or improve policy mapping"
                result['passed'] = False
            
            print(f"  {result['message']}")
        
        except Exception as e:
            result['message'] = f"❌ Confidence check failed: {e}"
            print(f"  {result['message']}")
        
        return result
    
    def checkpoint_3_filtering(self, sample_asset: Optional[Dict], categories_loaded: int, policy_map: Dict) -> Dict[str, Any]:
        """CHECKPOINT 3: Check if filtering is too aggressive"""
        result = {
            'passed': False,
            'message': '',
            'test_classification': None,
            'fix': ''
        }
        
        try:
            if not self.service or not sample_asset:
                result['message'] = "⚠️ Cannot test filtering without service and sample asset"
                return result
            
            print(f"  Testing classification on sample table:")
            print(f"    {sample_asset.get('schema')}.{sample_asset.get('table')}")
            
            # Get database
            db = self.service._get_active_database()
            
            # Classify single asset
            try:
                classification = self.service._classify_table_governance_driven(db, sample_asset)
                
                cat = classification.get('category')
                conf = classification.get('confidence', 0.0)
                status = classification.get('status')
                
                print(f"    Category: {cat}")
                print(f"    Confidence: {conf:.3f}")
                print(f"    Status: {status}")
                
                result['test_classification'] = classification
                
                # Check filtering logic
                would_pass = (cat in {'PII', 'SOX', 'SOC2'}) and (conf >= 0.25)
                
                print(f"    Would pass filter: {would_pass}")
                
                if not would_pass:
                    reasons = []
                    if cat not in {'PII', 'SOX', 'SOC2'}:
                        reasons.append(f"Category '{cat}' not in {{PII,SOX,SOC2}}")
                    if conf < 0.25:
                        reasons.append(f"Confidence {conf:.3f} < 0.25")
                    
                    result['message'] = f"❌ Would be FILTERED OUT: {'; '.join(reasons)}"
                    result['fix'] = "Lower threshold to 0.10 OR improve policy mapping"
                    result['passed'] = False
                    print(f"    {result['message']}")
                else:
                    result['message'] = "✓ Would PASS filter"
                    result['passed'] = True
                    print(f"    {result['message']}")
            
            except Exception as e:
                result['message'] = f"❌ Classification test failed: {e}"
                print(f"    {result['message']}")
                import traceback
                traceback.print_exc()
        
        except Exception as e:
            result['message'] = f"❌ Filtering check failed: {e}"
            print(f"  {result['message']}")
        
        return result


if __name__ == "__main__":
    debugger = PipelineDebugger()
    results = debugger.run_full_diagnostic()
    
    print()
    print("=" * 80)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 80)
    print()
    print("Review the output above to identify the root cause.")
    print("Recommended fixes are listed at the end in priority order.")
    print()
