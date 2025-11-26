"""
AI Classification Pipeline - Quick Fix Toggles
Emergency bypass switches for debugging

USAGE:
    from .agent.quick_fixes import apply_quick_fixes
    apply_quick_fixes(service, mode='bypass_all')
"""

def apply_quick_fixes(service, mode='diagnose'):
    """
    Apply quick debugging fixes to pipeline service
    
    Modes:
        'diagnose' - No changes, just report current state
        'lower_thresholds' - Set minimum confidence thresholds for testing
        'bypass_filtering' - Return ALL results regardless of category/confidence
        'force_policy_mapping' - Map all sensitive-looking categories to PII
        'bypass_all' - All bypasses enabled
    """
    
    print(f"🔧 QUICK FIX MODE: {mode}")
    print("-" * 80)
    
    if mode == 'diagnose':
        _diagnose_current_state(service)
    
    elif mode == 'lower_thresholds':
        _apply_lower_thresholds(service)
    
    elif mode == 'bypass_filtering':
        _bypass_pipeline_filtering(service)
    
    elif mode == 'force_policy_mapping':
        _force_policy_mapping(service)
    
    elif mode == 'bypass_all':
        _apply_lower_thresholds(service)
        _bypass_pipeline_filtering(service)
        _force_policy_mapping(service)
    
    else:
        print(f"❌ Unknown mode: {mode}")
        print(f"Valid modes: diagnose, lower_thresholds, bypass_filtering, force_policy_mapping, bypass_all")


def _diagnose_current_state(service):
    """Report current configuration"""
    print("Current Configuration:")
    print()
    
    # Check thresholds
    thresholds = getattr(service, '_category_thresholds', {})
    if thresholds:
        avg_threshold = sum(thresholds.values()) / len(thresholds)
        print(f"  Average category threshold: {avg_threshold:.3f}")
        print(f"  Threshold range: {min(thresholds.values()):.3f} - {max(thresholds.values()):.3f}")
    else:
        print(f"  ⚠️ No category thresholds loaded")
    
    # Check policy mapping
    policy_map = getattr(service, '_policy_group_by_category', {})
    print(f"  Policy mappings: {len(policy_map)} categories")
    
    if policy_map:
        pii_count = sum(1 for v in policy_map.values() if v == 'PII')
        sox_count = sum(1 for v in policy_map.values() if v == 'SOX')
        soc2_count = sum(1 for v in policy_map.values() if v == 'SOC2')
        print(f"    PII: {pii_count}, SOX: {sox_count}, SOC2: {soc2_count}")
    else:
        print(f"    ⚠️ NO MAPPINGS - all detections will be filtered!")
    
    # Check categories
    centroids = getattr(service, '_category_centroids', {})
    keywords = getattr(service, '_category_keywords', {})
    patterns = getattr(service, '_category_patterns', {})
    
    print(f"  Categories loaded: {len(centroids)}")
    print(f"  Keywords loaded: {sum(len(kws) for kws in keywords.values())}")
    print(f"  Patterns loaded: {sum(len(pats) for pats in patterns.values())}")
    
    print()


def _apply_lower_thresholds(service):
    """FIX 1: Lower all thresholds to minimum for testing"""
    print("✓ Applying FIX 1: Lower Thresholds")
    
    # Set all category thresholds to 0.10
    thresholds = getattr(service, '_category_thresholds', {})
    original_thresholds = thresholds.copy()
    
    for category in thresholds.keys():
        thresholds[category] = 0.10  # Very low for testing
    
    service._category_thresholds = thresholds
    
    print(f"  Set all {len(thresholds)} category thresholds to 0.10")
    print(f"  (Original average: {sum(original_thresholds.values())/max(1,len(original_thresholds)):.3f})")
    
    # Also lower pipeline filtering threshold
    service._conf_label_threshold = 0.05
    print(f"  Set label confidence threshold to 0.05")
    
    print()


def _bypass_pipeline_filtering(service):
    """FIX 2: Monkey-patch pipeline to return ALL results"""
    print("✓ Applying FIX 2: Bypass Pipeline Filtering")
    print("  ⚠️  WARNING: This will return ALL tables regardless of sensitivity")
    
    original_pipeline = service._run_governance_driven_pipeline
    
    def bypass_pipeline(db, assets):
        """Modified pipeline that returns ALL results"""
        results = []
        
        # Load metadata if needed
        if not service._category_centroids:
            service._load_metadata_driven_categories()
        
        print(f"  [BYPASS MODE] Classifying {len(assets)} assets (will return ALL)")
        
        for asset in assets:
            result = service._classify_table_governance_driven(db, asset)
            
            # BYPASS: Add ALL results regardless of category/confidence
            results.append(result)
            
            cat = result.get('category', 'UNKNOWN')
            conf = result.get('confidence', 0.0)
            print(f"    {asset.get('schema')}.{asset.get('table')}: {cat} ({conf:.3f}) - INCLUDED")
        
        print(f"  [BYPASS MODE] Returning all {len(results)} results")
        return results
    
    service._run_governance_driven_pipeline = bypass_pipeline
    print(f"  Patched _run_governance_driven_pipeline to bypass filtering")
    print()


def _force_policy_mapping(service):
    """FIX 3: Force all sensitive-looking categories to map to PII"""
    print("✓ Applying FIX 3: Force Policy Mapping")
    
    original_mapper = service._map_category_to_policy_group
    
    def forced_mapper(category):
        """Force sensitive categories to PII, financial to SOX, security to SOC2"""
        if not category or category == 'NON_SENSITIVE':
            return "OTHER"
        
        cat_lower = str(category).lower()
        
        # Financial indicators → SOX
        if any(kw in cat_lower for kw in ['financial', 'transaction', 'payment', 'account', 'revenue', 'sox']):
            return "SOX"
        
        # Security indicators → SOC2
        if any(kw in cat_lower for kw in ['security', 'password', 'credential', 'auth', 'access', 'soc']):
            return "SOC2"
        
        # Default: treat as PII (safer to over-classify than under-classify)
        return "PII"
    
    service._map_category_to_policy_group = forced_mapper
    print(f"  Patched _map_category_to_policy_group to force all categories to PII/SOX/SOC2")
    print(f"  All non-financial/security categories will map to PII by default")
    print()


def test_single_table(service, database, schema, table):
    """Quick test of single table classification"""
    print(f"🧪 TESTING SINGLE TABLE: {database}.{schema}.{table}")
    print("-" * 80)
    
    asset = {
        'database': database,
        'schema': schema,
        'table': table,
        'full_name': f"{database}.{schema}.{table}"
    }
    
    try:
        result = service._classify_table_governance_driven(database, asset)
        
        print(f"  Category: {result.get('category')}")
        print(f"  Confidence: {result.get('confidence', 0.0):.3f}")
        print(f"  Status: {result.get('status')}")
        print(f"  Columns classified: {len(result.get('columns', []))}")
        
        # Check if would pass filter
        cat = result.get('category')
        conf = result.get('confidence', 0.0)
        would_pass = (cat in {'PII', 'SOX', 'SOC2'}) and (conf >= 0.25)
        
        print()
        print(f"  Would pass normal filter: {would_pass}")
        
        if not would_pass:
            if cat not in {'PII', 'SOX', 'SOC2'}:
                print(f"    Issue: Category '{cat}' not in {{PII,SOX,SOC2}}")
            if conf < 0.25:
                print(f"    Issue: Confidence {conf:.3f} < 0.25")
        
        print()
        
        # Show column details
        if 'columns' in result:
            print(f"  Column Details:")
            for col in result['columns'][:5]:
                print(f"    {col.get('column_name')}: {col.get('category')} ({col.get('confidence', 0.0):.3f})")
            if len(result['columns']) > 5:
                print(f"    ... +{len(result['columns'])-5} more columns")
        
        return result
        
    except Exception as e:
        print(f"  ❌ Classification failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# Example usage in service
"""
# In your pipeline service, add this for emergency debugging:

try:
    from .agent.quick_fixes import apply_quick_fixes, test_single_table
    
    # Option 1: Just diagnose
    apply_quick_fixes(self, mode='diagnose')
    
    # Option 2: Lower thresholds to see if confidence is the issue
    apply_quick_fixes(self, mode='lower_thresholds')
    
    # Option 3: Bypass filtering to see what's actually being detected
    apply_quick_fixes(self, mode='bypass_filtering')
    
    # Option 4: Nuclear option - bypass everything
    apply_quick_fixes(self, mode='bypass_all')
    
    # Option 5: Test single table
    test_single_table(self, 'MY_DB', 'MY_SCHEMA', 'MY_TABLE')
    
except ImportError:
    pass  # Quick fixes not available
"""
