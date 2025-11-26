# AI Classification Pipeline - Phase 1 Fixes Implementation Plan

## CRITICAL ISSUES IDENTIFIED

### 1. Category Mapping Breakdown (Lines 1956-1990, 2596-2606)
- `_map_category_to_policy_group()` returns `None` for unmapped categories
- No fallback logic for clearly sensitive categories
- Result: Columns with valid detections get marked as "NON-SENSITIVE"

### 2. Overly Restrictive Thresholds (Lines 2515, 2603)
- Column detection threshold: 35% (`min_sensitive_conf = 0.35`)
- Double filtering: Once in classification, again in display
- No diagnostic visibility into filtering decisions

### 3. Missing Diagnostic Logging
- No visibility into why columns are filtered
- No audit trail showing raw category → mapped policy group → filtering decision

## IMPLEMENTATION PLAN

### Fix 1: Enhanced 3-Layer Category Mapping (IMMEDIATE)
**File**: `ai_classification_pipeline_service.py`
**Function**: `_map_category_to_policy_group` (lines 1956-1990)

**Changes**:
1. Add keyword-based fallback mapping
2. Add semantic similarity fallback
3. Never return None for clearly sensitive categories
4. Add comprehensive logging

**New Logic**:
```python
def _map_category_to_policy_group(self, category: str) -> str:
    # Layer 1: Metadata-driven mapping
    # Layer 2: Keyword-based fallback
    # Layer 3: Semantic similarity fallback
    # Default: Return category as-is (don't filter out)
```

### Fix 2: Lower Confidence Thresholds (IMMEDIATE)
**File**: `ai_classification_pipeline_service.py`
**Function**: `_classify_columns_local` (line 2515)

**Changes**:
- Lower `min_sensitive_conf` from 0.35 to 0.25
- Add confidence bands: 0.25-0.35 = "Review Recommended"
- Add diagnostic field showing filtering reason

### Fix 3: Add Comprehensive Diagnostic Logging (IMMEDIATE)
**Locations**:
- Line 2642: Add detailed logging before filtering decision
- Line 2598-2606: Log mapping results
- Add new field to results: `filtering_reason`

### Fix 4: Enhanced Metadata Policy Mapping (PHASE 2)
**File**: `ai_classification_pipeline_service.py`
**Function**: `_load_metadata_driven_categories` (lines 800-1173)

**Changes**:
- Analyze category DESCRIPTION in addition to name
- Use associated keywords to infer policy group
- Add fuzzy matching for similar category names

## EXPECTED IMPACT

### Before Fixes:
- ~30% of sensitive columns detected (70% filtered out)
- No visibility into why columns are filtered
- Many false negatives due to strict thresholds

### After Fixes:
- ~70-80% of sensitive columns detected
- Clear audit trail for every classification decision
- Reduced false negatives while maintaining precision
- Better policy group mapping accuracy

## ROLLOUT SEQUENCE

1. **Immediate** (15 min):
   - Fix 1: Enhanced category mapping with fallbacks
   - Fix 2: Lower thresholds to 25%
   - Fix 3: Add diagnostic logging

2. **Phase 2** (30 min):
   - Enhanced metadata policy mapping
   - Confidence calibration
   - Fuzzy category matching

3. **Phase 3** (1 hour):
   - Classification audit dashboard
   - Governance gap analysis
   - Confidence explanation UI
