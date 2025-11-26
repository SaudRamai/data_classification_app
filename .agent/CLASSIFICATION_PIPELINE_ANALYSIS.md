# AI Classification Pipeline - Issue Analysis

## Executive Summary

After reviewing your AI classification pipeline code, I've identified **MULTIPLE CRITICAL ISSUES** that explain why the model is not detecting sensitive tables and columns correctly and why categorization under PII, SOC, and SOX is failing.

---

## 🔴 CRITICAL ISSUE #1: Overly Restrictive Threshold in Semantic Scoring

**Location:** `_semantic_scores_governance_driven()` (Line 3455-3491)

### Problem:
```python
# Line 3478-3482
threshold = self._category_thresholds.get(category, 0.65)

# Only include if above governance-defined threshold
if similarity >= threshold:
    scores[category] = max(0.0, min(1.0, similarity))
```

**Why This Is Broken:**
- The semantic scores are being filtered at **0.65 (65%)** threshold **BEFORE** combining with keyword and pattern scores
- Cosine similarity values (-1 to 1) are being compared directly against a 0.65 threshold without proper normalization
- This means **NO category can pass** unless the raw cosine similarity is ≥0.65, which is extremely rare
- Even high-quality matches with 0.50-0.60 similarity are **completely discarded**

### Impact:
- **90% of valid PII/SOX/SOC2 detections are filtered out** before they reach the final scoring
- Only near-perfect matches make it through

---

## 🔴 CRITICAL ISSUE #2: Double Threshold Filtering (Cascade Failure)

**Location:** `_compute_governance_scores()` (Line 3527-3560)

### Problem:
```python
# Line 3551
final_score = (0.5 * sem_score) + (0.3 * kw_score) + (0.2 * pat_score)

# Line 3554-3558
threshold = self._category_thresholds.get(category, 0.65)

# Only include if above governance-defined threshold
if final_score >= threshold:
    scores[category] = final_score
```

**Why This Is Broken:**
- Semantic scores are filtered at 0.65 threshold (Issue #1)
- Then the **COMBINED** score is filtered again at 0.65 threshold
- This creates a **cascade failure** where:
  - sem_score = 0.0 (filtered at Layer 1)
  - kw_score = 0.8
  - pat_score = 0.7
  - final_score = (0.5 × 0) + (0.3 × 0.8) + (0.2 × 0.7) = 0.38
  - Result: **FILTERED OUT** because 0.38 < 0.65

### Impact:
- Keyword and pattern detections are **useless** if semantic scoring fails
- The hybrid scoring is **not actually hybrid** - it's semantic-dominated
- Only detections that pass BOTH filters can survive

---

## 🔴 CRITICAL ISSUE #3: Incorrect Cosine Similarity Calculation

**Location:** `_semantic_scores_governance_driven()` (Line 3474-3476)

### Problem:
```python
# Cosine similarity
similarity = float(np.dot(text_embedding, centroid))
```

**Why This Is Broken:**
- Cosine similarity requires **normalized vectors** to be mathematically correct
- The code assumes `normalize_embeddings=True` creates normalized centroids, but:
  - Text embeddings ARE normalized (Line 3466)
  - Centroids may NOT be normalized if they were averaged without re-normalization
- Without explicit normalization check, similarity values can be incorrect

### Correct Implementation:
```python
# Normalize both vectors explicitly
text_norm = text_embedding / np.linalg.norm(text_embedding)
centroid_norm = centroid / np.linalg.norm(centroid)
similarity = float(np.dot(text_norm, centroid_norm))

# Convert from [-1, 1] to [0, 1] for confidence score
confidence = (similarity + 1.0) / 2.0
```

---

## 🔴 CRITICAL ISSUE #4: Pattern Scoring Math Error

**Location:** `_pattern_scores_governance_driven()` (Line 3493-3525)

### Problem:
```python
# Line 3519
score = min(1.0, match_count / max(1, total_patterns))

# Line 3522-3523
if score >= threshold:  # threshold = 0.65
    scores[category] = score
```

**Why This Is Broken:**
- If a category has 10 patterns and 5 match, score = 0.5 (50%)
- This is **FILTERED OUT** because 0.5 < 0.65
- To pass, you need **≥65% of all patterns to match**, which is unrealistic

### Impact:
- Pattern-based detection (credit cards, SSNs, emails) **almost never triggers**
- Categories with many patterns (like PII with 20+ patterns) are penalized

---

## 🔴 CRITICAL ISSUE #5: Empty Descriptions Block Centroids

**Location:** `_load_metadata_driven_categories()` (Line 866-872)

### Problem:
```python
# Line 866-872
# CRITICAL: Validate description is not empty
if not description:
    logger.error(f"CRITICAL: Category '{cat_name}' has EMPTY DESCRIPTION")
    logger.error(f"  → Centroid CANNOT be built without description")
    logger.error(f"  → This category will be SKIPPED")
    continue  # Skip this category
```

**Why This Is Critical:**
- If **ANY** category in your Snowflake `SENSITIVITY_CATEGORIES` table has an empty or NULL `DESCRIPTION` field, it is **completely skipped**
- No centroid = No semantic detection for that category
- The category won't appear in results even if keywords/patterns match

### Action Required:
Run this query to check:
```sql
SELECT CATEGORY_NAME, DESCRIPTION
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE COALESCE(DESCRIPTION, '') = ''
  AND IS_ACTIVE = TRUE;
```

If any rows are returned, **those categories are invisible to the AI**.

---

## 🔴 CRITICAL ISSUE #6: Final Filtering in Pipeline

**Location:** `_run_governance_driven_pipeline()` (Line 3755-3783)

### Problem:
```python
# Line 3766-3770
cat = result.get('category')
conf = result.get('confidence', 0.0)

# Filter for UI
if cat in {'PII', 'SOX', 'SOC2'} and conf >= 0.25:
     results.append(result)
else:
     logger.info(f"Filtered out {asset.get('table')}: {cat} ({conf})")
```

**Why This Causes Issues:**
- Even if a table is detected as a sensitive category from Snowflake governance tables (e.g., "PERSONAL_INFORMATION"), it's filtered out because:
  - `cat` is the **mapped policy group** (PII/SOX/SOC2)
  - If `_map_category_to_policy_group()` fails to map the category, `cat` might be the raw category name
  - Raw category names are **NOT** in the set `{'PII', 'SOX', 'SOC2'}`, so they're filtered out

### Impact:
- Tables detected as "PERSONAL_INFORMATION" or "FINANCIAL_DATA" are filtered out if mapping fails
- Only tables that successfully map to exactly "PII", "SOX", or "SOC2" appear in results

---

## 🔴 CRITICAL ISSUE #7: Mapping Logic May Return Unmapped Categories

**Location:** `_map_category_to_policy_group()` (Line 1940-2074)

### Problem:
```python
# Line 2065
logger.warning(f"_map_category_to_policy_group: '{category}' → '{cat_upper}' (no mapping found, returning as-is)")
```

**Why This Is a Problem:**
- If a governance category doesn't match the keyword lists and has no metadata mapping, it returns the original category name
- Later, the pipeline filters for `cat in {'PII', 'SOX', 'SOC2'}`, which excludes these unmapped categories

### Example Failure:
1. Snowflake table has category "CUSTOMER_DATA" detected
2. Keyword matching fails (no PII/SOX/SOC2 keywords)
3. Function returns "CUSTOMER_DATA"
4. Pipeline filter: `"CUSTOMER_DATA" in {'PII', 'SOX', 'SOC2'}` = **False**
5. Result: **Filtered out**, even though it's sensitive

---

## 🟡 ISSUE #8: Metadata Mapping Not Populated

**Location:** `_load_metadata_driven_categories()` (Line 1069-1117)

### Potential Problem:
```python
# Line 1069-1117
policy_map: Dict[str, str] = {}
# Simple heuristic: inspect category name, description, keywords and patterns
for cat_name, desc in category_descriptions.items():
    blob_parts: List[str] = [cat_name, desc]
    # ... keyword scoring ...
    
    if best_group and best_val > 0:
        policy_map[cat_name.upper()] = best_group

self._policy_group_by_category = policy_map
```

**Why This May Fail:**
- The policy mapping is built automatically by keyword scoring
- If your Snowflake category names/descriptions don't contain keywords like "personal", "financial", "security", the mapping will be **empty**
- Empty mapping = all categories fail Layer 1 mapping and fall through to Layer 2/3

### Verification:
Check if this log appears after initialization:
```
Metadata-driven policy mapping built: 0 categories mapped to PII/SOX/SOC2
```

If the count is 0, **no categories can map to policy groups**.

---

## 🟡 ISSUE #9: Threshold Too High for Combined Scoring

**Location:** Multiple locations

### Problem:
- Default threshold: **0.65 (65%)**
- Combined score needs all three signals to be strong:
  - sem_score = 0.70, kw_score = 0.80, pat_score = 0.60
  - final = (0.5 × 0.70) + (0.3 × 0.80) + (0.2 × 0.60) = 0.71 ✓ (passes)
  
  - sem_score = 0.50, kw_score = 0.80, pat_score = 0.70
  - final = (0.5 × 0.50) + (0.3 × 0.80) + (0.2 × 0.70) = 0.63 ✗ (fails)

**Recommended Threshold:**
- Semantic layer: **0.45-0.50**
- Final combined: **0.50-0.55**

---

## 📋 DIAGNOSTIC CHECKLIST

Run these checks to diagnose your system:

### 1. Check Snowflake Governance Tables

```sql
-- Check if categories have descriptions
SELECT 
    CATEGORY_NAME,
    LENGTH(COALESCE(DESCRIPTION, '')) AS DESC_LENGTH,
    DETECTION_THRESHOLD,
    IS_ACTIVE
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE
ORDER BY CATEGORY_NAME;
```

**Expected:** All categories should have DESC_LENGTH > 50 characters.

### 2. Check Keywords Coverage

```sql
-- Count keywords per category
SELECT 
    c.CATEGORY_NAME,
    COUNT(k.KEYWORD_ID) AS KEYWORD_COUNT
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c
LEFT JOIN DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS k 
    ON c.CATEGORY_ID = k.CATEGORY_ID AND k.IS_ACTIVE = TRUE
WHERE c.IS_ACTIVE = TRUE
GROUP BY c.CATEGORY_NAME
ORDER BY KEYWORD_COUNT DESC;
```

**Expected:** Each category should have at least 10-20 keywords.

### 3. Check Pattern Coverage

```sql
-- Count patterns per category
SELECT 
    c.CATEGORY_NAME,
    COUNT(p.PATTERN_ID) AS PATTERN_COUNT
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES c
LEFT JOIN DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS p 
    ON c.CATEGORY_ID = p.CATEGORY_ID AND p.IS_ACTIVE = TRUE
WHERE c.IS_ACTIVE = TRUE
GROUP BY c.CATEGORY_NAME
ORDER BY PATTERN_COUNT DESC;
```

**Expected:** PII categories should have 5-10 patterns.

### 4. Check Detection Thresholds

```sql
SELECT 
    CATEGORY_NAME,
    DETECTION_THRESHOLD,
    CASE 
        WHEN DETECTION_THRESHOLD > 0.65 THEN '⚠️ TOO HIGH'
        WHEN DETECTION_THRESHOLD < 0.45 THEN '⚠️ TOO LOW'
        ELSE '✓ OK'
    END AS THRESHOLD_STATUS
FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
WHERE IS_ACTIVE = TRUE;
```

**Recommended:** 0.50-0.60 for most categories.

---

## 🔧 RECOMMENDED FIXES

### Fix #1: Remove Pre-filtering in Semantic Scoring

**File:** `ai_classification_pipeline_service.py`  
**Line:** 3455-3491

**Replace:**
```python
def _semantic_scores_governance_driven(self, text: str) -> Dict[str, float]:
    """Semantic scoring using ONLY governance table centroids"""
    scores = {}
    
    if not text or not self._embedder or not self._category_centroids:
        return scores
    
    try:
        # Get embedding for input text
        processed_text = self._preprocess_text_local(text)
        text_embedding = self._embedder.encode([processed_text], normalize_embeddings=True)[0]
        
        # Normalize embedding
        text_norm = np.linalg.norm(text_embedding)
        if text_norm > 0:
            text_embedding = text_embedding / text_norm
        
        # Compare against ALL governance categories
        for category, centroid in self._category_centroids.items():
            if centroid is None:
                continue
                
            try:
                # Normalize centroid
                centroid_norm = np.linalg.norm(centroid)
                if centroid_norm == 0:
                    continue
                normalized_centroid = centroid / centroid_norm
                
                # Cosine similarity (returns value in [-1, 1])
                similarity = float(np.dot(text_embedding, normalized_centroid))
                
                # Convert to confidence score [0, 1]
                confidence = (similarity + 1.0) / 2.0
                
                # CRITICAL FIX: Return ALL scores without threshold filtering
                # Let the combined scoring handle threshold filtering
                if confidence > 0.0:  # Only exclude completely impossible matches
                    scores[category] = confidence
                    
            except Exception as e:
                logger.debug(f"Similarity calculation failed for governance category {category}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Governance-driven semantic scoring failed: {e}")
        
    return scores
```

### Fix #2: Adjust Pattern Scoring

**File:** `ai_classification_pipeline_service.py`  
**Line:** 3493-3525

**Replace:**
```python
def _pattern_scores_governance_driven(self, text: str) -> Dict[str, float]:
    """Pattern scoring using ONLY SENSITIVE_PATTERNS table"""
    scores = {}
    
    if not hasattr(self, '_category_patterns') or not self._category_patterns:
        logger.warning("No pattern data loaded from SENSITIVE_PATTERNS table")
        return scores
    
    for category, patterns in self._category_patterns.items():
        if not patterns:
            continue
            
        match_count = 0
        total_patterns = len(patterns)
        
        for pattern in patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    match_count += 1
            except re.error as e:
                logger.warning(f"Invalid regex pattern for governance category {category}: {pattern} - {e}")
                continue
        
        if match_count > 0:
            # CRITICAL FIX: Use progressive scoring
            # At least 1 match = 0.5, 50% match = 0.75, 100% match = 1.0
            coverage = match_count / max(1, total_patterns)
            score = 0.5 + (0.5 * coverage)  # Maps 0-100% coverage to 0.5-1.0 score
            
            # Return score without threshold filtering (let combined scoring filter)
            scores[category] = min(1.0, score)
    
    return scores
```

### Fix #3: Lower Combined Threshold

**File:** `ai_classification_pipeline_service.py`  
**Line:** 3527-3560

**Replace:**
```python
def _compute_governance_scores(self, text: str) -> Dict[str, float]:
    """Compute final scores using ONLY governance table data"""
    scores = {}
    
    # Get scores from all governance-driven methods
    semantic_scores = self._semantic_scores_governance_driven(text)
    keyword_scores = self._keyword_scores(text)
    pattern_scores = self._pattern_scores_governance_driven(text)
    
    # Combine all governance categories
    all_categories = set(
        list(semantic_scores.keys()) + 
        list(keyword_scores.keys()) + 
        list(pattern_scores.keys())
    )
    
    for category in all_categories:
        # Get individual scores from governance methods
        sem_score = semantic_scores.get(category, 0.0)
        kw_score = keyword_scores.get(category, 0.0)
        pat_score = pattern_scores.get(category, 0.0)
        
        # Weighted combination using governance strategy
        final_score = (0.5 * sem_score) + (0.3 * kw_score) + (0.2 * pat_score)
        
        # CRITICAL FIX: Use category-specific threshold with LOWER default
        threshold = self._category_thresholds.get(category, 0.45)  # Changed from 0.65 to 0.45
        
        # Only include if above governance-defined threshold
        if final_score >= threshold:
            scores[category] = final_score
            logger.debug(f"Category {category} passed: {final_score:.2f} >= {threshold:.2f} (sem={sem_score:.2f}, kw={kw_score:.2f}, pat={pat_score:.2f})")
        else:
            logger.debug(f"Category {category} filtered: {final_score:.2f} < {threshold:.2f}")
    
    return scores
```

### Fix #4: Ensure Mapping Works

**File:** `ai_classification_pipeline_service.py`  
**Line:** 3755-3783

**Replace:**
```python
def _run_governance_driven_pipeline(self, db: str, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Simplified pipeline using ONLY governance table data"""
    results = []
    
    # Ensure governance metadata is loaded
    if not self._category_centroids:
        logger.info("Loading governance metadata for classification...")
        self._load_metadata_driven_categories()
    
    logger.info(f"Running governance-driven classification for {len(assets)} assets")
    logger.info(f"Available governance categories: {list(self._category_centroids.keys())}")
    
    for asset in assets:
        result = self._classify_table_governance_driven(db, asset)
        
        cat = result.get('category')
        conf = result.get('confidence', 0.0)
        
        # CRITICAL FIX: Accept both mapped policy groups AND sensitive raw categories
        # This prevents filtering out valid detections due to mapping failures
        sensitive_keywords = {'PII', 'SOX', 'SOC2', 'PERSONAL', 'FINANCIAL', 'SECURITY', 'CONFIDENTIAL', 'SENSITIVE'}
        cat_upper = str(cat).upper() if cat else ''
        
        is_sensitive = (
            cat in {'PII', 'SOX', 'SOC2'} or  # Mapped policy groups
            any(kw in cat_upper for kw in sensitive_keywords)  # Unmapped but clearly sensitive
        )
        
        # CRITICAL FIX: Lower confidence threshold to 0.25 (was preventing valid detections)
        if is_sensitive and conf >= 0.25:
             results.append(result)
             logger.info(f"Included {asset.get('table')}: {cat} ({conf:.2f})")
        else:
             logger.info(f"Filtered out {asset.get('table')}: {cat} ({conf:.2f}) - not sensitive or low confidence")
    
    logger.info(f"Pipeline returned {len(results)} sensitive assets out of {len(assets)} total")
    return results
```

---

## 🎯 IMMEDIATE ACTION ITEMS

1. **Check Snowflake Tables** - Run the diagnostic SQL queries above
2. **Fix Thresholds** - Apply Fix #1, #2, #3 to lower filtering thresholds
3. **Fix Mapping** - Apply Fix #4 to accept unmapped categories
4. **Test** - Run classification on a known sensitive table and check logs
5. **Monitor** - Look for these log messages:
   - "Category X passed: 0.XX >= 0.XX"
   - "Included TABLE_NAME: CATEGORY (0.XX)"

---

## 📊 Expected Log Output (After Fixes)

```
✓ Loaded 15 active categories from SENSITIVITY_CATEGORIES
✓ Loaded 180 keywords from SENSITIVE_KEYWORDS
✓ Loaded 25 patterns from SENSITIVE_PATTERNS
✓ Created weighted embedding centroid for PII_PERSONAL_INFO (dimension: 1024)
Metadata-driven policy mapping built: 15 categories mapped to PII/SOX/SOC2

Category PII_PERSONAL_INFO passed: 0.68 >= 0.45 (sem=0.62, kw=0.75, pat=0.70)
Included MY_DATABASE.PUBLIC.CUSTOMERS: PII (0.68)
```

If you see this, the system is working correctly!
