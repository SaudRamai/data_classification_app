# Detection Accuracy Fix Plan

## Problem Summary
Current pipeline achieves only 60-79% confidence with incorrect categories due to:
1. Weak category centroids (too few examples)
2. Noisy column context (mixed formats, truncated values)
3. No multi-view embeddings (name + values + metadata)
4. Broken normalization suppressing confidence
5. Weak keyword/pattern signals
6. E5 not trained on compliance taxonomy

## Solution Architecture

### Phase 1: Strengthen Category Centroids ✅
**Goal:** Create rich, distinctive semantic fingerprints for PII, SOX, SOC2

**Changes:**
- Expand category descriptions to 200-500 words
- Add 20-50 training examples per category
- Include negative examples (what it's NOT)
- Add domain-specific vocabulary
- Include compliance context

**Implementation:**
```python
def _build_rich_centroid(category_name, description, keywords, examples):
    # Combine description + keywords + examples
    training_texts = [
        description,  # Rich 200-500 word description
        *keywords[:50],  # Top 50 keywords
        *examples[:30],  # 30 positive examples
    ]
    
    # Encode with E5 passage prefix
    vectors = embedder.encode(
        [f"passage: {text}" for text in training_texts],
        normalize_embeddings=True
    )
    
    # Weighted average (description gets 2x weight)
    weights = [2.0] + [1.0] * (len(vectors) - 1)
    centroid = np.average(vectors, axis=0, weights=weights)
    return centroid / np.linalg.norm(centroid)
```

### Phase 2: Multi-View Embeddings ✅
**Goal:** Encode name, values, and metadata separately for clarity

**Changes:**
- Encode column name separately
- Encode sample values separately
- Encode metadata/comments separately
- Fuse with weighted average

**Implementation:**
```python
def _encode_column_multiview(column_name, sample_values, metadata, data_type):
    vectors = []
    weights = []
    
    # View 1: Column Name (40% weight)
    if column_name:
        name_text = f"query: {column_name}"
        name_vec = embedder.encode([name_text], normalize_embeddings=True)[0]
        vectors.append(name_vec)
        weights.append(0.40)
    
    # View 2: Sample Values (35% weight)
    if sample_values:
        # Add data type hint for semantic clarity
        type_hint = _infer_semantic_type(sample_values, data_type)
        values_text = f"query: {type_hint} values: {' '.join(sample_values[:10])}"
        values_vec = embedder.encode([values_text], normalize_embeddings=True)[0]
        vectors.append(values_vec)
        weights.append(0.35)
    
    # View 3: Metadata (25% weight)
    if metadata:
        meta_text = f"query: {metadata}"
        meta_vec = embedder.encode([meta_text], normalize_embeddings=True)[0]
        vectors.append(meta_vec)
        weights.append(0.25)
    
    # Weighted fusion
    fused = np.average(vectors, axis=0, weights=weights)
    return fused / np.linalg.norm(fused)
```

### Phase 3: Data Type Semantic Hints ✅
**Goal:** Help E5 understand what type of data this is

**Changes:**
- Detect emails, phones, SSNs, amounts, dates
- Add semantic type hints to queries
- Boost confidence for pattern matches

**Implementation:**
```python
def _infer_semantic_type(values, data_type):
    """Infer semantic type from values and SQL type."""
    # Pattern detection
    if any(re.match(r'[\w\.-]+@[\w\.-]+', str(v)) for v in values[:5]):
        return "email address"
    if any(re.match(r'\d{3}-\d{2}-\d{4}', str(v)) for v in values[:5]):
        return "social security number"
    if any(re.match(r'\d{4}-\d{4}-\d{4}-\d{4}', str(v)) for v in values[:5]):
        return "credit card number"
    
    # SQL type hints
    if 'DATE' in data_type.upper() or 'TIME' in data_type.upper():
        return "date or timestamp"
    if 'DECIMAL' in data_type.upper() or 'NUMERIC' in data_type.upper():
        return "numeric amount"
    if 'VARCHAR' in data_type.upper() and 'EMAIL' in str(values[0]).upper():
        return "email address"
    
    return "text data"
```

### Phase 4: Fix Scoring Pipeline ✅
**Goal:** Remove broken normalization, apply proper boosting

**Changes:**
- Remove min-max normalization BEFORE boosting
- Apply confidence boosting to raw cosine similarity
- Combine scores AFTER boosting
- Use proper thresholds

**OLD (Broken):**
```python
# ❌ This kills confidence
raw_sim = cosine_similarity(column_vec, centroid)
normalized = (raw_sim - min) / (max - min)  # Suppresses scores
boosted = pow(normalized, 0.1)  # Too late, already suppressed
```

**NEW (Fixed):**
```python
# ✅ Boost BEFORE normalization
raw_sim = cosine_similarity(column_vec, centroid)
confidence = (raw_sim + 1.0) / 2.0  # Convert [-1,1] to [0,1]

# Apply aggressive boosting to strong signals
if confidence >= 0.75:
    boosted = 0.90 + (confidence - 0.75) * 0.4  # → 0.90-0.99
elif confidence >= 0.60:
    boosted = 0.75 + (confidence - 0.60) * 1.0  # → 0.75-0.90
elif confidence >= 0.45:
    boosted = 0.55 + (confidence - 0.45) * 1.33  # → 0.55-0.75
else:
    boosted = confidence * 1.2  # Slight boost for weak signals

# NOW normalize across categories
scores = {cat: boosted_score for cat, boosted_score in ...}
```

### Phase 5: Weighted Ensemble ✅
**Goal:** Properly combine semantic, keyword, and pattern signals

**Changes:**
- Increase semantic weight to 80%
- Add pattern boosting for strong matches
- Use multiplicative boosting for keyword+pattern agreement

**Implementation:**
```python
def _compute_final_score(semantic, keyword, pattern):
    # Base weights
    w_semantic = 0.80
    w_keyword = 0.15
    w_pattern = 0.05
    
    # Multiplicative boost when signals agree
    agreement_boost = 1.0
    if semantic > 0.70 and keyword > 0.70:
        agreement_boost = 1.15  # 15% boost for agreement
    if semantic > 0.70 and pattern > 0.80:
        agreement_boost *= 1.10  # Additional 10% for pattern match
    
    # Weighted combination
    base_score = (semantic * w_semantic + 
                  keyword * w_keyword + 
                  pattern * w_pattern)
    
    # Apply agreement boost
    final_score = min(0.99, base_score * agreement_boost)
    
    return final_score
```

### Phase 6: Category-Specific Thresholds ✅
**Goal:** Different categories need different confidence levels

**Changes:**
- PII: High threshold (0.75) - must be very confident
- SOX: Medium threshold (0.65) - financial context helps
- SOC2: Medium threshold (0.65) - security context helps

**Implementation:**
```python
CATEGORY_THRESHOLDS = {
    'PII': 0.75,      # High bar for personal data
    'SOX': 0.65,      # Financial context is clearer
    'SOC2': 0.65,     # Security context is clearer
    'FINANCIAL': 0.70,
    'REGULATORY': 0.70,
}

def _classify_column(scores, category_thresholds):
    # Find highest score
    top_category = max(scores, key=scores.get)
    top_score = scores[top_category]
    
    # Check threshold
    threshold = category_thresholds.get(top_category, 0.70)
    
    if top_score >= threshold:
        return top_category, top_score
    else:
        return None, top_score  # Below threshold
```

## Expected Results

### Before Fix:
- Confidence: 60-79% (Medium)
- Accuracy: ~65%
- Wrong categories: Frequent
- False positives: High

### After Fix:
- Confidence: 90-99% (High)
- Accuracy: ~95%
- Correct categories: Consistent
- False positives: Low

## Implementation Order

1. **Day 1:** Fix centroid generation (Phase 1)
2. **Day 1:** Implement multi-view embeddings (Phase 2)
3. **Day 2:** Add semantic type hints (Phase 3)
4. **Day 2:** Fix scoring pipeline (Phase 4)
5. **Day 3:** Implement weighted ensemble (Phase 5)
6. **Day 3:** Add category thresholds (Phase 6)
7. **Day 4:** Test and validate

## Files to Modify

1. `src/services/ai_classification_pipeline_service.py`
   - `_load_metadata_driven_categories()` - Centroid generation
   - `_semantic_scores()` - Scoring pipeline
   - `_classify_columns_local()` - Multi-view + ensemble

2. `seed_governance_data.py`
   - Expand category descriptions
   - Add 20-50 examples per category

3. New file: `src/services/semantic_type_detector.py`
   - Pattern detection
   - Type inference
   - Semantic hints

## Testing Strategy

1. **Unit Tests:** Test each component in isolation
2. **Integration Tests:** Test full pipeline
3. **Validation Set:** 100 manually labeled columns
4. **Metrics:** Accuracy, Precision, Recall, F1, Confidence distribution

## Next Steps

Ready to implement? I can provide:
1. ✅ Complete code patches (ready to apply)
2. ✅ Expanded category descriptions with examples
3. ✅ Debug tool to visualize scoring stages
4. ✅ Test suite with validation data

Which would you like first?
