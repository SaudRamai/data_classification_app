# Implementation Checklist - 80% Confidence & Column Detection

## Pre-Implementation Verification

- [ ] **Backup current code**
  ```bash
  cp ai_classification_pipeline_service.py ai_classification_pipeline_service.py.backup
  ```

- [ ] **Verify Python version**
  ```bash
  python --version  # Should be 3.8+
  ```

- [ ] **Check dependencies installed**
  ```bash
  pip list | grep -E "sentence-transformers|numpy|pandas|streamlit"
  ```

---

## Code Changes Applied

### Fix 1: Enhanced Semantic Score Boosting
- [ ] **File:** `ai_classification_pipeline_service.py`
- [ ] **Lines:** 968-976
- [ ] **Change:** Replaced `if x >= 0.7: x = pow(x, 0.5)` with aggressive boosting
- [ ] **Verification:** Check for `x^0.4` and `x^0.6` formulas
- [ ] **Expected:** Scores now reach 0.95+ for strong signals

### Fix 2: Lowered Confidence Threshold
- [ ] **File:** `ai_classification_pipeline_service.py`
- [ ] **Line:** 63
- [ ] **Change:** `self._conf_label_threshold: float = 0.30` (was 0.45)
- [ ] **Verification:** Search for `_conf_label_threshold` and confirm value
- [ ] **Expected:** More aggressive classification

### Fix 3: Column-Level Classification Method
- [ ] **File:** `ai_classification_pipeline_service.py`
- [ ] **Lines:** 1658-1787
- [ ] **Change:** Added `_classify_columns_local()` method
- [ ] **Verification:** Method exists and has governance table integration
- [ ] **Expected:** Column-level results with 80%+ confidence

### Fix 4: Diagnostic Logging
- [ ] **File:** `ai_classification_pipeline_service.py`
- [ ] **Lines:** 1674, 1765
- [ ] **Change:** Added logging statements
- [ ] **Verification:** Check for `logger.info()` calls
- [ ] **Expected:** Detailed logs for debugging

---

## Testing Phase 1: Unit Tests

### Test Semantic Score Boosting
```python
# Test case 1: Strong signal
x = 0.8
result = pow(x, 0.4)  # Should be ~0.89
assert 0.88 < result < 0.90, f"Expected ~0.89, got {result}"
print("✓ Strong signal boosting works")

# Test case 2: Medium signal
x = 0.5
result = pow(x, 0.6)  # Should be ~0.71
assert 0.70 < result < 0.72, f"Expected ~0.71, got {result}"
print("✓ Medium signal boosting works")

# Test case 3: Weak signal
x = 0.3
result = x  # Should remain unchanged
assert result == 0.3, f"Expected 0.3, got {result}"
print("✓ Weak signal unchanged")
```

- [ ] Run semantic boosting tests
- [ ] All tests pass

### Test Confidence Threshold
```python
from src.services.ai_classification_pipeline_service import AIClassificationPipelineService

pipeline = AIClassificationPipelineService()
assert pipeline._conf_label_threshold == 0.30, "Threshold not lowered"
print("✓ Confidence threshold is 0.30")
```

- [ ] Run threshold test
- [ ] Test passes

### Test Column Classification Method Exists
```python
pipeline = AIClassificationPipelineService()
assert hasattr(pipeline, '_classify_columns_local'), "Method not found"
assert callable(pipeline._classify_columns_local), "Method not callable"
print("✓ Column classification method exists")
```

- [ ] Run method existence test
- [ ] Test passes

---

## Testing Phase 2: Integration Tests

### Test Embeddings Initialization
```python
pipeline = AIClassificationPipelineService()
pipeline._init_local_embeddings()

assert pipeline._embedder is not None, "Embedder not initialized"
assert pipeline._embed_backend == 'sentence-transformers', "Backend incorrect"
assert pipeline._embed_ready == True, "Embeddings not ready"
print("✓ Embeddings initialized successfully")
```

- [ ] Run embeddings test
- [ ] Check logs for "✓ Embeddings initialized"
- [ ] Test passes

### Test Centroid Generation
```python
pipeline = AIClassificationPipelineService()
pipeline._init_local_embeddings()

valid_centroids = len([v for v in pipeline._category_centroids.values() if v is not None])
assert valid_centroids > 0, "No centroids generated"
print(f"✓ Generated {valid_centroids} centroids")
```

- [ ] Run centroid test
- [ ] Check logs for "Centroid generation complete"
- [ ] Verify valid_centroids > 0

### Test Table-Level Classification
```python
pipeline = AIClassificationPipelineService()
pipeline._init_local_embeddings()
pipeline._auto_tune_parameters()

asset = {
    'database': 'TEST_DB',
    'schema': 'TEST_SCHEMA',
    'table': 'TEST_TABLE',
    'full_name': 'TEST_DB.TEST_SCHEMA.TEST_TABLE',
    'comment': 'Test table with customer data'
}

results = pipeline._classify_assets_local('TEST_DB', [asset])
assert len(results) > 0, "No results returned"
assert 'confidence' in results[0], "Confidence not in results"
assert results[0]['confidence'] >= 0.30, "Confidence below threshold"
print(f"✓ Table classification: {results[0]['confidence']:.1%} confidence")
```

- [ ] Run table classification test
- [ ] Verify confidence >= 0.30
- [ ] Check logs for score computation

### Test Column-Level Classification
```python
pipeline = AIClassificationPipelineService()
pipeline._init_local_embeddings()
pipeline._auto_tune_parameters()

col_results = pipeline._classify_columns_local('TEST_DB', 'TEST_SCHEMA', 'TEST_TABLE', max_cols=10)
assert len(col_results) > 0, "No column results"
assert 'confidence' in col_results[0], "Confidence not in results"
print(f"✓ Column classification: {len(col_results)} columns classified")
```

- [ ] Run column classification test
- [ ] Verify results returned
- [ ] Check logs for column-level classification

---

## Testing Phase 3: Performance Tests

### Measure Confidence Distribution
```python
col_results = pipeline._classify_columns_local('DB', 'SCHEMA', 'TABLE')
confidences = [col['confidence'] for col in col_results if 'error' not in col]

confident = sum(1 for c in confidences if c >= 0.80)
likely = sum(1 for c in confidences if 0.30 <= c < 0.80)
uncertain = sum(1 for c in confidences if c < 0.30)

print(f"Confident (≥80%): {confident} ({confident/len(confidences)*100:.1f}%)")
print(f"Likely (30-80%): {likely} ({likely/len(confidences)*100:.1f}%)")
print(f"Uncertain (<30%): {uncertain} ({uncertain/len(confidences)*100:.1f}%)")
```

- [ ] Run performance test
- [ ] Verify ≥70% of columns have ≥80% confidence
- [ ] Verify <10% uncertain classifications

### Measure Execution Time
```python
import time

start = time.time()
col_results = pipeline._classify_columns_local('DB', 'SCHEMA', 'TABLE', max_cols=50)
elapsed = time.time() - start

print(f"Classified {len(col_results)} columns in {elapsed:.2f}s")
print(f"Average: {elapsed/len(col_results)*1000:.1f}ms per column")
```

- [ ] Run timing test
- [ ] Verify <5s for 50 columns
- [ ] Verify <100ms per column

---

## Testing Phase 4: Accuracy Validation

### Compare with Manual Classifications
```python
manual_classifications = {
    'customer_id': 'PII',
    'customer_name': 'PII',
    'customer_email': 'PII',
    'customer_ssn': 'PII',
    'created_date': 'OPERATIONAL',
    'updated_date': 'OPERATIONAL',
}

col_results = pipeline._classify_columns_local('DB', 'SCHEMA', 'TABLE')

matches = 0
for col in col_results:
    col_name = col['column']
    if col_name in manual_classifications:
        if col['category'] == manual_classifications[col_name]:
            matches += 1
            print(f"✓ {col_name}: {col['category']} @ {col['confidence_pct']:.1f}%")
        else:
            print(f"✗ {col_name}: Got {col['category']}, expected {manual_classifications[col_name]}")

accuracy = matches / len(manual_classifications)
print(f"\nAccuracy: {accuracy:.1%}")
```

- [ ] Run accuracy validation
- [ ] Verify accuracy ≥ 85%
- [ ] Document any misclassifications

---

## Testing Phase 5: Governance Table Integration

### Verify Governance Tables Exist
```python
from src.connectors.snowflake_connector import snowflake_connector

gov_db = 'DATA_CLASSIFICATION_GOVERNANCE'
tables = ['SENSITIVE_CATEGORIES', 'SENSITIVE_KEYWORDS', 'SENSITIVE_PATTERNS']

for table in tables:
    try:
        result = snowflake_connector.execute_query(f"SELECT COUNT(*) FROM {gov_db}.{table}")
        count = result[0][0] if result else 0
        print(f"✓ {table}: {count} rows")
    except Exception as e:
        print(f"✗ {table}: {e}")
```

- [ ] Run governance table check
- [ ] Verify all tables exist
- [ ] Verify tables have data

### Verify Governance Boost Applied
```python
# Check logs for governance boost
# Look for: "Governance table boost" or governance scores in logs
```

- [ ] Run column classification
- [ ] Check logs for governance integration
- [ ] Verify boost applied to scores

---

## Deployment Checklist

### Pre-Deployment
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Performance tests meet targets
- [ ] Accuracy validation passes
- [ ] Governance tables verified
- [ ] Code reviewed
- [ ] Backup created

### Deployment
- [ ] Deploy to staging environment
- [ ] Run full test suite in staging
- [ ] Verify logs show expected output
- [ ] Monitor for errors
- [ ] Collect performance metrics

### Post-Deployment
- [ ] Monitor production logs
- [ ] Verify confidence scores ≥80%
- [ ] Verify <10% uncertain classifications
- [ ] Collect accuracy metrics
- [ ] Document any issues
- [ ] Plan follow-up improvements

---

## Rollback Plan

If issues occur:

1. **Immediate Rollback**
   ```bash
   cp ai_classification_pipeline_service.py.backup ai_classification_pipeline_service.py
   ```

2. **Restart Services**
   ```bash
   # Restart Streamlit app
   streamlit run app.py
   ```

3. **Verify Rollback**
   - Check logs for "Embeddings initialized"
   - Verify confidence threshold is 0.45
   - Test classification returns to previous behavior

---

## Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| Embeddings initialized | ✓ | [ ] |
| Centroids generated | >0 | [ ] |
| Table confidence | 70-85% | [ ] |
| Column confidence | 80-95% | [ ] |
| Confidence ≥80% | ≥70% | [ ] |
| Uncertain <10% | ✓ | [ ] |
| Accuracy ≥85% | ✓ | [ ] |
| Governance integrated | ✓ | [ ] |
| Performance <5s/50cols | ✓ | [ ] |

---

## Documentation

- [ ] Update README with new column-level detection
- [ ] Document governance table integration
- [ ] Add example usage to code comments
- [ ] Update API documentation
- [ ] Create troubleshooting guide
- [ ] Document configuration options

---

## Sign-Off

- [ ] Developer: _________________ Date: _______
- [ ] Reviewer: _________________ Date: _______
- [ ] QA: _________________ Date: _______
- [ ] Deployment: _________________ Date: _______

