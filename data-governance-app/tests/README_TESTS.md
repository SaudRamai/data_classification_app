# AI Classification Pipeline Service - Test Suite Documentation

## Overview

Comprehensive test suite for `ai_classification_pipeline_service.py` covering all critical fixes and functionality.

---

## Test Coverage

### 1. Semantic Scoring Tests (`TestSemanticScoring`)

**What's Tested:**
- ✅ Returns all non-zero scores (no pre-filtering at 0.65)
- ✅ Proper vector normalization before cosine similarity
- ✅ Correct conversion from similarity [-1,1] to confidence [0,1]
- ✅ Perfect match detection (score ~1.0)
- ✅ Zero-norm vector handling (graceful failure)

**Critical Fixes Verified:**
- FIX #1: Removed pre-filtering at 0.65 threshold
- FIX #2: Explicit vector normalization
- FIX #3: Proper confidence conversion

### 2. Pattern Scoring Tests (`TestPatternScoring`)

**What's Tested:**
- ✅ Progressive scoring (1 match = 0.5, scaling to 1.0)
- ✅ Single pattern match gives base score
- ✅ Multiple pattern matches scale correctly
- ✅ No pre-filtering (returns all non-zero scores)
- ✅ Empty results for no matches

**Critical Fixes Verified:**
- FIX #4: Progressive scoring instead of requiring 65% match rate
- FIX #5: No pre-filtering at threshold

### 3. Combined Scoring Tests (`TestCombinedScoring`)

**What's Tested:**
- ✅ All signals combined with correct weights (0.5, 0.3, 0.2)
- ✅ Keyword-only detection works (no cascade failure)
- ✅ Keyword + Pattern works without semantic
- ✅ Lower threshold (0.45 instead of 0.65)
- ✅ Multiplicative boosting for strong signals

**Critical Fixes Verified:**
- FIX #6: Adaptive weight adjustment
- FIX #7: Threshold lowered from 0.65 to 0.45
- FIX #8: No cascade failures

### 4. Baseline Categories Tests (`TestBaselineCategories`)

**What's Tested:**
- ✅ 3 baseline categories created (PII, SOX, SOC2)
- ✅ Rich keywords provided (20+ for PII, 15+ for others)
- ✅ Patterns included (4+ for PII)
- ✅ Policy mapping configured correctly
- ✅ Thresholds set to 0.40

**Critical Fixes Verified:**
- FIX #9: Baseline fallback categories
- FIX #10: Always have working PII/SOX/SOC2 categories

### 5. Policy Mapping Tests (`TestPolicyMapping`)

**What's Tested:**
- ✅ Layer 1: Metadata-driven mapping
- ✅ Layer 4: Direct string matching (CUSTOMER→PII, FINANCIAL→SOX, etc.)
- ✅ Safety net: Sensitive keywords default to PII
- ✅ Non-sensitive categories return as-is

**Critical Fixes Verified:**
- FIX #11: Enhanced Layer 4 detection
- FIX #12: Safety net prevents filtering

### 6. Database Selection Tests (`TestDatabaseSelection`)

**What's Tested:**
- ✅ Gets database from global filter
- ✅ Probes Snowflake for current database
- ✅ Auto-selects first available user database
- ✅ Handles 'NONE' string correctly

**Critical Fixes Verified:**
- FIX #13: Never returns 'NONE'
- FIX #14: Comprehensive fallback chain

### 7. Integration Tests (`TestIntegration`)

**What's Tested:**
- ✅ End-to-end classification with baseline categories
- ✅ PII detection from text description
- ✅ Threshold validation

---

## Running the Tests

### Quick Start:
```bash
cd c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app
.\run_tests.ps1
```

### Manual Run:
```bash
# Install dependencies
pip install -r tests/requirements-test.txt

# Run all tests
pytest tests/test_ai_classification_pipeline_service.py -v

# Run with coverage
pytest tests/test_ai_classification_pipeline_service.py -v --cov=src.services.ai_classification_pipeline_service

# Run specific test class
pytest tests/test_ai_classification_pipeline_service.py::TestSemanticScoring -v

# Run specific test
pytest tests/test_ai_classification_pipeline_service.py::TestSemanticScoring::test_semantic_scoring_returns_all_nonzero_scores -v
```

---

## Expected Results

### All Tests Passing:
```
tests/test_ai_classification_pipeline_service.py::TestSemanticScoring::test_semantic_scoring_returns_all_nonzero_scores PASSED
tests/test_ai_classification_pipeline_service.py::TestSemanticScoring::test_semantic_scoring_proper_normalization PASSED
tests/test_ai_classification_pipeline_service.py::TestSemanticScoring::test_semantic_scoring_similarity_to_confidence_conversion PASSED
... (30+ more tests)

================================ 35 passed in 2.45s ================================
✓ ALL TESTS PASSED!
```

### Test Summary by Category:
- **Semantic Scoring:** 5 tests
- **Pattern Scoring:** 4 tests
- **Combined Scoring:** 5 tests
- **Baseline Categories:** 5 tests
- **Policy Mapping:** 4 tests
- **Database Selection:** 4 tests
- **Integration:** 1 test

**Total:** 28 automated tests

---

## Coverage Goals

- **Target:** 80%+ code coverage
- **Critical Methods:** 100% coverage
  - `_semantic_scores_governance_driven()`
  - `_pattern_scores_governance_driven()`
  - `_compute_governance_scores()`
  - `_create_baseline_categories()`
  - `_map_category_to_policy_group()`

---

## Test Data

### Mock Centroids:
```python
PII_PERSONAL_INFO: [0.8, 0.6, 0.0]  # High on PII dimension
SOX_FINANCIAL_DATA: [0.6, 0.8, 0.0]  # High on Financial dimension
SOC2_SECURITY_DATA: [0.0, 0.6, 0.8]  # High on Security dimension
```

### Mock Patterns:
```python
PII: SSN, Email, Phone
SOX: Currency amounts
SOC2: API keys/tokens
```

### Mock Keywords:
```python
PII: email, name, phone, customer, employee
SOX: revenue, transaction, payment, financial
SOC2: password, token, credential, security
```

---

## Continuous Integration

### GitHub Actions (Optional):
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r tests/requirements-test.txt
      - run: pytest tests/test_ai_classification_pipeline_service.py -v --cov
```

---

## Troubleshooting

### ImportError: No module named 'src'
**Solution:** Ensure you're running from project root:
```bash
cd c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app
pytest tests/
```

### Tests fail due to missing dependencies
**Solution:** Install test requirements:
```bash
pip install -r tests/requirements-test.txt
```

### Mock errors
**Solution:** Ensure unittest.mock is available (Python 3.3+)

---

## Extending Tests

### Adding New Test:
```python
class TestNewFeature:
    @pytest.fixture
    def service(self):
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            # Setup mocks
            return service
    
    def test_new_functionality(self, service):
        # Arrange
        input_data = "test"
        
        # Act
        result = service.new_method(input_data)
        
        # Assert
        assert result == expected_output
```

---

## Test Maintenance

### Regular Updates:
- ✅ Update tests when adding new features
- ✅ Update mocks when changing schemas
- ✅ Keep thresholds in sync with code
- ✅ Add regression tests for bugs

### Review Schedule:
- **After each fix:** Add test for the fix
- **Weekly:** Run full test suite
- **Before release:** 100% pass rate required

---

## Performance Testing

For performance testing (not included in this suite):
```python
import time

def test_classification_performance():
    start = time.time()
    # Run classification
    duration = time.time() - start
    assert duration < 5.0  # Should complete in < 5 seconds
```

---

## Success Criteria

✅ **All 28 tests pass**  
✅ **80%+ code coverage**  
✅ **No import errors**  
✅ **No dependency issues**  
✅ **Tests run in < 10 seconds**

---

**Test Suite Version:** 1.0  
**Last Updated:** 2025-11-25  
**Compatibility:** Python 3.8+, pytest 7.4+
