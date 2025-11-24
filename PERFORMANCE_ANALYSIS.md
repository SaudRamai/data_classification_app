# AI Classification Pipeline - Performance Analysis & Optimization

## Current Issues

### 1. **Critical: LLM Timeout (600 seconds)**
- **Error**: `HTTPConnectionPool(host='localhost', port=11434): Read timed out. (read timeout=600)`
- **Location**: `src/services/llm_classification_service.py:80`
- **Root Cause**: 
  - Processing one table takes >10 minutes
  - Batch size of 15 columns per request is still too large for local LLM
  - Verbose system prompt increases processing time
  - Sequential processing (max_workers=1) exacerbates the issue

### 2. **Architecture Problems**

#### A. Inefficient LLM Service Design
**File**: `src/services/llm_classification_service.py`

**Problems**:
1. **Large Batch Size**: `BATCH_SIZE = 15` - Too many columns per LLM request
2. **Verbose System Prompt**: 36 lines of instructions including 4 detailed examples
3. **No Streaming**: Waits for complete response (blocks for entire generation)
4. **No Context Caching**: System prompt sent with every request
5. **Timeout Too High**: 600 seconds allows hanging instead of failing fast

#### B. Sequential Processing Bottleneck
**File**: `src/services/ai_classification_pipeline_service.py:2541`

```python
with ThreadPoolExecutor(max_workers=1) as executor:
```

**Problems**:
- Only processes 1 table at a time
- Comment says "Local LLMs struggle with parallel requests" but this is overly conservative
- For Ollama with sufficient resources, 2-3 parallel requests are feasible

#### C. Excessive Context Building
**File**: `src/services/ai_classification_pipeline_service.py:2407-2425`

**Problems**:
- Fetches ALL columns for every table before LLM request
- No limit on column count
- Includes unnecessary metadata (comments) in every column

#### D. No Progress Indicators
- User has no visibility into which batch is processing
- No estimated time remaining
- Error messages don't indicate which table/batch failed

## Optimization Strategy

### Tier 1: Critical Fixes (Immediate Impact)

1. **Reduce LLM Batch Size**: 15 → 5 columns per request
   - Reduces token count significantly
   - Faster response time per batch
   - Better error isolation

2. **Simplify System Prompt**: Remove verbose examples, keep only essential rules
   - Current: ~500 tokens
   - Optimized: ~150 tokens
   - 3x faster generation

3. **Reduce Timeout**: 600s → 120s per batch
   - Fail fast on problematic batches
   - Better error detection

4. **Add Max Columns Limit**: Cap at 50 columns per table
   - Prevents processing massive tables
   - Predictable performance

### Tier 2: Performance Enhancements

1. **Increase Parallelism**: max_workers=1 → max_workers=2
   - Test with 2 parallel requests first
   - Monitor Ollama resource usage
   - Can revert if unstable

2. **Add Batch Progress Logging**:
   - Log each batch completion
   - Show column count per batch
   - Add retry logic for failed batches

3. **Optimize Column Fetching**:
   - Add LIMIT to column queries
   - Fetch only required fields (name, data_type)
   - Skip comment field unless needed

4. **Response Validation**:
   - Validate JSON schema before processing
   - Add timeout per batch (not just per request)
   - Better error messages

### Tier 3: Advanced Optimizations

1. **Smart Column Sampling**:
   - Classify only "sensitive-looking" columns
   - Use heuristics (name patterns) to pre-filter
   - Reduce LLM calls by 50-70%

2. **Context Caching** (if Ollama supports):
   - Cache system prompt across requests
   - Reuse model state between batches

3. **Incremental Results**:
   - Save classifications after each table
   - Resume from last checkpoint on failure

4. **Alternative Models**:
   - Test faster models (e.g., `tinyllama`, `llama3.2:1b`)
   - Trade-off: Speed vs Accuracy

## Performance Metrics (Estimated)

### Current State
- **Time per table**: >600 seconds (timeout)
- **Columns per batch**: 15
- **System prompt tokens**: ~500
- **Tables processed**: 0 (timeout)

### After Tier 1 Fixes
- **Time per table**: ~60-120 seconds (for 50 columns)
- **Columns per batch**: 5
- **System prompt tokens**: ~150
- **Tables processed**: 30 in ~30-60 minutes

### After Tier 2 Optimizations
- **Time per table**: ~30-60 seconds
- **Parallel processing**: 2x speedup
- **Tables processed**: 30 in ~15-30 minutes

## Implementation Priority

### Phase 1: Fix the Timeout (5 minutes)
1. ✅ Reduce batch size to 5
2. ✅ Simplify system prompt
3. ✅ Reduce timeout to 120s
4. ✅ Add column limit (50)
5. ✅ Add better logging

### Phase 2: Improve Performance (10 minutes)
1. Increase max_workers to 2
2. Add batch progress indicators
3. Optimize column fetching
4. Add retry logic

### Phase 3: Test & Monitor (15 minutes)
1. Test with real table
2. Monitor Ollama logs
3. Measure actual performance
4. Fine-tune parameters

## Code Changes Summary

### Files to Modify:
1. `src/services/llm_classification_service.py` (Critical)
   - Reduce BATCH_SIZE: 15 → 5
   - Simplify system prompt
   - Reduce timeout: 600 → 120
   - Add better error messages

2. `src/services/ai_classification_pipeline_service.py` (Important)
   - Increase max_workers: 1 → 2
   - Add column limit in queries
   - Add batch progress logging
   - Optimize column fetching

## Risk Assessment

### Low Risk (Safe to implement):
- ✅ Reduce batch size
- ✅ Simplify prompt
- ✅ Add logging
- ✅ Add column limits

### Medium Risk (Test first):
- ⚠️ Reduce timeout (may cause false failures)
- ⚠️ Increase parallelism (may overload Ollama)

### High Risk (Careful testing needed):
- ⛔ Change models (accuracy impact)
- ⛔ Column sampling (may miss sensitive data)

## Next Steps

1. Implement Tier 1 fixes (all low risk)
2. Test with one table
3. If successful, implement Tier 2
4. Monitor and iterate

## Monitoring Checklist

After implementing fixes, monitor:
- [ ] Average time per table
- [ ] Average time per batch
- [ ] Success rate (% tables completed)
- [ ] Ollama CPU/memory usage
- [ ] Error types and frequency
- [ ] Classification accuracy (spot check)
