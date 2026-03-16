# Testing Checklist - Post-Optimization

## Pre-Test Setup

### 1. Verify Ollama is Ready
```bash
# Check if Ollama is running
curl http://localhost:11434/v1/models

# Expected output: JSON with model list
# If error: Start Ollama (in another terminal)
ollama serve
```

### 2. Verify Model is Available
```bash
# List models
ollama list

# Expected: phi3.5 in the list
# If not found:
ollama pull phi3.5
```

### 3. Restart Streamlit App
Since we modified the code, restart your app:

```bash
# Stop current app (Ctrl+C in terminal)
# Then restart:
cd /home/ankit.koranga/data_classification_app/data-governance-app
streamlit run src/app.py
```

## Test Phase 1: Single Table Test (5 minutes)

### Goal
Verify basic functionality with minimal risk

### Steps
1. Open the Streamlit app
2. Go to **AI Assistant** → **Automatic AI Classification Pipeline**
3. Select a database with small tables
4. Click **Run Classification Pipeline**
5. Let it run on 1-2 tables

### What to Watch For

✅ **Success Indicators**:
```
Console logs should show:
- "Classifying X columns in Y batches (batch_size=5)"
- "Processing batch 1/Y (5 columns)..."
- "✓ Batch 1/Y completed: 5 columns classified"
- "Classification complete: X columns classified, 0 errors"

UI should show:
- Progress bar updating smoothly
- "Classifying table 1 of 2..."
- Results table appearing with classifications
```

❌ **Failure Indicators**:
```
Console logs showing:
- "Batch X timed out after 120s"
- "Error during LLM classification batch X"
- "HTTPConnectionPool: Connection refused"

UI showing:
- Stuck progress bar
- Error messages in red
- No results appearing
```

### Expected Timing
- **Small table (< 20 columns)**: 30-60 seconds
- **Medium table (20-50 columns)**: 60-120 seconds
- **If timeout after 120s**: Something is wrong, see debugging guide

## Test Phase 2: Performance Validation (10 minutes)

### Goal
Measure actual performance improvements

### Steps
1. Note the start time
2. Run classification on 5 tables
3. Note the end time
4. Check logs for patterns

### Metrics to Collect

Create a simple tracking sheet:

| Table Name | Columns | Batches | Time (s) | Status | Errors |
|------------|---------|---------|----------|---------|--------|
| table_1    | 25      | 5       | 65       | ✅      | 0      |
| table_2    | 48      | 10      | 115      | ✅      | 0      |
| table_3    | 15      | 3       | 42       | ✅      | 0      |
| ...        | ...     | ...     | ...      | ...     | ...    |

### Success Criteria
- ✅ All tables complete without timeout
- ✅ Average time per table < 90s
- ✅ No more than 1 error per 10 batches
- ✅ Classification results look reasonable

### If Tests Fail
See **DEBUGGING_GUIDE.md** for troubleshooting steps

## Test Phase 3: Stress Test (Optional, 15 minutes)

### Goal
Test with larger batch to identify any remaining issues

### Steps
1. Run classification on 10-15 tables
2. Monitor system resources (CPU, memory)
3. Check for any degradation over time

### Resource Monitoring
```bash
# In another terminal, run:
watch -n 1 "ps aux | grep ollama | head -5"

# Watch for:
# - Memory growth (should be stable)
# - CPU usage (should be high but not pegged at 100%)
# - No zombie processes
```

### Success Criteria
- ✅ Sustained performance (no slowdown over time)
- ✅ Memory usage stable (< 6GB for Ollama)
- ✅ CPU usage efficient (< 100% per core average)
- ✅ Success rate > 90%

## Test Phase 4: Accuracy Spot Check (10 minutes)

### Goal
Verify classifications are still accurate after optimizations

### Steps
1. Pick 3-5 completed tables
2. Review the classifications manually
3. Check for obvious errors

### Examples to Check

**Table: CUSTOMERS**
- `customer_id` → Should be **SOC2** ✅
- `email` → Should be **PII** or **PII + SOC2** ✅
- `phone_number` → Should be **PII** ✅
- `created_at` → Should be **SOC2** or none ✅

**Table: ORDERS**
- `order_id` → Should be **SOC2** ✅
- `total_amount` → Should be **SOX** or **SOC2 + SOX** ✅
- `tax_amount` → Should be **SOX** ✅

**Table: EMPLOYEES**
- `employee_id` → Should be **SOC2** or **PII** ✅
- `ssn` → Should be **PII** (Sensitive) ✅ CRITICAL
- `salary` → Should be **SOX** or **PII + SOX** ✅
- `department` → Should be **SOC2** or none ✅

### Red Flags
- ❌ SSN/Credit Card not marked as PII
- ❌ Financial columns (salary, amount, price) not marked as SOX
- ❌ Everything classified as the same category
- ❌ Obviously non-sensitive columns marked as sensitive

## Results Interpretation

### Scenario A: All Tests Pass ✅
**Status**: Optimization successful!

**Next Steps**:
1. Run full 30-table classification
2. Document successful configuration
3. Monitor production usage

### Scenario B: Some Timeouts, Mostly Working ⚠️
**Status**: Needs tuning

**Possible Causes**:
1. Some tables have many columns (> 50)
2. Complex column names/comments
3. Ollama resource constraints

**Actions**:
1. Reduce `BATCH_SIZE` from 5 to 3
2. Reduce `MAX_COLUMNS_PER_TABLE` from 50 to 30
3. Reduce `max_workers` from 2 to 1
4. Check Ollama logs for errors

### Scenario C: Frequent Failures ❌
**Status**: Needs investigation

**Immediate Actions**:
1. Run the test script from DEBUGGING_GUIDE.md
2. Check Ollama status: `ollama list`, `curl http://localhost:11434/v1/models`
3. Review error logs for patterns
4. Consider using faster model: `llama3.2:1b`

**Escalation**:
If issues persist, use emergency fallback (disable LLM classification):
- See "Emergency Fallback" in DEBUGGING_GUIDE.md
- Use local embedding-based classification instead

### Scenario D: Works but Slow (> 120s per table) 🐌
**Status**: Performance optimization needed

**Priority Actions**:
1. Switch to faster model: `ollama pull llama3.2:1b`
2. Reduce batch size: `BATCH_SIZE = 3`
3. Reduce column limit: `MAX_COLUMNS_PER_TABLE = 30`
4. Keep `max_workers = 1` (no parallelism)

**Expected Improvement**: ~50% faster

### Scenario E: Works but Inaccurate Classifications 🎯
**Status**: Quality optimization needed

**Possible Causes**:
1. System prompt too simplified
2. Model not understanding context
3. Batch size too small (losing context)

**Actions**:
1. Consider using larger/better model: `llama3.1`
2. Increase batch size back to 7-10 (trade speed for accuracy)
3. Enhance system prompt with more examples
4. Increase timeout to 180s for better model

## Quick Decision Matrix

| Symptom | Action | File | Line | Change |
|---------|--------|------|------|--------|
| Timeout errors | Reduce batch | llm_service.py | 54 | `BATCH_SIZE = 3` |
| Slow (>120s) | Faster model | llm_service.py | 174 | `model="llama3.2:1b"` |
| High memory | Reduce context | llm_service.py | 74 | `num_ctx: 1024` |
| Parallel issues | Serial only | pipeline.py | 2542 | `max_workers=1` |
| Too many cols | Lower limit | llm_service.py | 55 | `MAX_COLUMNS = 30` |
| Inaccurate | Better model | llm_service.py | 174 | `model="llama3.1"` |
| JSON errors | Debug logging | llm_service.py | 99 | Add `logger.error(content)` |

## Success Metrics Summary

After all tests, you should have:

**Performance Metrics**:
- ✅ Average time per table: 30-90 seconds
- ✅ Success rate: > 90%
- ✅ Timeout rate: < 5%
- ✅ Error rate: < 3%

**Quality Metrics**:
- ✅ PII detection accuracy: > 90%
- ✅ SOX detection accuracy: > 85%
- ✅ SOC2 detection accuracy: > 80%
- ✅ False positive rate: < 10%

**Resource Metrics**:
- ✅ Peak memory: < 6GB
- ✅ Average CPU: 70-90%
- ✅ No crashes or hangs
- ✅ Stable performance over time

## Logging Commands

### Save logs for analysis:
```bash
# Start with logging
streamlit run src/app.py 2>&1 | tee classification_test.log

# After test completes, analyze:
grep "Batch .* completed" classification_test.log | wc -l  # Count successful batches
grep "timed out" classification_test.log | wc -l  # Count timeouts
grep "ERROR" classification_test.log  # See all errors
```

### Monitor Ollama:
```bash
# If Ollama is running via systemd:
journalctl -u ollama -f

# If running manually:
# Check the terminal where `ollama serve` is running
```

## Final Checklist

Before declaring success:

- [ ] Completed single table test (Phase 1)
- [ ] Measured performance on 5 tables (Phase 2)
- [ ] No timeout errors in logs
- [ ] Batch completion messages appearing
- [ ] Average time < 90s per table
- [ ] Classifications look accurate (spot check)
- [ ] Memory usage stable
- [ ] No Ollama crashes
- [ ] Documented actual performance metrics
- [ ] No show-stopping issues

If all checkboxes are ✅, the optimization is successful! 🎉

## What to Report Back

After testing, please share:

1. **Test Results**:
   - How many tables tested?
   - How many succeeded vs failed?
   - Average time per table?

2. **Sample Logs**:
   - One successful batch sequence
   - Any error messages (if failures occurred)

3. **Configuration**:
   - Which model used? (phi3.5, llama3.2:1b, etc.)
   - Any parameters changed from defaults?

4. **Next Steps**:
   - Ready for production use?
   - Need further tuning?
   - Any concerns?

---

**Good luck with testing!** 🚀

The optimizations should provide 6-10x faster processing and eliminate timeouts.
If you encounter any issues, refer to DEBUGGING_GUIDE.md for detailed troubleshooting.
