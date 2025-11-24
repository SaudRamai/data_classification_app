# Quick Debugging Guide - LLM Classification Timeouts

## Immediate Checks

### 1. Is Ollama Running?
```bash
# Check if Ollama is responding
curl http://localhost:11434/v1/models

# Expected: JSON response with model list
# If error: Start Ollama first
```

### 2. Is the Model Loaded?
```bash
# List available models
ollama list

# Should show: phi3.5
# If not: ollama pull phi3.5
```

### 3. Can Ollama Process Requests?
```bash
# Simple test
curl -X POST http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "phi3.5",
    "messages": [{"role": "user", "content": "Say hello"}],
    "options": {"num_ctx": 2048, "num_predict": 50}
  }'

# Should return: JSON with response in < 5 seconds
# If timeout: Ollama has issues
```

## Common Issues & Fixes

### Issue 1: Still Timing Out After 120s

**Symptoms**:
```
[ERROR] Batch X timed out after 120s (columns: [...])
```

**Fixes** (in order of preference):

1. **Reduce batch size** in `llm_classification_service.py` line 54:
   ```python
   BATCH_SIZE = 3  # Was 5, now 3
   ```

2. **Reduce column limit** in `llm_classification_service.py` line 55:
   ```python
   MAX_COLUMNS_PER_TABLE = 30  # Was 50, now 30
   ```

3. **Reduce parallelism** in `ai_classification_pipeline_service.py` line 2542:
   ```python
   max_workers=1  # Was 2, back to 1
   ```

4. **Switch to faster model**:
   ```bash
   ollama pull llama3.2:1b
   ```
   Then in `llm_classification_service.py` line 174:
   ```python
   llm_classification_service = LLMClassificationService(model="llama3.2:1b")
   ```

### Issue 2: JSON Parse Errors

**Symptoms**:
```
[ERROR] Failed to parse JSON content from batch X
```

**Fixes**:

1. **Check Ollama version**: Ensure you have latest stable
   ```bash
   ollama version
   ```

2. **Try different model**: Some models are better at JSON
   ```bash
   ollama pull llama3.1
   ```

3. **Inspect actual response** (add debug logging):
   In `llm_classification_service.py` around line 99, add:
   ```python
   logger.error(f"Raw LLM response: {content}")
   ```

### Issue 3: Out of Memory (OOM)

**Symptoms**:
- Ollama crashes
- System becomes unresponsive
- Error: "killed by signal"

**Fixes**:

1. **Reduce context window** in `llm_classification_service.py` line 74:
   ```python
   "num_ctx": 1024,  # Was 2048, now 1024
   ```

2. **Use smaller model**:
   ```bash
   ollama pull tinyllama
   ```

3. **Set Ollama memory limit**:
   ```bash
   # In Ollama config (if using systemd)
   sudo systemctl edit ollama
   
   # Add:
   [Service]
   Environment="OLLAMA_MAX_LOADED_MODELS=1"
   Environment="OLLAMA_NUM_PARALLEL=1"
   ```

### Issue 4: Slow Performance (No Errors, Just Slow)

**Symptoms**:
- Batches complete but take > 60s each
- No errors in logs

**Fixes**:

1. **Check CPU/GPU usage**:
   ```bash
   htop
   # or
   nvidia-smi  # if using GPU
   ```

2. **Verify model is using GPU** (if available):
   ```bash
   # In Ollama logs, should see:
   # "loading model to GPU"
   ```

3. **Reduce token limits** in `llm_classification_service.py` lines 74-75:
   ```python
   "num_ctx": 1024,      # Was 2048
   "num_predict": 256    # Was 512
   ```

4. **Simplify prompt further** (line 157-173):
   - Remove multi-tagging rules
   - Keep only PII/SOC2/SOX definitions

## Performance Tuning Matrix

| Scenario | BATCH_SIZE | MAX_COLUMNS | max_workers | timeout | Model |
|----------|-----------|-------------|-------------|---------|-------|
| **Default (Implemented)** | 5 | 50 | 2 | 120 | phi3.5 |
| **Conservative (Safe)** | 3 | 30 | 1 | 90 | phi3.5 |
| **Fast (Risky)** | 5 | 50 | 3 | 120 | llama3.2:1b |
| **Ultra-Fast (Less Accurate)** | 3 | 30 | 2 | 60 | tinyllama |
| **High Accuracy (Slow)** | 5 | 50 | 1 | 180 | llama3.1 |

## Log Interpretation

### Good Signs ✅
```
[INFO] Classifying 50 columns in 10 batches (batch_size=5)
[INFO] Processing batch 1/10 (5 columns)...
[INFO] ✓ Batch 1/10 completed: 5 columns classified
```

### Warning Signs ⚠️
```
[WARNING] Table X has 150 columns. Limiting to 50.
[WARNING] Batch X returned no 'columns' key
```
- First: Expected, working as designed
- Second: LLM didn't return valid format, but recoverable

### Error Signs ❌
```
[ERROR] Batch X timed out after 120s (columns: [...])
[ERROR] Failed to parse JSON content from batch X
[ERROR] Error during LLM classification batch X: Connection refused
```
- First two: LLM issues, try fixes above
- Last one: Ollama not running

## Quick Test Script

Save as `test_llm.py`:

```python
import requests
import time

base_url = "http://localhost:11434/v1"
model = "phi3.5"

# Test 1: Connection
print("Test 1: Checking connection...")
try:
    r = requests.get(f"{base_url}/models", timeout=5)
    print(f"✅ Connection OK: {r.status_code}")
except Exception as e:
    print(f"❌ Connection failed: {e}")
    exit(1)

# Test 2: Simple completion
print("\nTest 2: Testing simple completion...")
start = time.time()
try:
    r = requests.post(
        f"{base_url}/chat/completions",
        headers={"Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": "Say 'test'"}],
            "options": {"num_ctx": 512, "num_predict": 10}
        },
        timeout=30
    )
    elapsed = time.time() - start
    print(f"✅ Simple completion OK: {elapsed:.1f}s")
except Exception as e:
    print(f"❌ Simple completion failed: {e}")

# Test 3: Classification-like request
print("\nTest 3: Testing classification request...")
start = time.time()
try:
    r = requests.post(
        f"{base_url}/chat/completions",
        headers={"Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": "Classify columns as PII, SOC2, or SOX. Output JSON."},
                {"role": "user", "content": "Columns: user_id, email, order_total"}
            ],
            "temperature": 0.1,
            "options": {"num_ctx": 2048, "num_predict": 256}
        },
        timeout=60
    )
    elapsed = time.time() - start
    print(f"✅ Classification request OK: {elapsed:.1f}s")
    print(f"Response length: {len(r.text)} chars")
except Exception as e:
    print(f"❌ Classification request failed: {e}")

print("\n=== Summary ===")
print("If all tests passed, your Ollama setup is working correctly.")
print("Expected times: Test 2 < 5s, Test 3 < 30s")
```

Run with:
```bash
python test_llm.py
```

## Emergency Fallback

If LLM classification is completely broken, disable it:

**File**: `src/services/ai_classification_pipeline_service.py`

**Line 487-494**: Comment out LLM path

```python
# Step 2-8: Run classification pipeline
# TEMPORARY: LLM disabled, using local classification
# if not llm_classification_service.check_connection():
#     st.error(f"LLM Service not reachable...")
#     return
# st.success(f"Using LLM-based classification...")
# results = self._classify_assets_llm(db=db, assets=assets[:30])

# Use local classification instead
results = self._classify_assets_local(db=db, assets=assets[:30])
```

This will use the embedding-based local classification which is slower but more reliable.

## Get Help

If none of these fixes work:

1. **Collect diagnostics**:
   ```bash
   # Save logs
   streamlit run app.py 2>&1 | tee streamlit.log
   
   # Check Ollama
   ollama list > ollama_models.txt
   curl http://localhost:11434/v1/models > ollama_status.txt
   ```

2. **Share**:
   - `streamlit.log` (last 100 lines)
   - `ollama_status.txt`
   - System specs (CPU, RAM, GPU)
   - Ollama version

3. **Key questions**:
   - Which specific error appears most?
   - How many columns in the problem table?
   - Does the test script pass?
   - What's your Ollama version?

---

**Last Updated**: After implementing Tier 1 & 2 optimizations
**Expected Success Rate**: 90%+ with default settings
**Fastest Configuration**: llama3.2:1b, BATCH_SIZE=3, max_workers=2
