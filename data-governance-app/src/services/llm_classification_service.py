import json
import logging
import requests
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class LLMClassificationService:
    """
    Service for classifying database columns using an LLM (Large Language Model).
    Designed to work with local open-source models (e.g., Phi-3.5, Llama-3) via an OpenAI-compatible API (like Ollama).
    """

    def __init__(self, base_url: str = "http://localhost:11434/v1", model: str = "phi3.5", api_key: str = "ollama"):
        """
        Initialize the LLM service.
        
        Args:
            base_url: The base URL of the LLM API (default: Ollama local).
            model: The model name to use (default: phi3.5).
            api_key: API key if required (default: 'ollama' for local).
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

    def check_connection(self) -> bool:
        """Check if the LLM service is reachable."""
        try:
            # Try listing models or a simple chat completion
            response = requests.get(f"{self.base_url}/models", headers=self.headers, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"LLM connection check failed: {e}")
            return False

    def classify_table(self, table_name: str, columns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Classify all columns in a table using the LLM.
        
        Args:
            table_name: Name of the table.
            columns: List of column metadata dictionaries (must contain 'name', 'data_type').
            
        Returns:
            JSON object with classification results.
        """
        import time
        
        # OPTIMIZED: Reduced batch size from 15 to 5 for faster processing and lower timeout risk
        # Smaller batches = faster LLM responses = less chance of timeout
        BATCH_SIZE = 5  # Reduced from 15
        MAX_COLUMNS_PER_TABLE = 50  # Prevent processing massive tables
        
        all_columns_results = []
        errors = []
        
        # If no columns, return empty
        if not columns:
            return {"columns": []}
        
        # Limit total columns to prevent excessive processing time
        if len(columns) > MAX_COLUMNS_PER_TABLE:
            logger.warning(f"Table {table_name} has {len(columns)} columns. Limiting to {MAX_COLUMNS_PER_TABLE}.")
            columns = columns[:MAX_COLUMNS_PER_TABLE]
        
        total_batches = (len(columns) + BATCH_SIZE - 1) // BATCH_SIZE
        logger.info(f"🔍 Classifying table '{table_name}': {len(columns)} columns in {total_batches} batches")
        
        # Track overall timing
        table_start = time.time()
            
        for batch_idx in range(0, len(columns), BATCH_SIZE):
            batch_num = batch_idx // BATCH_SIZE + 1
            batch_cols = columns[batch_idx:batch_idx + BATCH_SIZE]
            
            # ENHANCED: Log which columns are in this batch for debugging
            col_names = [c['name'] for c in batch_cols]
            logger.info(f"  ├─ Batch {batch_num}/{total_batches}: Processing {len(batch_cols)} columns: {col_names}")
            
            batch_start = time.time()
            prompt = self._construct_prompt(table_name, batch_cols)
            
            try:
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,  # Low temperature for deterministic results
                    "response_format": {"type": "json_object"},  # Force JSON if supported
                    "options": {
                        "num_ctx": 2048,  # Limit context window for faster processing
                        "num_predict": 512  # Limit output tokens
                    }
                }
                
                # OPTIMIZED: Reduced timeout from 600s to 120s (2 minutes)
                # Fail fast on problematic batches instead of waiting 10 minutes
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=120  # Reduced from 600
                )
                
                batch_time = time.time() - batch_start
                
                if response.status_code != 200:
                    logger.error(f"  ├─ ❌ Batch {batch_num} failed: HTTP {response.status_code} ({batch_time:.2f}s)")
                    logger.error(f"  │    Response: {response.text[:200]}")
                    errors.append(f"Batch {batch_num} failed: HTTP {response.status_code}")
                    continue
                    
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # clean markdown code blocks if present
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()
                    
                # Attempt to parse JSON
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    # Attempt simple repair for common trailing comma or missing bracket issues
                    try:
                        # Remove trailing commas
                        import re
                        fixed_content = re.sub(r",\s*([\]}])", r"\1", content)
                        parsed = json.loads(fixed_content)
                    except Exception:
                        logger.error(f"  ├─ ❌ Batch {batch_num} JSON parse failed ({batch_time:.2f}s)")
                        logger.error(f"  │    Content preview: {content[:200]}...")
                        errors.append(f"Batch {batch_num} JSON parse error")
                        continue

                if "columns" in parsed:
                    batch_results = parsed["columns"]
                    all_columns_results.extend(batch_results)
                    
                    # ENHANCED: Log successful batch with timing and classification summary
                    classified_count = len(batch_results)
                    cumulative = len(all_columns_results)
                    logger.info(f"  ├─ ✅ Batch {batch_num}/{total_batches} complete: {classified_count} columns in {batch_time:.2f}s (cumulative: {cumulative}/{len(columns)})")
                else:
                    logger.warning(f"  ├─ ⚠️  Batch {batch_num} returned no 'columns' key ({batch_time:.2f}s)")
                    
            except requests.exceptions.Timeout:
                batch_time = time.time() - batch_start
                error_msg = f"Batch {batch_num} timed out after 120s (columns: {col_names})"
                logger.error(f"  ├─ ⏱️  {error_msg}")
                errors.append(error_msg)
            except Exception as e:
                batch_time = time.time() - batch_start
                logger.error(f"  ├─ ❌ Batch {batch_num} error after {batch_time:.2f}s: {e}")
                errors.append(f"Batch {batch_num}: {str(e)}")
        
        # ENHANCED: Final summary with stats
        table_time = time.time() - table_start
        success_rate = (len(all_columns_results) / len(columns) * 100) if columns else 0
        
        logger.info(f"  └─ Table '{table_name}' complete: {len(all_columns_results)}/{len(columns)} columns ({success_rate:.0f}%) in {table_time:.2f}s")
        
        if errors:
            logger.warning(f"     Errors encountered: {len(errors)} batch(es) failed: {errors}")
                
        if not all_columns_results and errors:
            return {"error": "; ".join(errors)}
            
        return {"columns": all_columns_results}

    def _get_system_prompt(self) -> str:
        """Returns the optimized system prompt for faster processing and higher accuracy."""
        # OPTIMIZED: Simplified prompt to reduce token count (was ~500 tokens, now ~150 tokens)
        # Faster generation = lower timeout risk
        return """You are a data classification engine. Classify database columns into PII, SOC2, and SOX categories.

RULES:
1. PII: Personally Identifiable Information (name, email, address, SSN, phone, DOB)
2. SOC2: Customer/system data (user IDs, logs, transaction IDs, timestamps)
3. SOX: Financial data (prices, costs, revenue, salaries, tax amounts)
4. Multiple tags allowed if column serves multiple purposes
5. Set "pii_type" to "Sensitive" for SSN/credit cards, "Non-Sensitive" for names/emails

OUTPUT JSON FORMAT:
{
  "columns": [
    {
      "col_name": "exact_column_name",
      "classifications": ["PII"],
      "pii_type": "Sensitive",
      "confidence": "High"
    }
  ]
}

Be concise. Output only valid JSON."""

    def _construct_prompt(self, table_name: str, columns: List[Dict[str, Any]]) -> str:
        """Constructs a concise user prompt."""
        col_desc = [f"- {c['name']} ({c.get('data_type','?')}) : {c.get('comment','')}" for c in columns]
        return f"""Analyze Table: '{table_name}'
Columns:
{chr(10).join(col_desc)}

Return JSON with classifications for ALL columns. Apply the EXAMPLES logic strictly."""

# Singleton instance
llm_classification_service = LLMClassificationService()
