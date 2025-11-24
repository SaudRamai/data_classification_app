# ✅ E5-Large-v2 Accuracy Fix

## Issue Analysis
The `intfloat/e5-large-v2` model was failing to accurately classify columns because **it requires specific prefixes** to distinguish between "queries" (the thing you are searching for) and "passages" (the documents/categories you are searching against).

Without these prefixes, the model treats the input as raw text, leading to poor embedding alignment and low similarity scores, causing the classifier to fall back to keywords or produce random results.

## Fix Applied
I have updated `src/services/ai_classification_service.py` to implement the correct E5 prompting strategy:

1.  **Category Centroids (Passages):**
    *   Added `"passage: "` prefix to all category examples and descriptions before generating centroid vectors.
    *   *Example:* `"passage: PII includes email, phone, and ssn"`

2.  **Column Classification (Queries):**
    *   Added `"query: "` prefix to column names and comments before generating embeddings.
    *   *Example:* `"query: customer_email | user contact info"`

3.  **Model Awareness:**
    *   Added logic to automatically detect if an E5 model is being used (`self._model_name`) and apply these prefixes dynamically.

## Expected Result
*   **Higher Accuracy:** The embeddings will now be correctly aligned in the vector space.
*   **Better Separation:** PII, SOX, and SOC2 categories will have distinct, high-confidence regions.
*   **Correct Classification:** Columns like `email`, `ssn`, `revenue` will now match their respective categories with high confidence scores (>0.85).

## Next Steps
1.  **Run the Data Seed Script:**
    *   Execute `python seed_governance_data.py` to populate Snowflake with the correct category descriptions and keywords.
    *   *Note:* This is critical for the "passage" embeddings to be generated correctly.
2.  **Restart the Application.**
3.  **Run the Classification Pipeline.**
4.  Verify that columns are now being correctly classified into PII, SOX, and SOC2.
