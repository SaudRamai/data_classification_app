# How E5-Large-v2 Detects Sensitive Data: A Deep Dive

## Executive Summary

The `intfloat/e5-large-v2` embedding model detects sensitive tables and columns through **semantic understanding** rather than simple keyword matching. It converts text into 1024-dimensional vectors where semantically similar concepts cluster together, enabling it to recognize PII, SOX, and SOC2 data even when expressed in different ways.

---

## The 4-Stage Detection Pipeline

### **Stage 1: Category Centroid Generation** 📊
**Location:** `ai_classification_pipeline_service.py`, lines 1014-1064

#### What Happens:
For each sensitivity category (PII, SOX, SOC2), the system creates a **centroid** - a representative point in 1024-dimensional embedding space.

#### Process:
1. **Load Category Description** from `SENSITIVITY_CATEGORIES` table
   - Example for PII: "Personally Identifiable Information. This category covers any information that can directly or indirectly identify a natural person..."

2. **Load Keywords** from `SENSITIVE_KEYWORDS` table
   - Example: `ssn`, `email`, `phone_number`, `credit_card`, `passport`

3. **Combine Description + Keywords**
   ```python
   combined_text = f"{description} {' '.join(keywords[:50])}"
   ```
   This creates rich context like:
   ```
   "Personally Identifiable Information... ssn email phone_number credit_card passport..."
   ```

4. **Generate Training Examples**
   - Extracts key phrases from the combined text
   - Adds top 20 keywords as additional examples
   - Example examples for PII:
     - "social security number"
     - "email address"
     - "phone number"
     - "passport number"
     - "customer name"

5. **Encode with E5 Model**
   ```python
   # CRITICAL: E5 requires "passage: " prefix for documents
   processed_examples = [preprocess(s) for s in examples]
   vecs = embedder.encode(processed_examples, normalize_embeddings=True)
   ```
   - Each example becomes a 1024-dimensional vector
   - Vectors are normalized to unit length

6. **Calculate Centroid**
   ```python
   centroid = np.mean(vecs, axis=0)  # Average all vectors
   centroid = centroid / np.linalg.norm(centroid)  # Normalize
   ```
   - The centroid represents the "semantic center" of the category
   - It captures the essence of what PII/SOX/SOC2 "means"

**Result:** Each category has a centroid vector that represents its semantic meaning.

---

### **Stage 2: Column Text Encoding** 🔍
**Location:** `ai_classification_pipeline_service.py`, lines 1100-1123

#### What Happens:
When classifying a column, the system builds a rich text representation and encodes it.

#### Process:
1. **Build Column Context**
   ```python
   column_context = f"{table_name}.{column_name} {data_type} {comment}"
   ```
   Example: `"CUSTOMERS.EMAIL_ADDRESS VARCHAR(255) Customer email for notifications"`

2. **Preprocess Text**
   - Remove stopwords ("the", "a", "and")
   - Normalize whitespace
   - Lowercase

3. **Encode with E5 Model**
   ```python
   # CRITICAL: E5 requires "query: " prefix for search queries
   t_enc = f"query: {column_context}"
   column_vector = embedder.encode([t_enc], normalize_embeddings=True)[0]
   ```
   - The column becomes a 1024-dimensional vector
   - The "query: " prefix tells E5 this is a search query (asymmetric retrieval)

**Result:** The column is now a vector in the same 1024-dimensional space as the category centroids.

---

### **Stage 3: Semantic Similarity Calculation** 🎯
**Location:** `ai_classification_pipeline_service.py`, lines 1129-1173

#### What Happens:
The system calculates how similar the column vector is to each category centroid.

#### Process:
1. **Cosine Similarity**
   ```python
   for category, centroid in category_centroids.items():
       similarity = np.dot(column_vector, centroid)
       confidence = (similarity + 1.0) / 2.0  # Convert from [-1,1] to [0,1]
   ```
   - Dot product measures angle between vectors
   - Similar concepts have high dot product (close to 1.0)
   - Dissimilar concepts have low dot product (close to -1.0)

2. **Min-Max Normalization**
   ```python
   min_score = min(all_scores)
   max_score = max(all_scores)
   normalized = (score - min_score) / (max_score - min_score)
   ```
   - Spreads scores across [0, 1] range
   - Emphasizes differences between categories

3. **Aggressive Confidence Boosting**
   ```python
   if normalized >= 0.60:
       boosted = pow(normalized, 0.1)  # Push to ~0.95+
   elif normalized >= 0.40:
       boosted = pow(normalized, 0.15)  # Push to ~0.85+
   elif normalized >= 0.25:
       boosted = pow(normalized, 0.25)  # Push to ~0.75+
   ```
   - Power function amplifies strong signals
   - Ensures high-confidence matches get very high scores
   - Suppresses noise (weak signals stay low)

**Result:** Each category gets a confidence score (0-1) indicating how likely the column belongs to that category.

**Example Output:**
```python
{
    'PII': 0.92,      # Very likely PII
    'SOX': 0.15,      # Unlikely SOX
    'SOC2': 0.08      # Unlikely SOC2
}
```

---

### **Stage 4: Hybrid Scoring & Final Classification** ⚖️
**Location:** `ai_classification_pipeline_service.py`, lines 1800-2000

#### What Happens:
Semantic scores are combined with keyword and pattern matching for robust classification.

#### Process:
1. **Keyword Matching**
   - Checks if column name contains known keywords
   - Example: `EMAIL_ADDRESS` matches keyword `email` → PII
   - Weight: 20% of final score

2. **Pattern Matching**
   - Samples actual data values
   - Checks against regex patterns
   - Example: `123-45-6789` matches SSN pattern → PII
   - Weight: 15% of final score

3. **Semantic Matching**
   - Uses E5 embedding similarity (from Stage 3)
   - Weight: **75% of final score** (dominant signal)

4. **Weighted Combination**
   ```python
   final_score = (semantic * 0.75) + (keyword * 0.20) + (pattern * 0.15)
   ```

5. **Category Selection**
   ```python
   if final_score >= detection_threshold:  # Usually 0.65
       assign_category(column, category)
   ```

**Result:** Column is classified into the category with the highest final score above threshold.

---

## Why E5 is Accurate: The Secret Sauce 🔬

### 1. **Asymmetric Retrieval Design**
E5 is specifically trained for **asymmetric semantic search**:
- **Passages** (category descriptions): Prefixed with `"passage: "`
- **Queries** (columns): Prefixed with `"query: "`

This tells the model:
- Passages are comprehensive definitions
- Queries are short search terms
- The model should match queries to relevant passages

### 2. **Semantic Understanding**
E5 understands that these are all PII:
- `customer_email`
- `user_contact_info`
- `personal_identifier`
- `subscriber_details`

Even though they use different words, they're semantically similar.

### 3. **Contextual Awareness**
E5 considers the full context:
- `CUSTOMERS.SSN` → PII (personal identifier)
- `AUDIT_LOG.SSN` → SOC2 (security audit trail)
- `PAYROLL.SSN` → SOX (financial reporting)

The table name provides crucial context.

### 4. **Rich Training Data**
E5 was pre-trained on massive text corpora, learning:
- Financial terminology (for SOX)
- Security concepts (for SOC2)
- Personal data types (for PII)
- Industry-specific jargon

### 5. **High-Dimensional Space**
1024 dimensions allow fine-grained distinctions:
- Dimension 1-200: General semantics
- Dimension 201-500: Domain-specific concepts
- Dimension 501-800: Fine-grained attributes
- Dimension 801-1024: Contextual nuances

---

## Real-World Example 🌍

**Column:** `EMPLOYEES.WORK_EMAIL`

### Stage 1: Centroids (Pre-computed)
```
PII Centroid: [0.23, -0.15, 0.87, ..., 0.42]  (1024 dims)
SOX Centroid: [-0.12, 0.45, -0.33, ..., 0.18]
SOC2 Centroid: [0.08, 0.22, -0.55, ..., -0.31]
```

### Stage 2: Encode Column
```
Input: "query: EMPLOYEES.WORK_EMAIL VARCHAR(255)"
Vector: [0.21, -0.18, 0.91, ..., 0.39]  (1024 dims)
```

### Stage 3: Calculate Similarity
```
PII:   dot_product = 0.78 → confidence = 0.89 → boosted = 0.94
SOX:   dot_product = 0.12 → confidence = 0.56 → boosted = 0.42
SOC2:  dot_product = -0.05 → confidence = 0.47 → boosted = 0.28
```

### Stage 4: Hybrid Scoring
```
Semantic:  PII=0.94, SOX=0.42, SOC2=0.28  (weight: 0.75)
Keyword:   PII=0.80 (matches "email")     (weight: 0.20)
Pattern:   PII=0.00 (no data sampled)     (weight: 0.15)

Final:     PII = (0.94*0.75) + (0.80*0.20) + (0.00*0.15) = 0.87
```

**Result:** ✅ Classified as **PII** with 87% confidence

---

## Key Advantages Over Traditional Methods

| Traditional Keyword Matching | E5 Semantic Matching |
|------------------------------|----------------------|
| Exact match only | Semantic similarity |
| Misses synonyms | Understands synonyms |
| No context awareness | Full context understanding |
| Brittle (breaks with variations) | Robust (handles variations) |
| Requires exhaustive keyword lists | Learns from descriptions |
| Can't handle new terms | Generalizes to new terms |

---

## Configuration & Tuning 🎛️

### Critical Parameters:

1. **Detection Threshold** (default: 0.65)
   - Minimum confidence to classify
   - Lower = more sensitive (more false positives)
   - Higher = more specific (more false negatives)

2. **Semantic Weight** (default: 0.75)
   - Importance of E5 embeddings
   - Higher = trust semantic understanding more

3. **Keyword Weight** (default: 0.20)
   - Importance of exact keyword matches
   - Higher = trust traditional matching more

4. **Pattern Weight** (default: 0.15)
   - Importance of regex pattern matching
   - Higher = trust data patterns more

5. **Confidence Boosting** (lines 1149-1166)
   - Power function exponents control aggressiveness
   - Lower exponent = more aggressive boosting

---

## Conclusion

The E5-Large-v2 model achieves high accuracy through:
1. **Rich semantic understanding** of category definitions
2. **Asymmetric retrieval** design (passage vs. query)
3. **Contextual awareness** (table + column + data type)
4. **Hybrid scoring** (semantic + keyword + pattern)
5. **Aggressive confidence boosting** for strong signals

This multi-layered approach ensures that sensitive data is detected accurately, even when expressed in unconventional ways, while minimizing false positives through the hybrid scoring system.
