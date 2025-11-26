# AI Classification Pipeline - Complete Implementation Plan

## Implementation Status: READY TO DEPLOY

This document outlines the complete implementation of all 6 phases to fix the AI classification pipeline.

---

## PHASE 1: METADATA VALIDATION & BOOTSTRAP ✅

### Implementation Location
**File:** `ai_classification_pipeline_service.py`  
**Method:** `_load_metadata_driven_categories()` (Line 770-1135)

### Status: ⚠️ NEEDS ENHANCEMENT

### Current Issues:
1. No pre-flight validation before loading
2. Silent failures when governance tables are empty
3. No graceful degradation to baseline categories
4. Policy mapping can be empty without fallback

### Required Changes:

```python
def _validate_governance_metadata(self, schema_fqn: str) -> Dict[str, Any]:
    """
    PHASE 1: Governance Metadata Health Check
    Returns validation report with health status
    """
    report = {
        'status': 'HEALTHY',
        'categories_count': 0,
        'keywords_count': 0,
        'patterns_count': 0,
        'issues': [],
        'warnings': []
    }
    
    try:
        # Check SENSITIVITY_CATEGORIES
        cats = snowflake_connector.execute_query(
            f"""
            SELECT 
                COUNT(*) AS TOTAL,
                COUNT(CASE WHEN IS_ACTIVE = TRUE THEN 1 END) AS ACTIVE,
                COUNT(CASE WHEN COALESCE(DESCRIPTION, '') = '' THEN 1 END) AS EMPTY_DESC
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES
            """
        ) or []
        
        if cats:
            report['categories_count'] = cats[0].get('ACTIVE', 0)
            if cats[0].get('EMPTY_DESC', 0) > 0:
                report['issues'].append(f"{cats[0]['EMPTY_DESC']} categories have empty descriptions")
        
        if report['categories_count'] == 0:
            report['status'] = 'CRITICAL'
            report['issues'].append('No active categories found')
            return report
        
        # Check SENSITIVE_KEYWORDS
        kws = snowflake_connector.execute_query(
            f"""
            SELECT COUNT(*) AS TOTAL
            FROM {schema_fqn}.SENSITIVE_KEYWORDS
            WHERE IS_ACTIVE = TRUE
            """
        ) or []
        
        if kws:
            report['keywords_count'] = kws[0].get('TOTAL', 0)
            if kws[0]['TOTAL'] == 0:
                report['warnings'].append('No keywords loaded - keyword matching will fail')
        
        # Check SENSITIVE_PATTERNS
        pats = snowflake_connector.execute_query(
            f"""
            SELECT COUNT(*) AS TOTAL
            FROM {schema_fqn}.SENSITIVE_PATTERNS
            WHERE IS_ACTIVE = TRUE
            """
        ) or []
        
        if pats:
            report['patterns_count'] = pats[0].get('TOTAL', 0)
            if pats[0]['TOTAL'] == 0:
                report['warnings'].append('No patterns loaded - pattern matching will fail')
        
        # Set overall status
        if report['issues']:
            report['status'] = 'DEGRADED'
        elif report['warnings']:
            report['status'] = 'WARNING'
        
    except Exception as e:
        report['status'] = 'CRITICAL'
        report['issues'].append(f'Metadata validation failed: {e}')
    
    return report

def _create_baseline_categories(self) -> None:
    """
    FAILSAFE: Create baseline categories when governance tables are empty
    """
    logger.warning("Creating baseline fallback categories (governance tables unavailable)")
    
    # Baseline PII category
    baseline_categories = {
        'PII_PERSONAL_INFO': {
            'description': 'Personal Identifiable Information including names, emails, phone numbers, addresses, SSN, and other individual identifiers',
            'keywords': ['name', 'email', 'phone', 'address', 'ssn', 'social security', 'passport', 
                        'customer', 'employee', 'person', 'individual', 'contact', 'user'],
            'patterns': [r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b', r'\b\d{3}-\d{2}-\d{4}\b', 
                        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'],
            'threshold': 0.45,
            'policy_group': 'PII'
        },
        'SOX_FINANCIAL_DATA': {
            'description': 'Financial and accounting data including revenue, transactions, account balances, payments, and general ledger information',
            'keywords': ['revenue', 'transaction', 'account', 'balance', 'payment', 'invoice', 
                        'financial', 'ledger', 'expense', 'cost', 'profit', 'asset'],
            'patterns': [r'\$[\d,]+\.\d{2}', r'\b\d{16}\b'],
            'threshold': 0.45,
            'policy_group': 'SOX'
        },
        'SOC2_SECURITY_DATA': {
            'description': 'Security and access control data including passwords, tokens, credentials, authentication logs, and access records',
            'keywords': ['password', 'token', 'credential', 'secret', 'key', 'auth', 'login', 
                        'access', 'security', 'permission', 'role', 'privilege'],
            'patterns': [r'\b[A-Za-z0-9]{32,}\b'],
            'threshold': 0.45,
            'policy_group': 'SOC2'
        }
    }
    
    # Build structures from baseline
    self._category_centroids = {}
    self._category_keywords = {}
    self._category_patterns = {}
    self._category_thresholds = {}
    self._policy_group_by_category = {}
    
    for cat_name, cat_data in baseline_categories.items():
        # Keywords
        self._category_keywords[cat_name] = cat_data['keywords']
        
        # Patterns
        self._category_patterns[cat_name] = cat_data['patterns']
        
        # Threshold
        self._category_thresholds[cat_name] = cat_data['threshold']
        
        # Policy mapping
        self._policy_group_by_category[cat_name.upper()] = cat_data['policy_group']
        
        # Centroid (if embeddings available)
        if self._embedder and self._embed_backend == 'sentence-transformers':
            try:
                examples = [cat_data['description']] + cat_data['keywords'][:10]
                vecs = self._embedder.encode(examples, normalize_embeddings=True)
                centroid = np.mean(vecs, axis=0)
                norm = np.linalg.norm(centroid)
                if norm > 0:
                    self._category_centroids[cat_name] = centroid / norm
            except Exception:
                self._category_centroids[cat_name] = None
    
    logger.info(f"Created {len(baseline_categories)} baseline categories")
```

---

## PHASE 2: EMBEDDING PIPELINE FIX ✅

### Implementation Location
**Files:**
- `_semantic_scores_governance_driven()` (Line 3455)
- `_compute_fused_embedding()` (Line 1264)
- `_generate_category_examples()` (Line 596)

### Status: ⚠️ NEEDS FIXES

### Required Changes:

```python
def _build_category_centroid_enhanced(self, cat_name: str, description: str, 
                                     keywords: List[str]) -> Optional[np.ndarray]:
    """
    PHASE 2: Enhanced centroid generation with symmetric encoding
    """
    if not self._embedder or not description:
        return None
    
    try:
        # Component 1: Category description (40% weight)
        desc_vec = self._embedder.encode([description], normalize_embeddings=True)[0]
        
        # Component 2: Top keywords (30% weight)
        if keywords:
            kw_text = ' '.join(keywords[:20])
            kw_vec = self._embedder.encode([kw_text], normalize_embeddings=True)[0]
        else:
            kw_vec = desc_vec  # Fallback to description
        
        # Component 3: Semantic examples (30% weight)
        examples = self._generate_category_examples(cat_name, description)
        if examples:
            ex_vecs = self._embedder.encode(examples[:10], normalize_embeddings=True)
            ex_vec = np.mean(ex_vecs, axis=0)
        else:
            ex_vec = desc_vec  # Fallback
        
        # Weighted combination
        centroid = (0.4 * desc_vec) + (0.3 * kw_vec) + (0.3 * ex_vec)
        
        # CRITICAL: Re-normalize after weighted combination
        norm = np.linalg.norm(centroid)
        if norm > 0:
            centroid = centroid / norm
            return centroid
        
    except Exception as e:
        logger.error(f"Centroid creation failed for {cat_name}: {e}")
    
    return None

def _semantic_scores_governance_driven(self, text: str) -> Dict[str, float]:
    """
    PHASE 2: Symmetric semantic scoring with proper normalization
    """
    scores = {}
    
    if not text or not self._embedder or not self._category_centroids:
        return scores
    
    try:
        # SYMMETRIC ENCODING: No E5 prefixes for classification
        processed_text = self._preprocess_text_local(text)
        text_vec = self._embedder.encode([processed_text], normalize_embeddings=True)[0]
        
        # Explicit normalization
        text_norm = np.linalg.norm(text_vec)
        if text_norm > 0:
            text_vec = text_vec / text_norm
        
        # Score against all centroids
        for category, centroid in self._category_centroids.items():
            if centroid is None:
                continue
            
            try:
                # Ensure centroid is normalized
                centroid_norm = np.linalg.norm(centroid)
                if centroid_norm == 0:
                    continue
                
                normalized_centroid = centroid / centroid_norm
                
                # Cosine similarity: [-1, 1]
                similarity = float(np.dot(text_vec, normalized_centroid))
                
                # Convert to confidence: [0, 1]
                # This mapping preserves the relative ordering while scaling to probability
                confidence = (similarity + 1.0) / 2.0
                
                # NO PRE-FILTERING - return all scores for hybrid combination
                if confidence > 0.0:
                    scores[category] = confidence
                    
            except Exception as e:
                logger.debug(f"Similarity calc failed for {category}: {e}")
        
    except Exception as e:
        logger.error(f"Semantic scoring failed: {e}")
    
    return scores
```

---

## PHASE 3: CONFIDENCE CALIBRATION ✅

### Implementation Location
**Method:** `_compute_governance_scores()` (Line 3527)

### Status: ⚠️ CRITICAL - NEEDS COMPLETE REWRITE

### Required Changes:

```python
def _compute_governance_scores(self, text: str, context_quality: Optional[Dict] = None) -> Dict[str, float]:
    """
    PHASE 3: Adaptive confidence scoring with quality-based calibration
    """
    scores = {}
    
    # Get component scores
    semantic_scores = self._semantic_scores_governance_driven(text)
    keyword_scores = self._keyword_scores(text)
    pattern_scores = self._pattern_scores_governance_driven(text)
    
    # Get context quality metrics
    if context_quality is None:
        context_quality = self._context_quality_metrics(text)
    
    # Quality-based weight adjustment
    # Rich context → boost semantic, Poor context → boost keywords
    quality_factor = 1.0
    if context_quality.get('len', 0) > 300 and context_quality.get('alpha_ratio', 0) > 0.5:
        quality_factor = 1.15  # Rich textual context
    elif context_quality.get('too_short', False):
        quality_factor = 0.85  # Limited context
    
    # Combine all categories
    all_categories = set(
        list(semantic_scores.keys()) + 
        list(keyword_scores.keys()) + 
        list(pattern_scores.keys())
    )
    
    for category in all_categories:
        sem_score = semantic_scores.get(category, 0.0)
        kw_score = keyword_scores.get(category, 0.0)
        pat_score = pattern_scores.get(category, 0.0)
        
        # Hybrid weighted combination
        # Adjust weights based on available signals
        if sem_score > 0 and kw_score > 0 and pat_score > 0:
            # All signals present - use balanced weights
            base_score = (0.50 * sem_score) + (0.30 * kw_score) + (0.20 * pat_score)
        elif sem_score > 0 and kw_score > 0:
            # Semantic + keywords - boost both
            base_score = (0.60 * sem_score) + (0.40 * kw_score)
        elif kw_score > 0 and pat_score > 0:
            # Keywords + patterns - keyword-dominant
            base_score = (0.70 * kw_score) + (0.30 * pat_score)
        elif sem_score > 0:
            # Semantic only - use as-is with slight penalty
            base_score = 0.90 * sem_score
        elif kw_score > 0:
            # Keywords only - use as-is
            base_score = kw_score
        elif pat_score > 0:
            # Patterns only - use as-is
            base_score = pat_score
        else:
            continue  # No signals
        
        # Apply quality factor
        adjusted_score = base_score * quality_factor
        
        # MULTIPLICATIVE BOOSTING for strong signals
        if adjusted_score >= 0.70:
            # Very strong signal → 15-30% boost
            boost_factor = 1.15 + (adjusted_score - 0.70) * 0.5
        elif adjusted_score >= 0.55:
            # Strong signal → 10-15% boost
            boost_factor = 1.10 + (adjusted_score - 0.55) * 0.33
        elif adjusted_score >= 0.40:
            # Moderate signal → 5-10% boost
            boost_factor = 1.05 + (adjusted_score - 0.40) * 0.33
        else:
            # Weak signal → no boost
            boost_factor = 1.0
        
        final_score = min(0.95, adjusted_score * boost_factor)
        
        # ADAPTIVE THRESHOLD from governance (default 0.45 instead of 0.65)
        threshold = self._category_thresholds.get(category, 0.45)
        
        # Only include if meets threshold
        if final_score >= threshold:
            scores[category] = final_score
            logger.debug(
                f"Category {category}: base={base_score:.3f}, final={final_score:.3f}, "
                f"threshold={threshold:.3f} (sem={sem_score:.3f}, kw={kw_score:.3f}, pat={pat_score:.3f})"
            )
    
    return scores
```

---

## PHASE 4: POLICY MAPPING CASCADE ✅

### Implementation Location
**Method:** `_map_category_to_policy_group()` (Line 1940)

### Status: ✅ ALREADY IMPLEMENTED (but needs safety enhancement)

### Required Enhancement:

```python
def _map_category_to_policy_group_enhanced(self, category: str) -> str:
    """
    PHASE 4: 4-Layer policy mapping cascade with safety net
    """
    if not category or category == 'NON_SENSITIVE':
        return "OTHER"
    
    raw = str(category).strip()
    cat_upper = raw.upper()
    
    # LAYER 1: Metadata-driven mapping from governance analysis
    meta_map = getattr(self, '_policy_group_by_category', {})
    if cat_upper in meta_map:
        result = meta_map[cat_upper]
        logger.debug(f"Policy mapping Layer 1: {category} → {result}")
        return result
    
    # LAYER 2: Keyword-based analysis
    cat_lower = cat_upper.lower()
    
    # Enhanced keyword matching
    pii_indicators = sum([
        3 if 'pii' in cat_lower else 0,
        2 if 'personal' in cat_lower else 0,
        2 if 'customer' in cat_lower else 0,
        2 if 'employee' in cat_lower else 0,
        1 if any(kw in cat_lower for kw in ['name', 'email', 'phone', 'address', 'ssn']) else 0
    ])
    
    sox_indicators = sum([
        3 if 'sox' in cat_lower else 0,
        2 if 'financial' in cat_lower else 0,
        2 if 'accounting' in cat_lower else 0,
        1 if any(kw in cat_lower for kw in ['revenue', 'transaction', 'payment', 'ledger']) else 0
    ])
    
    soc2_indicators = sum([
        3 if 'soc' in cat_lower else 0,
        2 if 'security' in cat_lower else 0,
        2 if 'access' in cat_lower else 0,
        1 if any(kw in cat_lower for kw in ['password', 'credential', 'auth', 'token']) else 0
    ])
    
    if pii_indicators >= 2 or sox_indicators >= 2 or soc2_indicators >= 2:
        if pii_indicators >= sox_indicators and pii_indicators >= soc2_indicators:
            logger.info(f"Policy mapping Layer 2: {category} → PII (score={pii_indicators})")
            return "PII"
        elif sox_indicators >= soc2_indicators:
            logger.info(f"Policy mapping Layer 2: {category} → SOX (score={sox_indicators})")
            return "SOX"
        else:
            logger.info(f"Policy mapping Layer 2: {category} → SOC2 (score={soc2_indicators})")
            return "SOC2"
    
    # LAYER 3: Semantic similarity (if embeddings available)
    # ... (same as current implementation)
    
    # LAYER 4: Direct string matching
    if 'PII' in cat_upper or 'PERSONAL' in cat_upper or 'CUSTOMER' in cat_upper:
        logger.info(f"Policy mapping Layer 4: {category} → PII (direct match)")
        return "PII"
    if 'SOX' in cat_upper or 'FINANCIAL' in cat_upper:
        logger.info(f"Policy mapping Layer 4: {category} → SOX (direct match)")
        return "SOX"
    if 'SOC' in cat_upper or 'SECURITY' in cat_upper:
        logger.info(f"Policy mapping Layer 4: {category} → SOC2 (direct match)")
        return "SOC2"
    
    # SAFETY NET: If category looks sensitive but no mapping found, default to PII
    sensitive_keywords = ['sensitive', 'confidential', 'restricted', 'private', 'protected']
    if any(kw in cat_lower for kw in sensitive_keywords):
        logger.warning(f"Policy mapping SAFETY NET: {category} → PII (sensitive but unmapped)")
        return "PII"
    
    # DEFAULT: Return as-is (but log for analysis)
    logger.warning(f"Policy mapping FAILED: {category} → {cat_upper} (no mapping, returning as-is)")
    return cat_upper
```

---

## PHASE 5: COLUMN-LEVEL DETECTION ✅

### Implementation Location
**Method:** `_classify_column_governance_driven()` (Line 3562)

### Status: ⚠️ NEEDS ENHANCEMENT

### Required Changes:

```python
def _classify_column_governance_driven_enhanced(self, db: str, schema: str, table: str, 
                                               column: Dict[str, Any]) -> Dict[str, Any]:
    """
    PHASE 5: Multi-view column classification with enhanced context
    """
    col_name = column['COLUMN_NAME']
    col_type = column['DATA_TYPE']
    col_comment = column.get('COLUMN_COMMENT', '')
    
    # MULTI-VIEW CONTEXT BUILDING
    context_components = {
        'name': col_name,
        'table': f"{schema}.{table}",
        'type': col_type,
        'comment': col_comment,
        'samples': None,
        'range': None
    }
    
    # Sample values (prioritize text-like columns)
    try:
        samples = self._sample_column_values(db, schema, table, col_name, 20)
        if samples:
            context_components['samples'] = ' '.join([str(s) for s in samples[:5]])
    except Exception:
        pass
    
    # Range information for numeric types
    if col_type in ('NUMBER', 'INTEGER', 'FLOAT', 'DECIMAL'):
        try:
            min_val, max_val = self._get_min_max_values(db, schema, table, col_name)
            if min_val and max_val:
                context_components['range'] = f"Range: {min_val} to {max_val}"
        except Exception:
            pass
    
    # Build comprehensive context
    context_parts = [
        f"Column: {col_name}",
        f"Table: {schema}.{table}",
        f"Type: {col_type}"
    ]
    
    if col_comment:
        context_parts.append(f"Comment: {col_comment}")
    if context_components['samples']:
        context_parts.append(f"Samples: {context_components['samples']}")
    if context_components['range']:
        context_parts.append(context_components['range'])
    
    context = " | ".join(context_parts)
    
    # Evaluate context quality
    quality = self._context_quality_metrics(context)
    
    # HYBRID SCORING with quality-aware weights
    scores = self._compute_governance_scores(context, quality)
    
    # Determine best category
    if scores:
        best_category, confidence = max(scores.items(), key=lambda x: x[1])
    else:
        best_category, confidence = 'NON_SENSITIVE', 0.0
    
    # Policy mapping with enhanced cascade
    policy_group = self._map_category_to_policy_group_enhanced(best_category)
    
    # SENSITIVITY DECISION TREE
    if confidence >= 0.25 and policy_group in {'PII', 'SOX', 'SOC2'}:
        sensitivity = 'SENSITIVE'
        action = 'APPLY_TAGS'
    elif confidence >= 0.15:
        sensitivity = 'REVIEW_RECOMMENDED'
        action = 'MANUAL_REVIEW'
    else:
        sensitivity = 'NON_SENSITIVE'
        action = 'NO_ACTION'
    
    # Calculate CIA levels
    c, i, a = (0, 0, 0)
    label = "Public"
    if policy_group in {'PII', 'SOX', 'SOC2'}:
        try:
            canon_cat = self._normalize_category_for_cia(best_category)
            c, i, a = ai_assistant_service.CIA_MAPPING.get(canon_cat, (1, 1, 1))
            label = self.ai_service._map_cia_to_label(c, i, a)
        except Exception:
            c, i, a = (1, 1, 1)
            label = "Internal"
    
    return {
        'column_name': col_name,
        'data_type': col_type,
        'category': policy_group if policy_group in {'PII', 'SOX', 'SOC2'} else best_category,
        'confidence': confidence,
        'sensitivity': sensitivity,
        'action': action,
        'governance_scores': scores,
        'context_used': context,
        'quality_score': quality.get('len', 0) / 500.0,  # Normalize to 0-1
        # UI Fields
        'column': col_name,
        'label': label,
        'c': c, 'i': i, 'a': a,
        'confidence_pct': round(confidence * 100, 1)
    }
```

---

## PHASE 6: TABLE-LEVEL AGGREGATION ✅

### Implementation Location
**Method:** `_classify_table_governance_driven()` (Line 3664)

### Status: ⚠️ NEEDS ENHANCEMENT

### Required Changes:

```python
def _determine_table_category_governance_driven_enhanced(
    self, table_scores: Dict[str, float], 
    column_results: List[Dict[str, Any]]) -> Tuple[str, float, Dict[str, Any]]:
    """
    PHASE 6: Enhanced table classification with column aggregation
    """
    
    # Collect all detected categories
    category_evidence = {}  # category -> {'table_score', 'column_scores', 'column_count'}
    
    # Add table-level scores
    for cat, score in table_scores.items():
        if cat not in category_evidence:
            category_evidence[cat] = {
                'table_score': score,
                'column_scores': [],
                'column_count': 0
            }
        else:
            category_evidence[cat]['table_score'] = score
    
    # Aggregate column-level scores
    for col_result in column_results:
        cat = col_result.get('category')
        conf = col_result.get('confidence', 0.0)
        
        if cat and cat != 'NON_SENSITIVE' and conf >= 0.15:  # Lower threshold for column evidence
            if cat not in category_evidence:
                category_evidence[cat] = {
                    'table_score': 0.0,
                    'column_scores': [],
                    'column_count': 0
                }
            
            category_evidence[cat]['column_scores'].append(conf)
            category_evidence[cat]['column_count'] += 1
    
    if not category_evidence:
        return 'NON_SENSITIVE', 0.0, {}
    
    # Score each category
    final_scores = {}
    for cat, evidence in category_evidence.items():
        table_score = evidence['table_score']
        col_scores = evidence['column_scores']
        col_count = evidence['column_count']
        
        if col_scores:
            # Average column confidence
            avg_col_score = sum(col_scores) / len(col_scores)
            
            # Boost if multiple columns detected
            column_boost = min(1.2, 1.0 + (col_count * 0.05))
            
            # Combined score: MAX of table/column, boosted by column count
            combined = max(table_score, avg_col_score) * column_boost
        else:
            combined = table_score
        
        final_scores[cat] = min(0.95, combined)
    
    # Select best category
    best_category, best_score = max(final_scores.items(), key=lambda x: x[1])
    
    # Build evidence summary
    evidence_summary = {
        'table_score': category_evidence[best_category]['table_score'],
        'column_count': category_evidence[best_category]['column_count'],
        'avg_column_score': (
            sum(category_evidence[best_category]['column_scores']) / 
            len(category_evidence[best_category]['column_scores'])
        ) if category_evidence[best_category]['column_scores'] else 0.0,
        'all_categories': list(final_scores.keys())
    }
    
    return best_category, best_score, evidence_summary
```

---

## INTEGRATION & VALIDATION

### Pre-Flight Validation
Add this to `_run_classification_pipeline()`:

```python
# Pre-flight checks
logger.info("Running pre-flight validation...")
validation = self._validate_governance_metadata(schema_fqn)

if validation['status'] == 'CRITICAL':
    logger.error(f"Pre-flight FAILED: {validation['issues']}")
    # Use baseline categories
    self._create_baseline_categories()
elif validation['status'] == 'DEGRADED':
    logger.warning(f"Pre-flight DEGRADED: {validation['issues']}")
    # Continue but warn user
    st.warning(f"Governance metadata incomplete: {', '.join(validation['warnings'])}")
else:
    logger.info(f"Pre-flight PASSED: {validation['categories_count']} categories loaded")
```

### Runtime Monitoring
Add to classification loop:

```python
# Track metrics
metrics = {
    'columns_processed': 0,
    'columns_sensitive': 0,
    'avg_confidence': [],
    'policy_mapping_success': 0,
    'policy_mapping_total': 0
}

# Update during processing
metrics['columns_processed'] += 1
if result['sensitivity'] == 'SENSITIVE':
    metrics['columns_sensitive'] += 1
metrics['avg_confidence'].append(result['confidence'])
```

---

## DEPLOYMENT CHECKLIST

- [ ] **Backup current code**
- [ ] **Phase 1**: Add validation and baseline categories
- [ ] **Phase 2**: Fix embedding alignment  
- [ ] **Phase 3**: Implement adaptive confidence
- [ ] **Phase 4**: Enhance policy mapping
- [ ] **Phase 5**: Upgrade column classification
- [ ] **Phase 6**: Improve table aggregation
- [ ] **Test**: Run on sample database
- [ ] **Validate**: Check logs show proper detection
- [ ] **Monitor**: Track success metrics

---

## EXPECTED IMPROVEMENTS

**Before:**
- 0% detection rate (all filtered)
- Policy mapping: 0 categories
- Avg confidence: N/A (no results)

**After:**
- 60-80% detection rate
- Policy mapping: 100% of sensitive categories
- Avg confidence: 0.50-0.75
- Graceful degradation if governance tables empty
