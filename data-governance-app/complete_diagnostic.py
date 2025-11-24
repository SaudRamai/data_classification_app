"""
COMPLETE END-TO-END GOVERNANCE CONFIGURATION VALIDATION
========================================================

This diagnostic script validates why category centroids may not be generated.
It performs comprehensive checks on:
- Snowflake connectivity and schema
- Category metadata
- Keywords and patterns
- Python object mapping
- Embedding model initialization
- Centroid builder
- Fallback logic

DO NOT classify data. DO NOT generate embeddings.
ONLY run diagnostics and explain EXACTLY why centroids were or were not generated.
"""

import sys
sys.path.insert(0, 'src')

from services.snowflake_connector import snowflake_connector
from services.governance_db_resolver import resolve_governance_db
import traceback

# Color codes for terminal output
class Colors:
    PASS = '\033[92m'      # Green
    WARNING = '\033[93m'   # Yellow
    FAIL = '\033[91m'      # Red
    CRITICAL = '\033[95m'  # Magenta
    RESET = '\033[0m'      # Reset
    BOLD = '\033[1m'       # Bold

def print_header(text):
    print(f"\n{Colors.BOLD}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 80}{Colors.RESET}\n")

def print_status(status, message):
    if status == "PASS":
        print(f"{Colors.PASS}✓ PASS{Colors.RESET}     {message}")
    elif status == "WARNING":
        print(f"{Colors.WARNING}⚠ WARNING{Colors.RESET}  {message}")
    elif status == "FAIL":
        print(f"{Colors.FAIL}✗ FAIL{Colors.RESET}     {message}")
    elif status == "CRITICAL":
        print(f"{Colors.CRITICAL}✗ CRITICAL{Colors.RESET} {message}")

def print_section(title):
    print(f"\n{Colors.BOLD}{'─' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}Section: {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{'─' * 80}{Colors.RESET}")

# Global diagnostic results
diagnostic_results = {
    'snowflake_connectivity': None,
    'categories_validation': None,
    'keywords_validation': None,
    'patterns_validation': None,
    'embedding_service': None,
    'centroid_initialization': None,
    'fallback_reason': None
}

def section_1_snowflake_metadata():
    """Section 1 – Snowflake Metadata Status"""
    print_section("1. Snowflake Metadata Status")
    
    issues = []
    
    # Check 1.1: Governance Database
    print("\n1.1 Governance Database Resolution")
    try:
        gov_db = resolve_governance_db()
        if gov_db:
            print_status("PASS", f"Governance database resolved: {gov_db}")
        else:
            print_status("CRITICAL", "Governance database is None")
            issues.append("Governance database not configured")
            diagnostic_results['snowflake_connectivity'] = 'CRITICAL'
            return issues
    except Exception as e:
        print_status("CRITICAL", f"Failed to resolve governance database: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Governance database resolution error: {e}")
        diagnostic_results['snowflake_connectivity'] = 'CRITICAL'
        return issues
    
    schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
    
    # Check 1.2: Schema Exists
    print("\n1.2 Schema Validation")
    try:
        result = snowflake_connector.execute_query(f"SHOW SCHEMAS LIKE 'DATA_CLASSIFICATION_GOVERNANCE' IN DATABASE {gov_db}")
        if result and len(result) > 0:
            print_status("PASS", f"Schema exists: {schema_fqn}")
        else:
            print_status("CRITICAL", f"Schema 'DATA_CLASSIFICATION_GOVERNANCE' not found in {gov_db}")
            issues.append("Schema does not exist")
            diagnostic_results['snowflake_connectivity'] = 'CRITICAL'
            return issues
    except Exception as e:
        print_status("FAIL", f"Cannot verify schema: {e}")
        issues.append(f"Schema verification failed: {e}")
    
    # Check 1.3: Tables Exist
    print("\n1.3 Table Existence Validation")
    required_tables = ['SENSITIVITY_CATEGORIES', 'SENSITIVE_KEYWORDS', 'SENSITIVE_PATTERNS']
    
    for table_name in required_tables:
        try:
            result = snowflake_connector.execute_query(f"SHOW TABLES LIKE '{table_name}' IN SCHEMA {schema_fqn}")
            if result and len(result) > 0:
                print_status("PASS", f"Table exists: {table_name}")
            else:
                print_status("CRITICAL", f"Table missing: {table_name}")
                issues.append(f"Table {table_name} does not exist")
        except Exception as e:
            print_status("FAIL", f"Cannot verify table {table_name}: {e}")
            issues.append(f"Table verification failed for {table_name}: {e}")
    
    # Check 1.4: Query Connectivity
    print("\n1.4 Query Connectivity Test")
    try:
        test_query = f"SELECT COUNT(*) as CNT FROM {schema_fqn}.SENSITIVITY_CATEGORIES"
        result = snowflake_connector.execute_query(test_query)
        if result:
            count = result[0].get('CNT', 0)
            print_status("PASS", f"Query executed successfully. Row count: {count}")
            if count == 0:
                print_status("WARNING", "SENSITIVITY_CATEGORIES table is empty")
                issues.append("SENSITIVITY_CATEGORIES has 0 rows")
        else:
            print_status("FAIL", "Query returned no results")
            issues.append("Cannot query SENSITIVITY_CATEGORIES")
    except Exception as e:
        print_status("CRITICAL", f"Query execution failed: {e}")
        issues.append(f"Query connectivity error: {e}")
    
    if issues:
        diagnostic_results['snowflake_connectivity'] = 'FAIL'
    else:
        diagnostic_results['snowflake_connectivity'] = 'PASS'
    
    return issues

def section_2_categories_validation():
    """Section 2 – Categories Validation"""
    print_section("2. Categories Validation")
    
    issues = []
    
    try:
        gov_db = resolve_governance_db()
        schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
    except Exception as e:
        print_status("CRITICAL", f"Cannot resolve governance database: {e}")
        diagnostic_results['categories_validation'] = 'CRITICAL'
        return [f"Governance DB error: {e}"]
    
    # Check 2.1: Load Categories
    print("\n2.1 Loading Categories from SENSITIVITY_CATEGORIES")
    try:
        categories = snowflake_connector.execute_query(f"""
            SELECT 
                CATEGORY_NAME,
                DESCRIPTION,
                IS_ACTIVE,
                DETECTION_THRESHOLD,
                DEFAULT_THRESHOLD,
                SENSITIVITY_WEIGHT,
                CATEGORY_ID
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES
        """)
        
        if not categories:
            print_status("CRITICAL", "No categories found in SENSITIVITY_CATEGORIES")
            issues.append("SENSITIVITY_CATEGORIES table is empty")
            diagnostic_results['categories_validation'] = 'CRITICAL'
            return issues
        
        print_status("PASS", f"Loaded {len(categories)} categories from database")
        
    except Exception as e:
        print_status("CRITICAL", f"Failed to query SENSITIVITY_CATEGORIES: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Query error: {e}")
        diagnostic_results['categories_validation'] = 'CRITICAL'
        return issues
    
    # Check 2.2: Validate Each Category
    print("\n2.2 Validating Individual Categories")
    
    valid_categories = 0
    invalid_categories = 0
    
    for idx, cat in enumerate(categories, 1):
        cat_name = cat.get('CATEGORY_NAME')
        description = cat.get('DESCRIPTION')
        is_active = cat.get('IS_ACTIVE')
        detection_threshold = cat.get('DETECTION_THRESHOLD')
        default_threshold = cat.get('DEFAULT_THRESHOLD')
        sensitivity_weight = cat.get('SENSITIVITY_WEIGHT')
        category_id = cat.get('CATEGORY_ID')
        
        print(f"\n   Category {idx}: {cat_name}")
        
        category_issues = []
        
        # Validate CATEGORY_NAME
        if not cat_name or str(cat_name).strip() == '':
            print_status("CRITICAL", f"   CATEGORY_NAME is empty")
            category_issues.append("Empty CATEGORY_NAME")
        else:
            print_status("PASS", f"   CATEGORY_NAME: '{cat_name}'")
        
        # Validate DESCRIPTION
        if description is None:
            print_status("CRITICAL", f"   DESCRIPTION is NULL → Centroid cannot be built")
            category_issues.append("NULL DESCRIPTION")
        elif str(description).strip() == '':
            print_status("CRITICAL", f"   DESCRIPTION is empty → Centroid cannot be built")
            category_issues.append("Empty DESCRIPTION")
        else:
            desc_len = len(str(description))
            print_status("PASS", f"   DESCRIPTION: {desc_len} characters")
            if desc_len < 10:
                print_status("WARNING", f"   DESCRIPTION is very short ({desc_len} chars)")
                category_issues.append(f"Short DESCRIPTION ({desc_len} chars)")
        
        # Validate IS_ACTIVE
        if is_active is None or is_active == False:
            print_status("WARNING", f"   IS_ACTIVE: {is_active} → Category will be skipped")
            category_issues.append("Inactive category")
        else:
            print_status("PASS", f"   IS_ACTIVE: {is_active}")
        
        # Validate DETECTION_THRESHOLD
        if detection_threshold is None:
            print_status("WARNING", f"   DETECTION_THRESHOLD is NULL (will use default)")
        elif detection_threshold < 0.1 or detection_threshold > 1.0:
            print_status("FAIL", f"   DETECTION_THRESHOLD: {detection_threshold} (invalid range, should be 0.1-1.0)")
            category_issues.append(f"Invalid DETECTION_THRESHOLD: {detection_threshold}")
        else:
            print_status("PASS", f"   DETECTION_THRESHOLD: {detection_threshold}")
        
        # Validate DEFAULT_THRESHOLD
        if default_threshold is not None:
            if default_threshold < 0.1 or default_threshold > 1.0:
                print_status("WARNING", f"   DEFAULT_THRESHOLD: {default_threshold} (invalid range)")
            else:
                print_status("PASS", f"   DEFAULT_THRESHOLD: {default_threshold}")
        
        # Validate SENSITIVITY_WEIGHT
        if sensitivity_weight is None:
            print_status("WARNING", f"   SENSITIVITY_WEIGHT is NULL (will use 1.0)")
        elif sensitivity_weight <= 0:
            print_status("FAIL", f"   SENSITIVITY_WEIGHT: {sensitivity_weight} (must be > 0)")
            category_issues.append(f"Invalid SENSITIVITY_WEIGHT: {sensitivity_weight}")
        else:
            print_status("PASS", f"   SENSITIVITY_WEIGHT: {sensitivity_weight}")
        
        # Validate CATEGORY_ID
        if category_id is None:
            print_status("CRITICAL", f"   CATEGORY_ID is NULL")
            category_issues.append("NULL CATEGORY_ID")
        else:
            print_status("PASS", f"   CATEGORY_ID: {category_id}")
        
        if category_issues:
            print(f"   {Colors.FAIL}Issues found: {', '.join(category_issues)}{Colors.RESET}")
            invalid_categories += 1
            issues.extend([f"{cat_name}: {issue}" for issue in category_issues])
        else:
            print(f"   {Colors.PASS}✓ Category is valid{Colors.RESET}")
            valid_categories += 1
    
    # Summary
    print(f"\n2.3 Categories Summary")
    print(f"   Total categories: {len(categories)}")
    print(f"   Valid categories: {valid_categories}")
    print(f"   Invalid categories: {invalid_categories}")
    
    if invalid_categories > 0:
        diagnostic_results['categories_validation'] = 'FAIL'
    elif valid_categories == 0:
        diagnostic_results['categories_validation'] = 'CRITICAL'
    else:
        diagnostic_results['categories_validation'] = 'PASS'
    
    return issues

def section_3_keywords_patterns_validation():
    """Section 3 – Keywords/Patterns Validation"""
    print_section("3. Keywords and Patterns Validation")
    
    issues = []
    
    try:
        gov_db = resolve_governance_db()
        schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
    except Exception as e:
        print_status("CRITICAL", f"Cannot resolve governance database: {e}")
        return [f"Governance DB error: {e}"]
    
    # Check 3.1: Keywords Validation
    print("\n3.1 Keywords Validation")
    try:
        keywords = snowflake_connector.execute_query(f"""
            SELECT 
                c.CATEGORY_NAME,
                c.CATEGORY_ID,
                COUNT(k.KEYWORD_ID) as KEYWORD_COUNT,
                COUNT(CASE WHEN k.IS_ACTIVE = TRUE THEN 1 END) as ACTIVE_KEYWORD_COUNT
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES c
            LEFT JOIN {schema_fqn}.SENSITIVE_KEYWORDS k ON c.CATEGORY_ID = k.CATEGORY_ID
            WHERE c.IS_ACTIVE = TRUE
            GROUP BY c.CATEGORY_NAME, c.CATEGORY_ID
            ORDER BY c.CATEGORY_NAME
        """)
        
        if keywords:
            print_status("PASS", f"Loaded keyword statistics for {len(keywords)} categories")
            
            for kw in keywords:
                cat_name = kw.get('CATEGORY_NAME')
                total_kw = kw.get('KEYWORD_COUNT', 0)
                active_kw = kw.get('ACTIVE_KEYWORD_COUNT', 0)
                
                if active_kw == 0:
                    print_status("WARNING", f"   {cat_name}: 0 active keywords → Centroid will be DEGRADED")
                    issues.append(f"{cat_name}: No active keywords")
                elif active_kw < 5:
                    print_status("WARNING", f"   {cat_name}: Only {active_kw} active keywords (recommend 10+)")
                    issues.append(f"{cat_name}: Few keywords ({active_kw})")
                else:
                    print_status("PASS", f"   {cat_name}: {active_kw} active keywords")
        else:
            print_status("FAIL", "No keyword data found")
            issues.append("No keywords in SENSITIVE_KEYWORDS")
    
    except Exception as e:
        print_status("FAIL", f"Failed to validate keywords: {e}")
        issues.append(f"Keyword validation error: {e}")
    
    # Check 3.2: Patterns Validation
    print("\n3.2 Patterns Validation")
    try:
        patterns = snowflake_connector.execute_query(f"""
            SELECT 
                c.CATEGORY_NAME,
                c.CATEGORY_ID,
                COUNT(p.PATTERN_ID) as PATTERN_COUNT,
                COUNT(CASE WHEN p.IS_ACTIVE = TRUE THEN 1 END) as ACTIVE_PATTERN_COUNT
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES c
            LEFT JOIN {schema_fqn}.SENSITIVE_PATTERNS p ON c.CATEGORY_ID = p.CATEGORY_ID
            WHERE c.IS_ACTIVE = TRUE
            GROUP BY c.CATEGORY_NAME, c.CATEGORY_ID
            ORDER BY c.CATEGORY_NAME
        """)
        
        if patterns:
            print_status("PASS", f"Loaded pattern statistics for {len(patterns)} categories")
            
            for pat in patterns:
                cat_name = pat.get('CATEGORY_NAME')
                total_pat = pat.get('PATTERN_COUNT', 0)
                active_pat = pat.get('ACTIVE_PATTERN_COUNT', 0)
                
                if active_pat == 0:
                    print_status("WARNING", f"   {cat_name}: 0 active patterns → Pattern scoring unavailable")
                    issues.append(f"{cat_name}: No active patterns")
                else:
                    print_status("PASS", f"   {cat_name}: {active_pat} active patterns")
        else:
            print_status("WARNING", "No pattern data found")
            issues.append("No patterns in SENSITIVE_PATTERNS")
    
    except Exception as e:
        print_status("FAIL", f"Failed to validate patterns: {e}")
        issues.append(f"Pattern validation error: {e}")
    
    # Check 3.3: MATCH_TYPE Validation
    print("\n3.3 MATCH_TYPE Validation")
    try:
        match_types = snowflake_connector.execute_query(f"""
            SELECT DISTINCT MATCH_TYPE
            FROM {schema_fqn}.SENSITIVE_KEYWORDS
            WHERE IS_ACTIVE = TRUE
        """)
        
        if match_types:
            valid_match_types = {'EXACT', 'PARTIAL', 'FUZZY'}
            for mt in match_types:
                match_type = mt.get('MATCH_TYPE')
                if match_type in valid_match_types:
                    print_status("PASS", f"   MATCH_TYPE: {match_type}")
                else:
                    print_status("WARNING", f"   MATCH_TYPE: {match_type} (non-standard, will default to EXACT)")
                    issues.append(f"Non-standard MATCH_TYPE: {match_type}")
        else:
            print_status("WARNING", "No MATCH_TYPE values found (will default to EXACT)")
    
    except Exception as e:
        print_status("WARNING", f"Cannot validate MATCH_TYPE: {e}")
    
    # Check 3.4: Foreign Key Integrity
    print("\n3.4 Foreign Key Integrity Check")
    try:
        orphaned_keywords = snowflake_connector.execute_query(f"""
            SELECT COUNT(*) as CNT
            FROM {schema_fqn}.SENSITIVE_KEYWORDS k
            WHERE NOT EXISTS (
                SELECT 1 FROM {schema_fqn}.SENSITIVITY_CATEGORIES c
                WHERE c.CATEGORY_ID = k.CATEGORY_ID
            )
        """)
        
        orphaned_count = orphaned_keywords[0].get('CNT', 0) if orphaned_keywords else 0
        if orphaned_count > 0:
            print_status("FAIL", f"   {orphaned_count} orphaned keywords (CATEGORY_ID not in SENSITIVITY_CATEGORIES)")
            issues.append(f"{orphaned_count} orphaned keywords")
        else:
            print_status("PASS", "   All keywords have valid CATEGORY_ID references")
    
    except Exception as e:
        print_status("WARNING", f"Cannot validate foreign keys: {e}")
    
    if issues:
        diagnostic_results['keywords_validation'] = 'WARNING'
        diagnostic_results['patterns_validation'] = 'WARNING'
    else:
        diagnostic_results['keywords_validation'] = 'PASS'
        diagnostic_results['patterns_validation'] = 'PASS'
    
    return issues

def section_4_python_object_mapping():
    """Section 4 – Python Object Mapping Validation"""
    print_section("4. Python Object Mapping Validation")
    
    issues = []
    
    try:
        gov_db = resolve_governance_db()
        schema_fqn = f"{gov_db}.DATA_CLASSIFICATION_GOVERNANCE"
    except Exception as e:
        print_status("CRITICAL", f"Cannot resolve governance database: {e}")
        return [f"Governance DB error: {e}"]
    
    print("\n4.1 SQL Column to Python Attribute Mapping")
    
    # Load a sample category
    try:
        sample = snowflake_connector.execute_query(f"""
            SELECT 
                CATEGORY_NAME,
                DESCRIPTION,
                IS_ACTIVE,
                DETECTION_THRESHOLD,
                CATEGORY_ID
            FROM {schema_fqn}.SENSITIVITY_CATEGORIES
            LIMIT 1
        """)
        
        if not sample:
            print_status("FAIL", "No sample category to test mapping")
            return ["No categories available for mapping test"]
        
        cat = sample[0]
        
        # Test mapping
        mapping_tests = [
            ('CATEGORY_NAME', 'category_name', cat.get('CATEGORY_NAME')),
            ('DESCRIPTION', 'description', cat.get('DESCRIPTION')),
            ('IS_ACTIVE', 'is_active', cat.get('IS_ACTIVE')),
            ('DETECTION_THRESHOLD', 'detection_threshold', cat.get('DETECTION_THRESHOLD')),
            ('CATEGORY_ID', 'category_id', cat.get('CATEGORY_ID'))
        ]
        
        for sql_col, python_attr, value in mapping_tests:
            if value is not None:
                print_status("PASS", f"   {sql_col} → {python_attr}: {value}")
            else:
                print_status("WARNING", f"   {sql_col} → {python_attr}: NULL")
                issues.append(f"{sql_col} is NULL")
        
        # Check for common mismatches
        print("\n4.2 Common Mismatch Detection")
        
        mismatches = []
        
        # Check if using wrong attribute names
        if 'name' in str(cat.keys()).lower() and 'CATEGORY_NAME' not in cat:
            mismatches.append("Using 'name' instead of 'CATEGORY_NAME'")
        
        if 'details' in str(cat.keys()).lower() and 'DESCRIPTION' not in cat:
            mismatches.append("Using 'details' instead of 'DESCRIPTION'")
        
        if 'desc' in str(cat.keys()).lower() and 'DESCRIPTION' not in cat:
            mismatches.append("Using 'desc' instead of 'DESCRIPTION'")
        
        if mismatches:
            for mismatch in mismatches:
                print_status("CRITICAL", f"   {mismatch}")
                issues.append(mismatch)
        else:
            print_status("PASS", "   No attribute name mismatches detected")
        
        # Check capitalization
        print("\n4.3 Capitalization Check")
        actual_keys = list(cat.keys())
        expected_keys = ['CATEGORY_NAME', 'DESCRIPTION', 'IS_ACTIVE', 'DETECTION_THRESHOLD', 'CATEGORY_ID']
        
        for expected in expected_keys:
            if expected in actual_keys:
                print_status("PASS", f"   Column '{expected}' has correct capitalization")
            else:
                # Check if lowercase version exists
                if expected.lower() in [k.lower() for k in actual_keys]:
                    print_status("WARNING", f"   Column '{expected}' exists but with different capitalization")
                    issues.append(f"Capitalization mismatch: {expected}")
                else:
                    print_status("FAIL", f"   Column '{expected}' not found in result set")
                    issues.append(f"Missing column: {expected}")
    
    except Exception as e:
        print_status("CRITICAL", f"Mapping validation failed: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Mapping error: {e}")
    
    return issues

def section_5_embedding_service():
    """Section 5 – Embedding Service Status"""
    print_section("5. Embedding Service Status")
    
    issues = []
    
    print("\n5.1 Embedding Model Import")
    try:
        from sentence_transformers import SentenceTransformer
        print_status("PASS", "SentenceTransformer imported successfully")
    except ImportError as e:
        print_status("CRITICAL", f"Cannot import SentenceTransformer: {e}")
        issues.append("SentenceTransformer not installed")
        diagnostic_results['embedding_service'] = 'CRITICAL'
        return issues
    
    print("\n5.2 NumPy Import")
    try:
        import numpy as np
        print_status("PASS", "NumPy imported successfully")
    except ImportError as e:
        print_status("CRITICAL", f"Cannot import NumPy: {e}")
        issues.append("NumPy not installed")
        diagnostic_results['embedding_service'] = 'CRITICAL'
        return issues
    
    print("\n5.3 Model Loading")
    try:
        print("   Loading E5-Large-v2 model (this may take a moment)...")
        embedder = SentenceTransformer('intfloat/e5-large-v2')
        print_status("PASS", "E5-Large-v2 model loaded successfully")
    except Exception as e:
        print_status("CRITICAL", f"Failed to load embedding model: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Model loading error: {e}")
        diagnostic_results['embedding_service'] = 'CRITICAL'
        return issues
    
    print("\n5.4 Test Encoding")
    try:
        test_text = "This is a test sentence for embedding validation"
        vector = embedder.encode([test_text], normalize_embeddings=True)
        
        if vector is None:
            print_status("CRITICAL", "Encoding returned None")
            issues.append("Encoding returns None")
        elif len(vector) == 0:
            print_status("CRITICAL", "Encoding returned empty vector")
            issues.append("Empty vector")
        else:
            v = vector[0] if isinstance(vector, (list, tuple)) else vector
            dim = len(v) if hasattr(v, '__len__') else (v.shape[-1] if hasattr(v, 'shape') else 0)
            
            if dim == 0:
                print_status("CRITICAL", "Vector has dimension 0")
                issues.append("Zero-dimensional vector")
            else:
                print_status("PASS", f"Test encoding successful (dimension: {dim})")
                
                # Check if numeric
                if hasattr(v, 'dtype'):
                    print_status("PASS", f"   Vector is numeric (dtype: {v.dtype})")
                else:
                    print_status("WARNING", "   Cannot verify vector dtype")
                
                # Check for None values
                if np.any(np.isnan(v)):
                    print_status("FAIL", "   Vector contains NaN values")
                    issues.append("Vector contains NaN")
                else:
                    print_status("PASS", "   Vector contains no NaN values")
    
    except Exception as e:
        print_status("CRITICAL", f"Test encoding failed: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Encoding error: {e}")
        diagnostic_results['embedding_service'] = 'CRITICAL'
        return issues
    
    if issues:
        diagnostic_results['embedding_service'] = 'FAIL'
    else:
        diagnostic_results['embedding_service'] = 'PASS'
    
    return issues

def section_6_centroid_initialization():
    """Section 6 – Centroid Initialization Status"""
    print_section("6. Centroid Initialization Status")
    
    issues = []
    
    print("\n6.1 Initializing AI Classification Pipeline")
    try:
        from services.ai_classification_pipeline_service import AIClassificationPipelineService
        
        print("   Creating pipeline instance...")
        pipeline = AIClassificationPipelineService()
        print_status("PASS", "Pipeline instance created")
        
    except Exception as e:
        print_status("CRITICAL", f"Failed to create pipeline: {e}")
        print(f"   Stack trace: {traceback.format_exc()}")
        issues.append(f"Pipeline initialization error: {e}")
        diagnostic_results['centroid_initialization'] = 'CRITICAL'
        return issues
    
    print("\n6.2 Checking Centroid Storage")
    
    if not hasattr(pipeline, '_category_centroids'):
        print_status("CRITICAL", "_category_centroids attribute not found")
        issues.append("Missing _category_centroids attribute")
        diagnostic_results['centroid_initialization'] = 'CRITICAL'
        return issues
    
    centroids = pipeline._category_centroids
    
    if centroids is None:
        print_status("CRITICAL", "_category_centroids is None")
        issues.append("Centroids is None")
        diagnostic_results['centroid_initialization'] = 'CRITICAL'
        return issues
    
    if len(centroids) == 0:
        print_status("CRITICAL", "_category_centroids is empty dictionary")
        issues.append("No centroids created")
        diagnostic_results['centroid_initialization'] = 'CRITICAL'
        return issues
    
    print_status("PASS", f"Found {len(centroids)} category centroids")
    
    print("\n6.3 Validating Individual Centroids")
    
    valid_centroids = 0
    null_centroids = 0
    invalid_centroids = 0
    
    for cat_name, centroid in centroids.items():
        if centroid is None:
            print_status("FAIL", f"   {cat_name}: Centroid is None")
            null_centroids += 1
            issues.append(f"{cat_name}: Centroid is None")
        elif not hasattr(centroid, '__len__'):
            print_status("FAIL", f"   {cat_name}: Centroid is not array-like")
            invalid_centroids += 1
            issues.append(f"{cat_name}: Invalid centroid type")
        elif len(centroid) == 0:
            print_status("FAIL", f"   {cat_name}: Centroid is empty")
            invalid_centroids += 1
            issues.append(f"{cat_name}: Empty centroid")
        else:
            dim = len(centroid)
            print_status("PASS", f"   {cat_name}: Valid centroid (dimension: {dim})")
            valid_centroids += 1
            
            # Check for NaN
            import numpy as np
            if np.any(np.isnan(centroid)):
                print_status("WARNING", f"   {cat_name}: Centroid contains NaN values")
                issues.append(f"{cat_name}: Centroid has NaN")
    
    print(f"\n6.4 Centroid Summary")
    print(f"   Total categories: {len(centroids)}")
    print(f"   Valid centroids: {valid_centroids}")
    print(f"   Null centroids: {null_centroids}")
    print(f"   Invalid centroids: {invalid_centroids}")
    
    if valid_centroids == 0:
        diagnostic_results['centroid_initialization'] = 'CRITICAL'
    elif null_centroids > 0 or invalid_centroids > 0:
        diagnostic_results['centroid_initialization'] = 'FAIL'
    else:
        diagnostic_results['centroid_initialization'] = 'PASS'
    
    # Check other attributes
    print("\n6.5 Checking Related Attributes")
    
    if hasattr(pipeline, '_category_keywords'):
        kw_count = sum(len(v) for v in pipeline._category_keywords.values())
        print_status("PASS", f"   _category_keywords: {kw_count} total keywords")
    else:
        print_status("WARNING", "   _category_keywords attribute not found")
    
    if hasattr(pipeline, '_category_patterns'):
        pat_count = sum(len(v) for v in pipeline._category_patterns.values())
        print_status("PASS", f"   _category_patterns: {pat_count} total patterns")
    else:
        print_status("WARNING", "   _category_patterns attribute not found")
    
    if hasattr(pipeline, '_category_thresholds'):
        thresh_count = len(pipeline._category_thresholds)
        print_status("PASS", f"   _category_thresholds: {thresh_count} categories")
    else:
        print_status("WARNING", "   _category_thresholds attribute not found")
    
    return issues

def section_7_fallback_logic():
    """Section 7 – Fallback Mode Reason"""
    print_section("7. Fallback Mode Analysis")
    
    fallback_reasons = []
    
    # Analyze diagnostic results
    if diagnostic_results['snowflake_connectivity'] == 'CRITICAL':
        fallback_reasons.append("Snowflake connectivity failure")
    
    if diagnostic_results['categories_validation'] == 'CRITICAL':
        fallback_reasons.append("No categories found or all categories invalid")
    elif diagnostic_results['categories_validation'] == 'FAIL':
        fallback_reasons.append("Some categories have invalid metadata")
    
    if diagnostic_results['embedding_service'] == 'CRITICAL':
        fallback_reasons.append("Embedding model failed to load or encode")
    
    if diagnostic_results['centroid_initialization'] == 'CRITICAL':
        fallback_reasons.append("No centroids were created")
    elif diagnostic_results['centroid_initialization'] == 'FAIL':
        fallback_reasons.append("Some centroids failed to initialize")
    
    if fallback_reasons:
        print("\n7.1 Fallback Mode: ACTIVE")
        print_status("WARNING", "System will fall back to keyword-only classification")
        print("\nReasons for fallback:")
        for reason in fallback_reasons:
            print(f"   • {reason}")
        diagnostic_results['fallback_reason'] = fallback_reasons
    else:
        print("\n7.1 Fallback Mode: NOT ACTIVE")
        print_status("PASS", "System is operating in full semantic classification mode")
        diagnostic_results['fallback_reason'] = None
    
    return fallback_reasons

def final_verdict():
    """Final Verdict + Fix Recommendations"""
    print_header("FINAL DIAGNOSTIC REPORT")
    
    print("\n📊 SECTION SUMMARY")
    print(f"{'─' * 80}")
    
    sections = [
        ("1. Snowflake Metadata Status", diagnostic_results['snowflake_connectivity']),
        ("2. Categories Validation", diagnostic_results['categories_validation']),
        ("3. Keywords Validation", diagnostic_results['keywords_validation']),
        ("4. Patterns Validation", diagnostic_results['patterns_validation']),
        ("5. Embedding Service Status", diagnostic_results['embedding_service']),
        ("6. Centroid Initialization", diagnostic_results['centroid_initialization']),
    ]
    
    for section_name, status in sections:
        if status == 'PASS':
            print(f"{Colors.PASS}✓ PASS{Colors.RESET}     {section_name}")
        elif status == 'WARNING':
            print(f"{Colors.WARNING}⚠ WARNING{Colors.RESET}  {section_name}")
        elif status == 'FAIL':
            print(f"{Colors.FAIL}✗ FAIL{Colors.RESET}     {section_name}")
        elif status == 'CRITICAL':
            print(f"{Colors.CRITICAL}✗ CRITICAL{Colors.RESET} {section_name}")
        else:
            print(f"  UNKNOWN  {section_name}")
    
    # Overall verdict
    print(f"\n{'─' * 80}")
    print(f"\n{Colors.BOLD}OVERALL VERDICT:{Colors.RESET}")
    
    critical_count = sum(1 for _, status in sections if status == 'CRITICAL')
    fail_count = sum(1 for _, status in sections if status == 'FAIL')
    warning_count = sum(1 for _, status in sections if status == 'WARNING')
    pass_count = sum(1 for _, status in sections if status == 'PASS')
    
    if critical_count > 0:
        print(f"{Colors.CRITICAL}✗ SYSTEM FAILURE{Colors.RESET} - {critical_count} critical issue(s) found")
        print("   Centroids CANNOT be generated. System will NOT classify data.")
    elif fail_count > 0:
        print(f"{Colors.FAIL}✗ DEGRADED{Colors.RESET} - {fail_count} failure(s) found")
        print("   Centroids may be incomplete. Classification accuracy will be reduced.")
    elif warning_count > 0:
        print(f"{Colors.WARNING}⚠ OPERATIONAL WITH WARNINGS{Colors.RESET} - {warning_count} warning(s) found")
        print("   System is operational but some features may be degraded.")
    else:
        print(f"{Colors.PASS}✓ FULLY OPERATIONAL{Colors.RESET}")
        print("   All systems are functioning correctly.")
    
    # Fix recommendations
    print(f"\n{Colors.BOLD}FIX RECOMMENDATIONS:{Colors.RESET}")
    
    if diagnostic_results['snowflake_connectivity'] == 'CRITICAL':
        print("\n1. Snowflake Connectivity:")
        print("   • Verify governance database is configured in governance_db_resolver.py")
        print("   • Check Snowflake connection credentials")
        print("   • Ensure DATA_CLASSIFICATION_GOVERNANCE schema exists")
    
    if diagnostic_results['categories_validation'] in ['CRITICAL', 'FAIL']:
        print("\n2. Categories:")
        print("   • Populate SENSITIVITY_CATEGORIES table with at least one category")
        print("   • Ensure CATEGORY_NAME is not empty")
        print("   • Ensure DESCRIPTION is not NULL and has meaningful content (50+ chars recommended)")
        print("   • Set IS_ACTIVE = TRUE for categories you want to use")
        print("   • Set DETECTION_THRESHOLD between 0.1 and 1.0 (recommend 0.65)")
    
    if diagnostic_results['keywords_validation'] == 'WARNING':
        print("\n3. Keywords:")
        print("   • Add more keywords to SENSITIVE_KEYWORDS table (10+ per category recommended)")
        print("   • Ensure CATEGORY_ID foreign keys are valid")
        print("   • Set IS_ACTIVE = TRUE for keywords you want to use")
        print("   • Set MATCH_TYPE to 'EXACT', 'PARTIAL', or 'FUZZY'")
    
    if diagnostic_results['patterns_validation'] == 'WARNING':
        print("\n4. Patterns:")
        print("   • Add regex patterns to SENSITIVE_PATTERNS table")
        print("   • Ensure patterns are valid regex syntax")
        print("   • Set IS_ACTIVE = TRUE for patterns you want to use")
    
    if diagnostic_results['embedding_service'] == 'CRITICAL':
        print("\n5. Embedding Service:")
        print("   • Install sentence-transformers: pip install sentence-transformers")
        print("   • Install numpy: pip install numpy")
        print("   • Ensure internet connectivity for model download")
    
    if diagnostic_results['centroid_initialization'] in ['CRITICAL', 'FAIL']:
        print("\n6. Centroid Initialization:")
        print("   • Review logs above for specific centroid failures")
        print("   • Ensure categories have non-empty descriptions")
        print("   • Verify embedding model is loaded successfully")
        print("   • Check for Python exceptions during centroid building")
    
    print(f"\n{'=' * 80}")

def main():
    """Main diagnostic execution"""
    print_header("AI CLASSIFICATION PIPELINE - COMPLETE DIAGNOSTIC")
    print("This diagnostic will validate all components required for centroid generation.")
    print("No data will be classified. No embeddings will be generated for classification.")
    print("Only diagnostic checks will be performed.\n")
    
    all_issues = []
    
    # Run all diagnostic sections
    all_issues.extend(section_1_snowflake_metadata())
    all_issues.extend(section_2_categories_validation())
    all_issues.extend(section_3_keywords_patterns_validation())
    all_issues.extend(section_4_python_object_mapping())
    all_issues.extend(section_5_embedding_service())
    all_issues.extend(section_6_centroid_initialization())
    all_issues.extend(section_7_fallback_logic())
    
    # Final verdict
    final_verdict()
    
    # Summary of all issues
    if all_issues:
        print(f"\n{Colors.BOLD}ALL ISSUES FOUND ({len(all_issues)} total):{Colors.RESET}")
        for idx, issue in enumerate(all_issues, 1):
            print(f"   {idx}. {issue}")
    else:
        print(f"\n{Colors.PASS}{Colors.BOLD}✓ NO ISSUES FOUND - SYSTEM IS FULLY OPERATIONAL{Colors.RESET}")
    
    print(f"\n{'=' * 80}\n")

if __name__ == "__main__":
    main()
