"""
Diagnostic script to identify where the 'str' object has no attribute 'get' error occurs
"""
import re
import sys

def find_pattern_get_calls(filename):
    """Find all lines where .get() might be called on pattern objects"""
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    issues = []
    for i, line in enumerate(lines, 1):
        # Look for pattern-related .get() calls
        if 'pattern' in line.lower() and '.get(' in line:
            # Skip comments
            if line.strip().startswith('#'):
                continue
            # Skip docstrings
            if '"""' in line or "'''" in line:
                continue
            
            issues.append({
                'line_number': i,
                'line': line.strip(),
                'context': 'Pattern .get() call found'
            })
        
        # Look for iterations over _category_patterns where dict access might happen
        if '_category_patterns' in line and 'for' in line:
            # Check next few lines for .get() calls
            for j in range(i, min(i+10, len(lines))):
                next_line = lines[j]
                if '.get(' in next_line and 'pattern' in next_line.lower():
                    issues.append({
                        'line_number': j+1,
                        'line': next_line.strip(),
                        'context': f'Possible dict access on string pattern (iteration starts at line {i})'
                    })
    
    return issues

if __name__ == '__main__':
    filename = r'c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\services\ai_classification_pipeline_service.py'
    
    print("=" * 80)
    print("PATTERN ERROR DIAGNOSTIC")
    print("=" * 80)
    print(f"\nScanning: {filename}\n")
    
    issues = find_pattern_get_calls(filename)
    
    if issues:
        print(f"Found {len(issues)} potential issues:\n")
        for issue in issues:
            print(f"Line {issue['line_number']}: {issue['context']}")
            print(f"  Code: {issue['line']}")
            print()
    else:
        print("No obvious pattern .get() calls found.")
        print("\nThe error might be in:")
        print("1. Snowflake query results being returned as strings instead of dicts")
        print("2. Pattern metadata not being properly initialized")
        print("3. Code expecting _category_pattern_metadata but using _category_patterns")
    
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS:")
    print("=" * 80)
    print("1. Check if Snowflake connector is returning dict rows or string rows")
    print("2. Add type checking before accessing pattern attributes")
    print("3. Use _category_pattern_metadata (dicts) instead of _category_patterns (strings)")
    print("4. Add defensive coding with isinstance() checks")
