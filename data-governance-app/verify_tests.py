"""
Quick Test Verification Script
Validates test file syntax and reports test count
"""

import sys
import ast

def verify_test_file():
    """Verify the test file is syntactically correct"""
    
    test_file = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\tests\test_ai_classification_pipeline_service.py"
    
    print("=" * 80)
    print("TEST FILE VERIFICATION")
    print("=" * 80)
    print()
    
    # Check if file exists
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"✓ Test file found: {test_file}")
        print(f"  File size: {len(content)} characters")
    except FileNotFoundError:
        print(f"✗ Test file not found: {test_file}")
        return False
    except Exception as e:
        print(f"✗ Error reading file: {e}")
        return False
    
    # Check syntax
    try:
        tree = ast.parse(content)
        print(f"✓ Syntax is valid")
    except SyntaxError as e:
        print(f"✗ Syntax error at line {e.lineno}: {e.msg}")
        return False
    
    # Count test functions
    test_functions = []
    test_classes = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name.startswith('test_'):
                test_functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith('Test'):
                test_classes.append(node.name)
    
    print(f"✓ Found {len(test_classes)} test classes")
    print(f"✓ Found {len(test_functions)} test functions")
    
    # List test classes
    print()
    print("Test Classes:")
    for cls in test_classes:
        print(f"  - {cls}")
    
    print()
    print("=" * 80)
    print("VERIFICATION COMPLETE")
    print("=" * 80)
    print()
    print("To run the tests, use:")
    print("  python -m pytest tests\\test_ai_classification_pipeline_service.py -v")
    print()
    print("Or use the batch file:")
    print("  run_tests.bat")
    print()
    
    return True

if __name__ == "__main__":
    success = verify_test_file()
    sys.exit(0 if success else 1)
