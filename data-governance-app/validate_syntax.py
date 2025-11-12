import ast
import sys

# Get file path from command line argument or use default
if len(sys.argv) > 1:
    file_path = sys.argv[1]
else:
    file_path = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\3_Classification.py"

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    ast.parse(code)
    print("✅ No syntax errors found!")
    sys.exit(0)
except SyntaxError as e:
    print(f"❌ Syntax Error found:")
    print(f"  Line {e.lineno}: {e.msg}")
    print(f"  Text: {e.text}")
    print(f"  Offset: {' ' * (e.offset - 1) if e.offset else ''}^")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
