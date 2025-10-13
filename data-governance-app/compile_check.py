import ast, sys
from pathlib import Path

p = Path(r"c:\\Users\\ramai.saud\\Downloads\\DATA_CLASSIFICATION_APP\\data-governance-app\\src\\pages\\2_Data_Assets.py")
try:
    src = p.read_text(encoding='utf-8')
except Exception as e:
    print("READ_FAIL", e)
    sys.exit(1)

try:
    ast.parse(src, filename=str(p), mode='exec')
    print("OK: no SyntaxError")
except SyntaxError as e:
    print("SyntaxError at line", e.lineno, "col", e.offset)
    print("Msg:", e.msg)
    line = src.splitlines()[e.lineno-1] if e.lineno else ''
    print("Line:", line)
    # print some context
    start = max(0, (e.lineno or 1)-3)
    end = min(len(src.splitlines()), (e.lineno or 1)+3)
    for i in range(start, end):
        print(f"{i+1:5d}:", src.splitlines()[i])
    sys.exit(2)
except Exception as e:
    print("OTHER_FAIL", type(e).__name__, e)
    sys.exit(3)
