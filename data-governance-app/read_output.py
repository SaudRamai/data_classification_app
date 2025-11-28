
try:
    with open('diagnostic_output.txt', 'r', encoding='utf-16') as f:
        print(f.read())
except Exception:
    try:
        with open('diagnostic_output.txt', 'r', encoding='utf-8') as f:
            print(f.read())
    except Exception as e:
        print(f"Error reading file: {e}")
