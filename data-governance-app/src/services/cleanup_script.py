
import sys

file_path = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\services\ai_classification_pipeline_service.py"

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    start_del = 7341
    end_del = 7825
    
    # Validation
    # Indices are 1-based in my thought, 0-based in list.
    # Line 7340 (index 7339) should be '        return None'
    # Line 7341 (index 7340) should start with '            'expiration_date'
    # Line 7825 (index 7824) should be '    ' (empty line or closing brace of return dict?)
    # Line 7826 (index 7825) should start with '    # ========='
    
    print(f"Line {start_del-1}: {lines[start_del-2].rstrip()}")
    print(f"Line {start_del}: {lines[start_del-1].rstrip()}")
    print(f"Line {end_del}: {lines[end_del-1].rstrip()}")
    print(f"Line {end_del+1}: {lines[end_del].rstrip()}")
    
    # Perform separation
    new_content = lines[:start_del-1] + lines[end_del:]
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_content)
        
    print(f"Successfully deleted lines {start_del} to {end_del}. Total lines: {len(new_content)}")

except Exception as e:
    print(f"Error: {e}")
