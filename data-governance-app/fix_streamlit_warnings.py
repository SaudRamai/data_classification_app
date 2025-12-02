import os

files_to_fix = [
    r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\4_Compliance.py",
    r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\ui\reclassification_requests.py",
    r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\ui\classification_history_tab.py",
    r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\6_Data_Intelligence.py",
    r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\3_Classification.py"
]

for file_path in files_to_fix:
    if not os.path.exists(file_path):
        print(f"Skipping {file_path} (not found)")
        continue
        
    print(f"Processing {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        new_lines = []
        changed = False
        for line in content.splitlines():
            # Check for st.dataframe and use_container_width=True
            if "st.dataframe" in line and "use_container_width=True" in line:
                new_line = line.replace("use_container_width=True", "width='stretch'")
                new_lines.append(new_line)
                changed = True
            # Check for st.data_editor and use_container_width=True
            elif "st.data_editor" in line and "use_container_width=True" in line:
                new_line = line.replace("use_container_width=True", "width='stretch'")
                new_lines.append(new_line)
                changed = True
            # Check for use_container_width=False
            elif "st.dataframe" in line and "use_container_width=False" in line:
                new_line = line.replace("use_container_width=False", "width='content'")
                new_lines.append(new_line)
                changed = True
            elif "st.data_editor" in line and "use_container_width=False" in line:
                new_line = line.replace("use_container_width=False", "width='content'")
                new_lines.append(new_line)
                changed = True
            else:
                new_lines.append(line)
                
        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_lines))
            print(f"Updated {file_path}")
        else:
            print(f"No changes needed for {file_path}")
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
