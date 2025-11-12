import re

file_path = r"c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\3_Classification.py"

# Read the file content
with open(file_path, 'r', encoding='utf-8') as file:
    content = file.read()

# Define the pattern to find and the replacement
pattern = r'from \.\.services\.global_filters import get_global_filters\s+gf = get_global_filters\(\)'
replacement = '''try:
                            from src.services.global_filters import get_global_filters
                            gf = get_global_filters()
                        except ImportError:
                            gf = {}'''

# Replace the pattern with the new content
new_content = re.sub(pattern, replacement, content)

# Write the updated content back to the file
with open(file_path, 'w', encoding='utf-8') as file:
    file.write(new_content)

print("Import statement has been updated successfully.")
