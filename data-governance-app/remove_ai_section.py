with open('src/pages/2_Data_Assets.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the start and end of the AI Actions section
start_idx = None
end_idx = None

for i, line in enumerate(lines):
    if '# --- AI Actions: In-database' in line:
        start_idx = i
    if start_idx is not None and '# Helpers to enrich page-level SLA' in line:
        end_idx = i
        break

if start_idx is not None and end_idx is not None:
    print(f'Removing lines {start_idx+1} to {end_idx}')
    # Keep everything before start and from end onwards
    new_lines = lines[:start_idx] + lines[end_idx:]
    
    with open('src/pages/2_Data_Assets.py', 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print('AI Actions section removed successfully!')
else:
    print(f'Could not find section boundaries. start={start_idx}, end={end_idx}')
