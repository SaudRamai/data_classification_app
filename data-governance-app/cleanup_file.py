with open('src/pages/2_Data_Assets.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line with the end marker
cutoff = None
for i, line in enumerate(lines):
    if '**This is NOT mock data' in line and i > 2000:
        cutoff = i + 1  # Keep this line
        break

if cutoff:
    print(f'Truncating at line {cutoff}')
    with open('src/pages/2_Data_Assets.py', 'w', encoding='utf-8') as f:
        f.writelines(lines[:cutoff])
    print('Done!')
else:
    print('Marker not found')
