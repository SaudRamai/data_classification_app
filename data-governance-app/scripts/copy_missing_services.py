import os
import shutil
from pathlib import Path

# Define paths
project_root = Path(__file__).parent.parent
backup_dir = project_root / "src" / "services_backup_20251029_142109"
target_dir = project_root / "src" / "services"

# Ensure target directory exists
target_dir.mkdir(parents=True, exist_ok=True)

# Get list of files in both directories
backup_files = set(f.name for f in backup_dir.glob("*.py") if f.is_file())
target_files = set(f.name for f in target_dir.glob("*.py") if f.is_file())

# Find files that are in backup but not in target
missing_files = backup_files - target_files

if not missing_files:
    print("No missing service files found. All files are up to date.")
else:
    print(f"Found {len(missing_files)} missing service files. Copying...")
    
    for filename in sorted(missing_files):
        src = backup_dir / filename
        dst = target_dir / filename
        
        print(f"Copying {filename}...")
        shutil.copy2(src, dst)
    
    print("\nAll missing service files have been copied successfully!")
    print(f"Copied {len(missing_files)} files to {target_dir}")
