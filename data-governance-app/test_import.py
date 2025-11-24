import sys
import os

# Add the project root to the Python path
_here = os.path.abspath(__file__)
_project_root = os.path.dirname(_here)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

print("Testing import of ai_sensitive_detection_service...")

try:
    from src.services.ai_sensitive_detection_service import AISensitiveDetectionService
    print("✓ Class import successful")
except Exception as e:
    print(f"✗ Class import failed: {e}")
    import traceback
    traceback.print_exc()

try:
    from src.services.ai_sensitive_detection_service import ai_sensitive_detection_service
    print("✓ Singleton import successful")
    print(f"  Type: {type(ai_sensitive_detection_service)}")
except Exception as e:
    print(f"✗ Singleton import failed: {e}")
    import traceback
    traceback.print_exc()
