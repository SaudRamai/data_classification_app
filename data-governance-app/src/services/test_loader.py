import logging
import sys
import os

# Add the project root to the path so we can import src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from src.services.governance_rules_loader_v2 import governance_rules_loader
    print("Successfully imported governance_rules_loader_v2")
except ImportError as e:
    print(f"Failed to import governance_rules_loader_v2: {e}")
    sys.exit(1)

def test_loader():
    print("\nTesting load_category_metadata()...")
    meta = governance_rules_loader.load_category_metadata(force_refresh=True)
    print(f"Loaded {len(meta)} categories")
    if meta:
        print(f"Sample category: {list(meta.keys())[0]}")
    
    print("\nTesting load_classification_rules()...")
    rules = governance_rules_loader.load_classification_rules(force_refresh=True)
    print(f"Loaded {len(rules)} rules")
    if rules:
        print(f"Sample rule: {rules[0]}")

    print("\nTesting load_context_aware_rules()...")
    context_rules = governance_rules_loader.load_context_aware_rules(force_refresh=True)
    print(f"Loaded {len(context_rules)} context rule types")

if __name__ == "__main__":
    test_loader()
