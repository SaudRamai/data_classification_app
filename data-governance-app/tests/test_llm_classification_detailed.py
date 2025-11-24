import sys
import os
import json
import logging
from typing import List, Dict, Set

# Add the project root to the python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.services.llm_classification_service import llm_classification_service

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_detailed_llm_test():
    print("="*80)
    print("STARTING DETAILED LLM CLASSIFICATION TEST")
    print("="*80)

    # 1. Check Connection
    print("\n[1] Checking LLM Connection...")
    if llm_classification_service.check_connection():
        print(f"✅ Connection Successful! Using model: {llm_classification_service.model}")
    else:
        print(f"❌ Connection Failed. Is Ollama running at {llm_classification_service.base_url}?")
        return

    # 2. Define Test Scenarios
    # Based on the "Core Classification Principles" provided in the system prompt
    test_cases = [
        {
            "name": "E-Commerce Orders (Mixed PII, SOC2, SOX)",
            "table": "orders",
            "columns": [
                {"name": "order_id", "data_type": "VARCHAR", "comment": "Primary key"},
                {"name": "customer_email", "data_type": "VARCHAR", "comment": "Customer contact"},
                {"name": "billing_address", "data_type": "VARCHAR", "comment": "Billing address for tax"},
                {"name": "order_total", "data_type": "DECIMAL", "comment": "Final amount charged"},
                {"name": "credit_card_hash", "data_type": "VARCHAR", "comment": "Payment token"}
            ],
            "expected_tags": {
                "customer_email": {"PII", "SOC2"},
                "billing_address": {"PII", "SOC2", "SOX"}, # Address is PII, Customer Data (SOC2), Tax/Revenue (SOX)
                "order_total": {"SOC2", "SOX"},            # Customer Transaction (SOC2), Revenue (SOX)
                "credit_card_hash": {"PII", "SOC2", "SOX"} # Financial Account (PII), Customer Data (SOC2), Payment Record (SOX)
            }
        },
        {
            "name": "Employee Payroll (Sensitive PII + SOX)",
            "table": "payroll_data",
            "columns": [
                {"name": "employee_ssn", "data_type": "VARCHAR", "comment": "Social Security Number"},
                {"name": "salary_amount", "data_type": "DECIMAL", "comment": "Yearly gross salary"},
                {"name": "bank_account_number", "data_type": "VARCHAR", "comment": "Direct deposit account"}
            ],
            "expected_tags": {
                "employee_ssn": {"PII"}, # Sensitive PII
                "salary_amount": {"PII", "SOX"}, # Personal Financial (PII) + Expense (SOX)
                "bank_account_number": {"PII", "SOX"} # Sensitive PII + Payment Info (SOX)
            }
        },
        {
            "name": "System Access Logs (SOC2 Focus)",
            "table": "access_audit_logs",
            "columns": [
                {"name": "log_id", "data_type": "UUID", "comment": "Unique log identifier"},
                {"name": "user_id", "data_type": "VARCHAR", "comment": "User performing action"},
                {"name": "action_timestamp", "data_type": "TIMESTAMP", "comment": "Time of event"},
                {"name": "ip_address", "data_type": "VARCHAR", "comment": "Source IP"}
            ],
            "expected_tags": {
                "user_id": {"SOC2"}, # User identifier in system context
                "action_timestamp": {"SOC2"}, # Audit trail
                "ip_address": {"PII", "SOC2"} # Digital Identifier (PII) + Security Log (SOC2)
            }
        }
    ]

    # 3. Run Tests
    print("\n[2] Running Classification Scenarios...")
    
    total_columns = 0
    passed_columns = 0
    
    for case in test_cases:
        print(f"\n🔹 Testing Scenario: {case['name']}")
        print(f"   Table: {case['table']}")
        
        # Call the LLM Service
        result = llm_classification_service.classify_table(case['table'], case['columns'])
        
        if "error" in result:
            print(f"   ❌ Error: {result['error']}")
            continue
            
        # Analyze Results
        classified_cols = result.get("columns", [])
        # Analyze Results
        classified_cols = result.get("columns", [])
        # Handle both 'col_name' (new) and 'column_name' (old/fallback)
        col_map = {}
        for c in classified_cols:
            name = c.get('col_name', c.get('column_name'))
            if name:
                col_map[name] = set(c.get('classifications', []))
        
        for col_def in case['columns']:
            col_name = col_def['name']
            total_columns += 1
            
            actual_tags = col_map.get(col_name, set())
            expected_tags = case['expected_tags'].get(col_name, set())
            
            # We check if expected tags are a SUBSET of actual tags (LLM might find more valid ones)
            # Or strict equality? Let's aim for high overlap.
            
            missing_tags = expected_tags - actual_tags
            unexpected_tags = actual_tags - expected_tags
            
            # Simple scoring: Pass if all expected tags are present
            is_pass = len(missing_tags) == 0
            
            status_icon = "✅" if is_pass else "⚠️"
            if not is_pass and len(actual_tags) == 0: status_icon = "❌"
            
            print(f"   {status_icon} Column: {col_name:<20}")
            print(f"      Expected: {sorted(list(expected_tags))}")
            print(f"      Actual:   {sorted(list(actual_tags))}")
            
            if missing_tags:
                print(f"      MISSING:  {list(missing_tags)}")
            
            if is_pass:
                passed_columns += 1

    # 4. Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    score = (passed_columns / total_columns) * 100 if total_columns > 0 else 0
    print(f"Total Columns Tested: {total_columns}")
    print(f"Columns Passing Criteria: {passed_columns}")
    print(f"Accuracy Score: {score:.1f}%")
    
    if score == 100:
        print("\n🌟 EXCELLENT! The LLM is perfectly following your classification rules.")
    elif score >= 80:
        print("\n✅ GOOD. The LLM is mostly correct but missed a few nuances.")
    else:
        print("\n⚠️ NEEDS IMPROVEMENT. Check the prompt or model capabilities.")

if __name__ == "__main__":
    run_detailed_llm_test()
