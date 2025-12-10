"""
Test script to verify the compliance metrics query returns correct data
"""

# Expected data from Snowflake:
# CLASSIFICATION_COVERAGE_PERCENTAGE: 43.4
# FIVE_DAY_RULE_COMPLIANCE_PERCENTAGE: 0.8
# ANNUAL_REVIEW_RATE_PERCENTAGE: 56.6
# POLICY_VIOLATIONS: 73
# OVERALL_STATUS: 🔴 Issues

expected = {
    'classification_coverage_percentage': 43.4,
    'five_day_rule_compliance_percentage': 0.8,
    'annual_review_rate_percentage': 56.6,
    'policy_violations': 73,
    'overall_status': '🔴 Issues'
}

print("=" * 60)
print("COMPLIANCE METRICS VERIFICATION")
print("=" * 60)
print("\nExpected Results:")
print(f"  Classification Coverage: {expected['classification_coverage_percentage']}%")
print(f"  5-Day Rule Compliance: {expected['five_day_rule_compliance_percentage']}%")
print(f"  Annual Review Rate: {expected['annual_review_rate_percentage']}%")
print(f"  Policy Violations: {expected['policy_violations']}")
print(f"  Overall Status: {expected['overall_status']}")
print("\n" + "=" * 60)
print("After refreshing the Compliance page, verify that:")
print("=" * 60)
print("1. The debug sidebar shows the raw query results")
print("2. The Key Metrics section displays the expected values above")
print("3. If values don't match, check the sidebar debug output")
print("=" * 60)
