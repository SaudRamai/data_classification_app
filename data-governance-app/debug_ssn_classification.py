"""
Debug script to test SOCIAL_SECURITY_NUMBER classification
This script simulates the classification logic to identify where SOC2 is coming from
"""

import re

# Simulate the column name
col_name = "SOCIAL_SECURITY_NUMBER"
col_lower = col_name.lower()

print(f"Testing column: {col_name}")
print(f"Lowercase: {col_lower}")
print("=" * 80)

# Test PII keywords
pii_boost_keywords = {
    'ssn', 'social_security', 'social_security_number',
    'tax_id', 'tax_ident', 'tax_identification', 'ein', 'itin',
    'passport', 'passport_number',
}

# Test SOC2 keywords
soc2_boost_keywords = {
    'password', 'passwd', 'pwd', 'password_hash', 'user_password',
    'secret', 'private_key', 'trade_secret', 'trade_secret_key',
    'api_key', 'api_secret', 'api_token', 'access_token',
    'oauth', 'oauth_token', 'bearer_token', 'refresh_token',
    'security_question', 'security_answer',
    'confidential_agreement', 'nda',
    'ip_address', 'login_device', 'device_id'
}

print("\n1. Testing PII Keywords:")
print("-" * 80)
pii_sorted = sorted(pii_boost_keywords, key=len, reverse=True)
for kw in pii_sorted:
    if re.search(r'\b' + re.escape(kw) + r'\b', col_lower):
        print(f"  ✅ MATCH: '{kw}' (length={len(kw)})")
        break
    elif kw in col_lower and len(kw) > 5:
        print(f"  ✅ SUBSTRING MATCH: '{kw}' (length={len(kw)})")
        break
else:
    print("  ❌ No PII keyword match")

print("\n2. Testing SOC2 Keywords:")
print("-" * 80)
soc2_sorted = sorted(soc2_boost_keywords, key=len, reverse=True)
for kw in soc2_sorted:
    if re.search(r'\b' + re.escape(kw) + r'\b', col_lower):
        print(f"  ⚠️ MATCH: '{kw}' (length={len(kw)}) - THIS IS THE PROBLEM!")
        break
    elif kw in col_lower and len(kw) > 5:
        print(f"  ⚠️ SUBSTRING MATCH: '{kw}' (length={len(kw)}) - THIS IS THE PROBLEM!")
        break
else:
    print("  ✅ No SOC2 keyword match (correct)")

print("\n3. Word Boundary Test for 'security':")
print("-" * 80)
test_kw = 'security'
if re.search(r'\b' + re.escape(test_kw) + r'\b', col_lower):
    print(f"  ⚠️ '{test_kw}' MATCHES with word boundary in '{col_name}'")
    print(f"  This is because 'security' is a separate word in 'social_security_number'")
else:
    print(f"  ✅ '{test_kw}' does NOT match with word boundary")

print("\n4. Testing if 'security' is in SOC2 keywords:")
print("-" * 80)
if 'security' in soc2_boost_keywords:
    print("  ⚠️ 'security' IS in soc2_boost_keywords - THIS IS THE PROBLEM!")
    print("  Solution: Remove 'security' from soc2_boost_keywords or use more specific terms")
else:
    print("  ✅ 'security' is NOT in soc2_boost_keywords")

print("\n" + "=" * 80)
print("CONCLUSION:")
print("=" * 80)
print("If 'security' is in soc2_boost_keywords, it will match 'social_security_number'")
print("because word boundary regex treats 'security' as a separate word.")
print("\nSOLUTION: Remove generic 'security' from soc2_boost_keywords")
print("or ensure longer, more specific keywords are checked first (which we now do).")
