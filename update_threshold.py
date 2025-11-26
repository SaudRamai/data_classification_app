import sys

# Read the file
with open('data-governance-app/src/services/ai_classification_pipeline_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the thresholds
content = content.replace('confidence >= 0.50', 'confidence >= 0.80')
content = content.replace('confidence < 0.50', 'confidence < 0.80')
content = content.replace('< 50%', '< 80%')

# Write back
with open('data-governance-app/src/services/ai_classification_pipeline_service.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Successfully updated confidence thresholds from 50% to 80%")
