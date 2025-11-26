# Read the file
$content = Get-Content 'data-governance-app\src\services\ai_classification_pipeline_service.py' -Raw -Encoding UTF8

# Replace the thresholds
$content = $content -replace 'confidence >= 0\.50', 'confidence >= 0.80'
$content = $content -replace 'confidence < 0\.50', 'confidence < 0.80'
$content = $content -replace '< 50%', '< 80%'

# Write back
Set-Content 'data-governance-app\src\services\ai_classification_pipeline_service.py' -Value $content -Encoding UTF8 -NoNewline

Write-Host "Successfully updated confidence thresholds from 50% to 80%"
