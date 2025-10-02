$ErrorActionPreference = 'Stop'
$path = 'C:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\services\policy_enforcement_service.py'
$text = Get-Content -Raw -Encoding UTF8 -Path $path
# Replace any occurrences of INFORMATION_SCHEMA.TAG_REFERENCES with ACCOUNT_USAGE.TAG_REFERENCES
$new = $text -replace '(?i)INFORMATION_SCHEMA\.TAG_REFERENCES', '"SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"'
if ($new -ne $text) {
    Set-Content -Path $path -Value $new -Encoding UTF8
    Write-Host 'Replaced INFORMATION_SCHEMA.TAG_REFERENCES with SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES in policy_enforcement_service.py.'
} else {
    Write-Host 'No replacements performed in policy_enforcement_service.py.'
}
