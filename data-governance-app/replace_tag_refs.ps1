$ErrorActionPreference = 'Stop'
$path = 'C:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\1_Dashboard.py'
$text = Get-Content -Raw -Encoding UTF8 -Path $path
# Replace any occurrences of {db}.INFORMATION_SCHEMA.TAG_REFERENCES (case-insensitive)
$new = $text -replace '(?i)\{db\}\.information_schema\.tag_references', '"SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"'
$new = $new -replace '(?i)\{db\}\.INFORMATION_SCHEMA\.TAG_REFERENCES', '"SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"'
# Also replace occurrences without {db} prefix that might still refer to INFORMATION_SCHEMA.TAG_REFERENCES
$new = $new -replace '(?i)INFORMATION_SCHEMA\.TAG_REFERENCES', '"SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"'
if ($new -ne $text) {
    Set-Content -Path $path -Value $new -Encoding UTF8
    Write-Host 'Replaced INFORMATION_SCHEMA.TAG_REFERENCES with SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES.'
} else {
    Write-Host 'No replacements performed.'
}
