$p = "c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\services\ai_classification_pipeline_service.py"
$c = Get-Content $p -Encoding UTF8
Write-Host "Total lines: $($c.Count)"
Write-Host "Line 7340: $($c[7339])"
Write-Host "Line 7341: $($c[7340])"
Write-Host "Line 7825: $($c[7824])"
Write-Host "Line 7826: $($c[7825])"

$n = $c[0..7339] + $c[7825..($c.Count - 1)]
$n | Set-Content $p -Encoding UTF8
Write-Host "Cleaned file. New count: $($n.Count)"
