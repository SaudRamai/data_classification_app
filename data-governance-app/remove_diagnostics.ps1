$ErrorActionPreference = 'Stop'
$path = 'C:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app\src\pages\1_Dashboard.py'
$lines = Get-Content -Path $path -Encoding UTF8
$start = ($lines | Select-String -SimpleMatch 'with st.expander("Diagnostics", expanded=False):' | Select-Object -First 1).LineNumber
if (-not $start) {
    Write-Host 'Diagnostics start not found.'
    exit 1
}
$end = $null
for ($i = $start; $i -le $lines.Length; $i++) {
    if ($lines[$i-1] -match '^\s*@st\.cache_data\(ttl=1800\)') {
        $end = $i
        break
    }
}
if (-not $end) {
    Write-Host 'Diagnostics end marker not found.'
    exit 1
}
$head = @()
if ($start -gt 1) {
    $head = $lines[0..($start-2)]
}
$tail = $lines[($end-1)..($lines.Length-1)]
$new = $head + $tail
Set-Content -Path $path -Value $new -Encoding UTF8
Write-Host "Diagnostics block removed from lines $start to $end."