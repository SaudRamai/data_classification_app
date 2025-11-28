
# Fix Runner Script
Write-Host "Finding pytest executable..."
$loc = pip show pytest | Select-String "Location:"
if ($loc) {
    $path = $loc.ToString().Split(": ")[1].Trim()
    $root = Split-Path $path
    $scripts = "$root\Scripts"
    $pytestExe = "$scripts\pytest.exe"
    
    Write-Host "Checking for pytest at $pytestExe"
    
    if (Test-Path $pytestExe) {
        Write-Host "Found pytest! Running fix..."
        & $pytestExe tests/test_fix_governance.py -s -v
    }
    else {
        Write-Host "pytest.exe not found at $pytestExe"
        # Try finding it in the same dir as pip if pip is in path
        $pipPath = Get-Command pip | Select-Object -ExpandProperty Source
        if ($pipPath) {
            $pipDir = Split-Path $pipPath
            $pytestExe2 = "$pipDir\pytest.exe"
            if (Test-Path $pytestExe2) {
                Write-Host "Found pytest at $pytestExe2"
                & $pytestExe2 tests/test_fix_governance.py -s -v
            }
            else {
                Write-Host "Could not find pytest.exe"
            }
        }
    }
}
else {
    Write-Host "Could not find pytest via pip"
}
