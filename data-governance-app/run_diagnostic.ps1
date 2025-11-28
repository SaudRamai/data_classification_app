
# Test Runner Script for Diagnostic
Write-Host "Finding pytest executable..."
$loc = pip show pytest | Select-String "Location:"
if ($loc) {
    $path = $loc.ToString().Split(": ")[1].Trim()
    # Path is ...\site-packages
    # Scripts is usually parallel to site-packages or in a Scripts folder at the same level as Lib
    # For Windows Store python local packages:
    # ...\LocalCache\local-packages\Python311\site-packages
    # Scripts -> ...\LocalCache\local-packages\Python311\Scripts
    
    $root = Split-Path $path # ...\LocalCache\local-packages\Python311
    $scripts = "$root\Scripts"
    $pytestExe = "$scripts\pytest.exe"
    
    Write-Host "Checking for pytest at $pytestExe"
    
    if (Test-Path $pytestExe) {
        Write-Host "Found pytest!"
        & $pytestExe test_diagnostic.py -s -v
    }
    else {
        Write-Host "pytest.exe not found at $pytestExe"
        # Try listing the root to see structure
        Get-ChildItem $root
    }
}
