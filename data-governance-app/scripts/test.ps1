Param(
    [switch]$Unit,
    [switch]$Integration,
    [string]$Markers = ''
)
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$envPath = Join-Path $projectRoot 'env'
$venvPath = Join-Path $projectRoot 'venv'
$dotVenvPath = Join-Path $projectRoot '.venv'

if (Test-Path $envPath) {
    $venv = $envPath
} elseif (Test-Path $venvPath) {
    $venv = $venvPath
} else {
    $venv = $dotVenvPath
}
$scriptsDir = Join-Path $venv 'Scripts'
$pythonExe = Join-Path $scriptsDir 'python.exe'
$pytestExe = Join-Path $scriptsDir 'pytest.exe'

if (-not (Test-Path $pytestExe)) { throw 'pytest is not installed in the venv. Run scripts\setup.ps1 -Dev' }

Push-Location $projectRoot
try {
    $argsList = @()
    if ($Unit) { $argsList += 'tests/unit' }
    elseif ($Integration) { $argsList += 'tests/integration' }
    else { $argsList += 'tests' }

    if ($Markers) { $argsList += @('-m', $Markers) }

    & $pytestExe @argsList
} finally {
    Pop-Location
}
