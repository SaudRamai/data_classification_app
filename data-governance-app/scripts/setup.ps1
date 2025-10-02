Param(
    [switch]$Dev
)
$ErrorActionPreference = 'Stop'

# Determine venv path: prefer existing 'env', else create '.venv'
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
$pipExe = Join-Path $scriptsDir 'pip.exe'

# Initialize venv if not present
if (-not (Test-Path $pythonExe)) {
    if (-not (Test-Path $venv)) {
        New-Item -ItemType Directory -Force -Path $venv | Out-Null
    }
    Write-Host "Initializing virtual environment at $venv ..."
    python -m venv $venv
    $scriptsDir = Join-Path $venv 'Scripts'
    $pythonExe = Join-Path $scriptsDir 'python.exe'
    $pipExe = Join-Path $scriptsDir 'pip.exe'
}

if (-not (Test-Path $pythonExe)) {
    throw "Python executable not found in venv at $pythonExe"
}

Write-Host 'Upgrading pip...'
& $pythonExe -m pip install --upgrade pip

Write-Host 'Installing requirements.txt ...'
& $pipExe install -r (Join-Path $projectRoot 'requirements.txt')

if ($Dev) {
    Write-Host 'Installing requirements-dev.txt ...'
    $devReq = Join-Path $projectRoot 'requirements-dev.txt'
    if (Test-Path $devReq) { & $pipExe install -r $devReq } else { Write-Warning 'requirements-dev.txt not found' }
}

Write-Host 'Setup complete.'
