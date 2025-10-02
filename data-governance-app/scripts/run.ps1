Param(
    [string]$App = 'src/app.py',
    [int]$Port = 8501
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

if (-not (Test-Path $pythonExe)) {
    throw "Virtual environment not found. Run scripts/setup.ps1 first."
}

$streamlitExe = Join-Path $scriptsDir 'streamlit.exe'
if (-not (Test-Path $streamlitExe)) { throw 'streamlit is not installed in the venv.' }

Push-Location $projectRoot
try {
    # Streamlit picks up env vars; app.py loads .env from project root too
    & $streamlitExe run $App --server.port $Port
} finally {
    Pop-Location
}
