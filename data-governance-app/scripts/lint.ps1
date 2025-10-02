$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$venv = if (Test-Path (Join-Path $projectRoot 'env')) { Join-Path $projectRoot 'env' } else { Join-Path $projectRoot '.venv' }
$blackExe = Join-Path $venv 'Scripts' 'black.exe'
$flake8Exe = Join-Path $venv 'Scripts' 'flake8.exe'
$mypyExe = Join-Path $venv 'Scripts' 'mypy.exe'

if (-not (Test-Path $blackExe)) { throw 'black is not installed. Run scripts\setup.ps1 -Dev' }
if (-not (Test-Path $flake8Exe)) { throw 'flake8 is not installed. Run scripts\setup.ps1 -Dev' }
if (-not (Test-Path $mypyExe)) { throw 'mypy is not installed. Run scripts\setup.ps1 -Dev' }

Push-Location $projectRoot
try {
    & $blackExe .
    & $flake8Exe .
    & $mypyExe .
} finally {
    Pop-Location
}
