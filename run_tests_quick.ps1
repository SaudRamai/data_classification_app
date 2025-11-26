# Quick Test Runner - Ensures you're in the right directory

Write-Host "Navigating to data-governance-app directory..." -ForegroundColor Cyan
Set-Location "c:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app"

Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
Write-Host ""

Write-Host "Running tests..." -ForegroundColor Green
python -m pytest tests\test_ai_classification_pipeline_service.py -v --tb=short

Write-Host ""
Write-Host "Test run complete!" -ForegroundColor Cyan
