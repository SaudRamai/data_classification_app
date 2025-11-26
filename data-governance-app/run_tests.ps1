# Test Runner Script for AI Classification Pipeline Service

# Install test dependencies
Write-Host "Installing test dependencies..." -ForegroundColor Cyan
pip install -r tests/requirements-test.txt

Write-Host "`n" -NoNewline
Write-Host "="*80 -ForegroundColor Green
Write-Host "Running AI Classification Pipeline Tests" -ForegroundColor Green
Write-Host "="*80 -ForegroundColor Green
Write-Host "`n" -NoNewline

# Change to project directory
$projectDir = "C:\Users\ramai.saud\Downloads\DATA_CLASSIFICATION_APP\data-governance-app"
Set-Location $projectDir

# Run tests with coverage
Write-Host "Running test suite..." -ForegroundColor Yellow
pytest tests/test_ai_classification_pipeline_service.py `
    -v `
    --tb=short `
    --cov=src.services.ai_classification_pipeline_service `
    --cov-report=html `
    --cov-report=term-missing `
    --color=yes

Write-Host "`n" -NoNewline

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host "="*80 -ForegroundColor Green
    Write-Host "✓ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "="*80 -ForegroundColor Green
    Write-Host "`n" -NoNewline
    Write-Host "Coverage report generated at: htmlcov/index.html" -ForegroundColor Cyan
    Write-Host "Open it in a browser to see detailed coverage." -ForegroundColor Cyan
}
else {
    Write-Host "="*80 -ForegroundColor Red
    Write-Host "✗ SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "="*80 -ForegroundColor Red
    Write-Host "`n" -NoNewline
    Write-Host "Review the output above for details." -ForegroundColor Yellow
}

Write-Host "`n" -NoNewline
Write-Host "Test run complete." -ForegroundColor Cyan
