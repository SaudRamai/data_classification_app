@echo off
echo ================================================================================
echo Running AI Classification Pipeline Tests
echo ================================================================================
echo.

REM Find Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Python not found in PATH
    echo.
    echo Please install pytest first:
    echo   pip install pytest pytest-cov pytest-mock numpy
    echo.
    echo Then run this script again.
    pause
    exit /b 1
)

REM Install dependencies if needed
echo Checking test dependencies...
python -m pip install --quiet pytest pytest-mock numpy 2>nul
if %errorlevel% neq 0 (
    echo Warning: Could not install dependencies. Tests may fail.
    echo.
)

echo.
echo Running test suite...
echo.

REM Run pytest
python -m pytest tests\test_ai_classification_pipeline_service.py -v --tb=short --color=yes

if %errorlevel% equ 0 (
    echo.
    echo ================================================================================
    echo ALL TESTS PASSED!
    echo ================================================================================
) else (
    echo.
    echo ================================================================================
    echo SOME TESTS FAILED - See output above
    echo ================================================================================
)

echo.
pause
