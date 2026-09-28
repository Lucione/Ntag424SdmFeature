@echo off
REM ==============================================================================
REM BATCH RUNNER PER TEST AUTOMATIZZATI SERVER NTAG 424 DNA SU WINDOWS
# Progetto: Ntag424SdmFeature
REM Usage: .\server\tests\run_tests.bat [TARGET_URL]
REM ==============================================================================

SET TARGET_URL=%~1
IF "%TARGET_URL%"=="" SET TARGET_URL=https://logicarts.altervista.org/verify.php

echo ==========================================================================
echo ESECUZIONE TEST SUITE SERVER NTAG 424 DNA SU WINDOWS
echo Target URL: %TARGET_URL%
echo ==========================================================================

php "%~dp0run_tests.php" --url="%TARGET_URL%"

IF ERRORLEVEL 1 (
    echo.
    echo [INFO] Rilevato problema durante l'esecuzione PHP CLI. Avvio di PowerShell...
    powershell -ExecutionPolicy Bypass -File "%~dp0run_tests.ps1" -TargetUrl "%TARGET_URL%"
)

echo.
pause
