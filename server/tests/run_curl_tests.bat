@echo off
REM ==============================================================================
REM BATCH RUNNER PER TEST AUTOMATIZZATI SERVER NTAG 424 DNA (PURE CURL WINDOWS)
REM Progetto: Ntag424SdmFeature
REM Usage: .\server\tests\run_curl_tests.bat [TARGET_URL]
REM ==============================================================================

SET TARGET_URL=%~1
IF "%TARGET_URL%"=="" SET TARGET_URL=https://logicarts.altervista.org/verify.php

echo ==========================================================================
echo ESECUZIONE TEST SUITE AUTOMATIZZATA SERVER NTAG 424 DNA (WINDOWS CURL)
echo Target URL: %TARGET_URL%
echo ==========================================================================
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0run_curl_tests.ps1" -TargetUrl "%TARGET_URL%"

echo.
pause
