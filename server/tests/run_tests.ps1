# ==============================================================================
# RUNNER NATIVO WINDOWS POWERSHELL PER TEST AUTOMATIZZATI SERVER NTAG 424 DNA
# Progetto: Ntag424SdmFeature
#
# Esecuzione in PowerShell / PowerShell Core:
#   .\server\tests\run_tests.ps1
#   .\server\tests\run_tests.ps1 -TargetUrl "https://logicarts.altervista.org/verify.php"
# ==============================================================================

[CmdletBinding()]
param (
    [string]$TargetUrl = "https://logicarts.altervista.org/verify.php"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==========================================================================" -ForegroundColor DarkGray
Write-Host "SUITE DI TEST AUTOMATIZZATA SERVER BACKEND (WINDOWS POWERSHELL)" -ForegroundColor Cyan
Write-Host "Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor DarkGray

# Verifica se PHP CLI è disponibile su Windows
$phpPath = Get-Command "php" -ErrorAction SilentlyContinue

if ($null -ne $phpPath) {
    Write-Host "`n[INFO] Rilevato PHP CLI su Windows ($($phpPath.Source)). Avvio del runner PHP..." -ForegroundColor Green
    php "$ScriptDir\run_tests.php" --url="$TargetUrl"
} else {
    Write-Host "`n[INFO] PHP CLI non trovato in PATH. Esecuzione Test HTTP Remoti via PowerShell Invoke-RestMethod..." -ForegroundColor Yellow

    # TEST 1: Parametri Mancanti
    Write-Host "`n[TEST 1] Invocazione senza parametri (Atteso: HTTP 400 missing_params)..." -ForegroundColor Yellow
    try {
        $res1 = Invoke-RestMethod -Uri "$TargetUrl?json=1" -Method Get -Headers @{ "Accept" = "application/json" } -ErrorAction Stop
        Write-Host "[FAIL] Risposta inattesa: $($res1 | ConvertTo-Json -Compress)" -ForegroundColor Red
    } catch {
        $httpRes = $_.Exception.Response
        if ($null -ne $httpRes) {
            $statusCode = [int]$httpRes.StatusCode
            $reader = New-Object System.IO.StreamReader($httpRes.GetResponseStream())
            $body = $reader.ReadToEnd() | ConvertFrom-Json
            if ($statusCode -eq 400 -and $body.outcome -eq "missing_params") {
                Write-Host "[PASS] Test #1 Superato: HTTP 400 missing_params confermato." -ForegroundColor Green
            } else {
                Write-Host "[FAIL] Test #1 Fallito: HTTP $statusCode - Outcome: $($body.outcome)" -ForegroundColor Red
            }
        } else {
            Write-Host "[FAIL] Errore di rete: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # TEST 2: Firma CMAC Errata
    Write-Host "`n[TEST 2] Invocazione con payload corrotto/CMAC errato (Atteso: mac_invalid)..." -ForegroundColor Yellow
    try {
        $res2 = Invoke-RestMethod -Uri "$TargetUrl?picc_data=00112233445566778899aabbccddeeff&cmac=0011223344556677&json=1" -Method Get -Headers @{ "Accept" = "application/json" }
        if ($res2.outcome -eq "mac_invalid" -and $res2.mac_valid -eq $false) {
            Write-Host "[PASS] Test #2 Superato: mac_invalid confermato e mac_valid = false." -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Test #2 Fallito: Outcome = $($res2.outcome)" -ForegroundColor Red
        }
    } catch {
        Write-Host "[FAIL] Errore invocazione: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`n--------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[TIP] Per eseguire la sintesi crittografica dinamica completa dei tag sintetici, installa PHP per Windows." -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------------------" -ForegroundColor Cyan
}

Write-Host "`n==========================================================================" -ForegroundColor DarkGray
Write-Host "ESECUZIONE TEST COMPLETATA." -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkGray
