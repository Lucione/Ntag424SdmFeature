# ==============================================================================
# SUITE DI TEST AUTOMATIZZATA IN POWERSHELL / CURL PER WINDOWS
# Progetto: Ntag424SdmFeature
#
# Esecuzione da PowerShell:
#   .\server\tests\run_curl_tests.ps1
#   .\server\tests\run_curl_tests.ps1 -TargetUrl "https://logicarts.altervista.org/verify.php"
# ==============================================================================

[CmdletBinding()]
param (
    [string]$TargetUrl = "https://logicarts.altervista.org/verify.php"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir "test_results.log"

"=== INIZIO SUITE DI TEST POWERSHELL/CURL SERVER NTAG 424 DNA [" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] ===" | Out-File -FilePath $LogFile -Encoding utf8

function Log-Test {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    $Message | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Host $Message -ForegroundColor $Color
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "SUITE DI TEST AUTOMATIZZATA SERVER BACKEND (WINDOWS POWERSHELL / CURL)" -ForegroundColor Yellow
Write-Host "Target URL: $TargetUrl" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

$totalTests = 0
$passedTests = 0

function Assert-Test {
    param (
        [string]$TestName,
        [bool]$Condition,
        [string]$Details = ""
    )
    $script:totalTests++
    if ($Condition) {
        $script:passedTests++
        Log-Test "[PASS] Test #$($script:totalTests): $TestName" -Color Green
    } else {
        Log-Test "[FAIL] Test #$($script:totalTests): $TestName" -Color Red
        if ($Details -ne "") {
            Log-Test "       Diagnostica: $Details" -Color Red
        }
    }
}

# TEST 1: Parametri Mancanti
Log-Test "`n[TEST] 1. Invocazione senza parametri (Atteso: HTTP 400 missing_params)..." -Color Yellow
try {
    $res1 = Invoke-RestMethod -Uri "$TargetUrl?json=1" -Method Get -Headers @{ "Accept" = "application/json" } -ErrorAction Stop
    Assert-Test "Parametri mancanti restituiscono errore 400" $false "Risposta inattesa: $($res1 | ConvertTo-Json -Compress)"
} catch {
    $httpRes = $_.Exception.Response
    if ($null -ne $httpRes) {
        $statusCode = [int]$httpRes.StatusCode
        $reader = New-Object System.IO.StreamReader($httpRes.GetResponseStream())
        $body = $reader.ReadToEnd() | ConvertFrom-Json
        Assert-Test "Parametri mancanti restituiscono HTTP 400 e outcome 'missing_params'" ($statusCode -eq 400 -and $body.outcome -eq "missing_params") "HTTP $statusCode - Outcome: $($body.outcome)"
    } else {
        Assert-Test "Errore di connessione di rete" $false $_.Exception.Message
    }
}

# TEST 2: Firma CMAC Errata / Payload Corrotto
Log-Test "`n[TEST] 2. Invocazione con payload corrotto/CMAC errato (Atteso: mac_invalid)..." -Color Yellow
try {
    $res2 = Invoke-RestMethod -Uri "$TargetUrl?picc_data=00112233445566778899aabbccddeeff&cmac=0011223344556677&json=1" -Method Get -Headers @{ "Accept" = "application/json" }
    Assert-Test "Payload corrotto restituisce outcome 'mac_invalid' e mac_valid = false" ($res2.outcome -eq "mac_invalid" -and $res2.mac_valid -eq $false) "Outcome: $($res2.outcome)"
} catch {
    Assert-Test "Errore invocazione richiesta HTTP" $false $_.Exception.Message
}

# TEST 3: Invocazione via curl.exe nativo Windows
Log-Test "`n[TEST] 3. Esecuzione richiesta cURL nativa Windows (curl.exe)..." -Color Yellow
$curlPath = Get-Command "curl.exe" -ErrorAction SilentlyContinue
if ($null -ne $curlPath) {
    $curlOut = & curl.exe -s "$TargetUrl?picc_data=00112233445566778899aabbccddeeff&cmac=0011223344556677&json=1" -H "Accept: application/json"
    $curlJson = $curlOut | ConvertFrom-Json
    Assert-Test "curl.exe esegue con successo la richiesta REST e riceve JSON" ($curlJson.outcome -eq "mac_invalid") "Output cURL: $curlOut"
} else {
    Log-Test "[SKIP] curl.exe non trovato nel PATH del sistema." -Color DarkGray
}

# TEST 4: Verificazione Struttura JSON di Risposta API
Log-Test "`n[TEST] 4. Verifica della struttura dei campi nel JSON di risposta..." -Color Yellow
try {
    $res4 = Invoke-RestMethod -Uri "$TargetUrl?picc_data=00112233445566778899aabbccddeeff&cmac=0011223344556677&json=1" -Method Get -Headers @{ "Accept" = "application/json" }
    $hasFields = ($null -ne $res4.outcome) -and ($null -ne $res4.description) -and ($null -ne $res4.http_code)
    Assert-Test "Risposta JSON contiene i campi 'outcome', 'description' e 'http_code'" $hasFields "Campi presenti: $($res4 | ConvertTo-Json -Compress)"
} catch {
    Assert-Test "Errore nella verifica campi JSON" $false $_.Exception.Message
}

# RIEPILOGO FINALE
Log-Test "`n--------------------------------------------------------------------------" -Color Cyan
Log-Test "RIEPILOGO SUITE DI TEST POWERSHELL / CURL:"
Log-Test "• Test Totali Eseguiti : $totalTests"
Log-Test "• Test SUPERATI        : $passedTests"
Log-Test "• Test FALLITI         : $($totalTests - $passedTests)"

if ($passedTests -eq $totalTests) {
    Log-Test "`n>>> ESITO SUITE: TUTTI I TEST SONO STATI SUPERATI CON SUCCESSO! <<<" -Color Green
} else {
    Log-Test "`n>>> ESITO SUITE: PRESENTE ALMENO UN FALLIMENTO, VERIFICARE I LOG. <<<" -Color Red
}

Log-Test "--------------------------------------------------------------------------`n" -Color Cyan
