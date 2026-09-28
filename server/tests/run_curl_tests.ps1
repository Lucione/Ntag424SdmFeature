# ==============================================================================
# SUITE DI TEST AUTOMATIZZATA IN POWERSHELL / CURL PER WINDOWS
# Progetto: Ntag424SdmFeature
# Compatibile con Windows PowerShell 5.1 e PowerShell 7+
#
# Uso base (solo test negativi / di contratto):
#   .\run_curl_tests.ps1
#   .\run_curl_tests.ps1 -TargetUrl "https://logicarts.altervista.org/verify.php"
#
# Uso completo (test positivi + replay). I valori vanno letti da un tap REALE
# NON ancora verificato dal server (altrimenti il contatore risulta gia' usato):
#   .\run_curl_tests.ps1 -ValidPicc "<picc_data>" -ValidCmac "<cmac>" `
#                        -ExpectedReplayOutcome "<outcome atteso al secondo uso>"
#
# Se il server usa nomi di parametro diversi (es. "e" / "c"):
#   .\run_curl_tests.ps1 -PiccParam e -CmacParam c
# ==============================================================================

[CmdletBinding()]
param (
    [string]$TargetUrl = "https://logicarts.altervista.org/verify.php",
    [string]$PiccParam = "picc_data",
    [string]$CmacParam = "cmac",
    [string]$ValidPicc = "",
    [string]$ValidCmac = "",
    [string]$ExpectedReplayOutcome = "",
    [int]$MaxResponseMs = 5000
)

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir "test_results.log"

if ($TargetUrl -notmatch '^https?://[^/\s]+') {
    throw "TargetUrl non valido: '$TargetUrl' (atteso es. https://host/verify.php)"
}

"=== INIZIO SUITE DI TEST POWERSHELL/CURL SERVER NTAG 424 DNA [" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] ===" | Out-File -FilePath $LogFile -Encoding utf8

$script:totalTests = 0
$script:passedTests = 0
$script:skippedTests = 0
$script:AllBodies = New-Object System.Collections.Generic.List[string]

function Log-Test {
    param ([string]$Message, [string]$Color = "White")
    $Message | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Host $Message -ForegroundColor $Color
}

function Assert-Test {
    param ([string]$TestName, [bool]$Condition, [string]$Details = "")
    $script:totalTests++
    if ($Condition) {
        $script:passedTests++
        Log-Test "[PASS] Test #$($script:totalTests): $TestName" -Color Green
    } else {
        Log-Test "[FAIL] Test #$($script:totalTests): $TestName" -Color Red
        if ($Details -ne "") { Log-Test "       Diagnostica: $Details" -Color Red }
    }
}

function Skip-Test {
    param ([string]$TestName, [string]$Reason)
    $script:skippedTests++
    Log-Test "[SKIP] $TestName ($Reason)" -Color DarkGray
}

# Chiamata HTTP che restituisce SEMPRE status/body/header, anche con 3xx/4xx/5xx.
# Funziona su PS 5.1 (WebException) e PS 7 (HttpResponseException).
function Invoke-Api {
    param (
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{ "Accept" = "application/json" },
        [string]$Body = "",
        [switch]$NoRedirect
    )
    $r = [ordered]@{ Status = 0; Raw = ""; Json = $null; NetError = $null; ContentType = ""; Location = ""; Ms = 0 }
    $req = @{ Uri = $Url; Method = $Method; Headers = $Headers; UseBasicParsing = $true; ErrorAction = "Stop"; TimeoutSec = 30 }
    if ($NoRedirect) { $req["MaximumRedirection"] = 0 }
    if ($Method -eq "POST") { $req["Body"] = $Body; $req["ContentType"] = "application/x-www-form-urlencoded" }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ok = Invoke-WebRequest @req
        $r.Status = [int]$ok.StatusCode
        $r.Raw = [string]$ok.Content
        $r.ContentType = [string]$ok.Headers["Content-Type"]
        if ($ok.Headers["Location"]) { $r.Location = [string]$ok.Headers["Location"] }
    } catch {
        $ex = $_.Exception
        $err = $ex.Response
        if ($null -ne $err) {
            $r.Status = [int]$err.StatusCode
            if ($err -is [System.Net.HttpWebResponse]) {
                $r.ContentType = [string]$err.ContentType
                $r.Location = [string]$err.Headers["Location"]
            } else {
                try { $r.ContentType = [string]$err.Content.Headers.ContentType } catch { }
                try { if ($null -ne $err.Headers.Location) { $r.Location = $err.Headers.Location.ToString() } } catch { }
            }
            if ($null -ne $_.ErrorDetails -and $_.ErrorDetails.Message) {
                $r.Raw = $_.ErrorDetails.Message
            } else {
                try {
                    $sr = New-Object System.IO.StreamReader($err.GetResponseStream())
                    $r.Raw = $sr.ReadToEnd()
                } catch { }
            }
        } else {
            $r.NetError = $ex.Message
        }
    }
    $sw.Stop()
    $r.Ms = [int]$sw.ElapsedMilliseconds
    if ($r.Raw) {
        $script:AllBodies.Add($r.Raw)
        try { $r.Json = $r.Raw | ConvertFrom-Json } catch { }
    }
    [pscustomobject]$r
}

function Show-Resp {
    param ($R)
    if ($R.NetError) { return "Errore di rete: $($R.NetError)" }
    $b = [string]$R.Raw
    if ($b.Length -gt 200) { $b = $b.Substring(0, 200) + "..." }
    $b = $b -replace "\s+", " "
    return "HTTP $($R.Status) CT='$($R.ContentType)' Loc='$($R.Location)' Body: $b"
}

function Flip-Last  { param ([string]$S); $n = if ($S[-1] -eq '0') { '1' } else { '0' }; return $S.Substring(0, $S.Length - 1) + $n }
function Flip-First { param ([string]$S); $n = if ($S[0] -eq '0') { '1' } else { '0' }; return $n + $S.Substring(1) }

# --------------------------------------------------------------------------
# Costanti di test
# NB: si usa ${TargetUrl} perche' "$TargetUrl?..." fa interpretare il '?' come
# parte del nome variabile ($TargetUrl? = vuota) -> URI "json=1" non valido.
# --------------------------------------------------------------------------
$badPicc = "00112233445566778899aabbccddeeff"   # 16 byte (32 hex)
$badCmac = "0011223344556677"                    # 8 byte (16 hex)
$baseQ   = "${PiccParam}=${badPicc}&${CmacParam}=${badCmac}&json=1"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "SUITE DI TEST AUTOMATIZZATA SERVER BACKEND (WINDOWS POWERSHELL / CURL)" -ForegroundColor Yellow
Write-Host "Target URL: $TargetUrl  |  Parametri: $PiccParam / $CmacParam" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# ============================ A. CONTRATTO API ============================
Log-Test "`n--- A. CONTRATTO API E PARAMETRI ---" -Color Cyan

# A1: json=1 deve restituire JSON diretto (non redirect/HTML)
Log-Test "`n[TEST] A1. Modalita' json=1 restituisce JSON (non HTML / redirect)..." -Color Yellow
$rNone = Invoke-Api "${TargetUrl}?json=1"
if ($rNone.NetError) {
    Assert-Test "Endpoint raggiungibile" $false $rNone.NetError
} else {
    Assert-Test "json=1 restituisce un body JSON valido" ($null -ne $rNone.Json) (Show-Resp $rNone)
}

# A2: nessun parametro
Log-Test "`n[TEST] A2. Nessun parametro (Atteso: HTTP 400 missing_params)..." -Color Yellow
Assert-Test "Nessun parametro -> HTTP 400 + outcome 'missing_params'" `
    ($rNone.Status -eq 400 -and $rNone.Json.outcome -eq "missing_params") (Show-Resp $rNone)

# A3: solo picc
Log-Test "`n[TEST] A3. Solo $PiccParam (Atteso: 400 missing_params)..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=${badPicc}&json=1"
Assert-Test "Solo $PiccParam -> HTTP 400 + 'missing_params'" ($r.Status -eq 400 -and $r.Json.outcome -eq "missing_params") (Show-Resp $r)

# A4: solo cmac
Log-Test "`n[TEST] A4. Solo $CmacParam (Atteso: 400 missing_params)..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${CmacParam}=${badCmac}&json=1"
Assert-Test "Solo $CmacParam -> HTTP 400 + 'missing_params'" ($r.Status -eq 400 -and $r.Json.outcome -eq "missing_params") (Show-Resp $r)

# A5: valori vuoti
Log-Test "`n[TEST] A5. Parametri presenti ma vuoti..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=&${CmacParam}=&json=1"
Assert-Test "Valori vuoti -> 4xx, outcome presente, mai mac_valid=true" `
    ($r.Status -ge 400 -and $r.Status -lt 500 -and $null -ne $r.Json.outcome -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# A6: i nomi dei parametri sono riconosciuti dal server
Log-Test "`n[TEST] A6. Nomi parametro riconosciuti ($PiccParam / $CmacParam)..." -Color Yellow
$rBad = Invoke-Api "${TargetUrl}?$baseQ"
Assert-Test "Con entrambi i parametri l'outcome NON e' 'missing_params'" `
    ($null -ne $rBad.Json -and $rBad.Json.outcome -ne "missing_params") `
    "Se fallisce: il server usa altri nomi di parametro (usa -PiccParam/-CmacParam) o richiede parametri aggiuntivi (es. enc). $(Show-Resp $rBad)"

# A7: CMAC errato
Log-Test "`n[TEST] A7. Payload/CMAC errato (Atteso: mac_invalid, mac_valid=false)..." -Color Yellow
Assert-Test "Payload corrotto -> outcome 'mac_invalid' e mac_valid=false" `
    ($rBad.Json.outcome -eq "mac_invalid" -and $rBad.Json.mac_valid -eq $false) (Show-Resp $rBad)

# A8: coerenza http_code <-> status HTTP
Log-Test "`n[TEST] A8. Coerenza campo http_code con lo status HTTP..." -Color Yellow
Assert-Test "http_code nel JSON == status HTTP reale (mac_invalid, 4xx)" `
    ($null -ne $rBad.Json -and [int]$rBad.Json.http_code -eq $rBad.Status -and $rBad.Status -ge 400 -and $rBad.Status -lt 500) (Show-Resp $rBad)

# A9: content-type
Log-Test "`n[TEST] A9. Content-Type della risposta JSON..." -Color Yellow
Assert-Test "Content-Type contiene application/json" ($rBad.ContentType -match "application/json") (Show-Resp $rBad)

# A10: campi
Log-Test "`n[TEST] A10. Struttura JSON..." -Color Yellow
$j = $rBad.Json
Assert-Test "JSON contiene 'outcome', 'description', 'http_code'" `
    (($null -ne $j) -and ($null -ne $j.outcome) -and ($null -ne $j.description) -and ($null -ne $j.http_code)) (Show-Resp $rBad)

# A11: tempo di risposta
Log-Test "`n[TEST] A11. Tempo di risposta..." -Color Yellow
Assert-Test "Risposta entro $MaxResponseMs ms" ($rBad.Ms -le $MaxResponseMs) "$($rBad.Ms) ms"

# A12: json=1 senza header Accept
Log-Test "`n[TEST] A12. json=1 senza header Accept..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?$baseQ" -Headers @{}
Assert-Test "json=1 da solo basta per ottenere JSON (senza Accept)" ($null -ne $r.Json -and $null -ne $r.Json.outcome) (Show-Resp $r)

# A13: modalita' HTML (senza json=1, senza Accept JSON) -> redirect a result.php o pagina HTML
Log-Test "`n[TEST] A13. Modalita' HTML per browser/telefono (redirect o pagina)..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=${badPicc}&${CmacParam}=${badCmac}" -Headers @{ "Accept" = "text/html" } -NoRedirect
$isRedirect = ($r.Status -ge 300 -and $r.Status -lt 400 -and $r.Location -match "outcome=")
$isHtml = ($r.Status -eq 200 -and $r.ContentType -match "text/html")
Assert-Test "Senza json=1: redirect con 'outcome=' oppure pagina HTML" ($isRedirect -or $isHtml) (Show-Resp $r)

# ======================== B. INPUT MALFORMATI ========================
Log-Test "`n--- B. INPUT MALFORMATI E ROBUSTEZZA ---" -Color Cyan

function Test-Malformed {
    param ([string]$Name, [string]$Query)
    Log-Test "`n[TEST] $Name" -Color Yellow
    $x = Invoke-Api "${TargetUrl}?$Query"
    Assert-Test "$Name -> 4xx, outcome presente, mac_valid mai true" `
        ($x.Status -ge 400 -and $x.Status -lt 500 -and $null -ne $x.Json.outcome -and $x.Json.mac_valid -ne $true) (Show-Resp $x)
}

Test-Malformed "B1. picc_data con caratteri non esadecimali" "${PiccParam}=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz&${CmacParam}=${badCmac}&json=1"
Test-Malformed "B2. picc_data di lunghezza dispari (31 hex)" "${PiccParam}=$($badPicc.Substring(1))&${CmacParam}=${badCmac}&json=1"
Test-Malformed "B3. picc_data troppo corto (8 hex)" "${PiccParam}=00112233&${CmacParam}=${badCmac}&json=1"
Test-Malformed "B4. cmac troppo corto (4 hex)" "${PiccParam}=${badPicc}&${CmacParam}=0011&json=1"
Test-Malformed "B5. cmac con caratteri non esadecimali" "${PiccParam}=${badPicc}&${CmacParam}=gggggggggggggggg&json=1"

# B6: oversize (accetta 4xx come 414/400; vieta solo i 5xx)
Log-Test "`n[TEST] B6. Parametro enorme (8 KB)..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=$('a' * 8000)&${CmacParam}=${badCmac}&json=1"
Assert-Test "Parametro da 8 KB non causa errori 5xx ne' successo" `
    ($null -eq $r.NetError -and $r.Status -ge 400 -and $r.Status -lt 500) (Show-Resp $r)

# B7: maiuscole
Log-Test "`n[TEST] B7. Hex maiuscolo equivalente al minuscolo..." -Color Yellow
$rUp = Invoke-Api "${TargetUrl}?${PiccParam}=$($badPicc.ToUpper())&${CmacParam}=$($badCmac.ToUpper())&json=1"
Assert-Test "Stesso outcome con hex maiuscolo e minuscolo" `
    ($null -ne $rUp.Json -and $rUp.Json.outcome -eq $rBad.Json.outcome) "minuscolo='$($rBad.Json.outcome)' maiuscolo='$($rUp.Json.outcome)'"

# B8: parametro array PHP (picc_data[]=...) -> TypeError se non gestito
Log-Test "`n[TEST] B8. Parametro in forma array ($PiccParam[])..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}[]=${badPicc}&${CmacParam}=${badCmac}&json=1"
Assert-Test "Parametro array non causa 5xx" ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# B9: parametro duplicato
Log-Test "`n[TEST] B9. Parametro duplicato..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=${badPicc}&${PiccParam}=${badPicc}&${CmacParam}=${badCmac}&json=1"
Assert-Test "Parametro duplicato non causa 5xx" ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# B10: metodo POST
Log-Test "`n[TEST] B10. Metodo POST..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?json=1" -Method POST -Body "${PiccParam}=${badPicc}&${CmacParam}=${badCmac}"
Assert-Test "POST non causa 5xx e non valida mai il MAC" ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# ============================ C. SICUREZZA ============================
Log-Test "`n--- C. SICUREZZA ---" -Color Cyan

# C1: XSS
Log-Test "`n[TEST] C1. Payload XSS nei parametri non riflesso..." -Color Yellow
$xss = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
$r = Invoke-Api "${TargetUrl}?${PiccParam}=${xss}&${CmacParam}=${xss}&json=1"
Assert-Test "Input XSS non riflesso in chiaro e nessun 5xx" `
    ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Raw -notmatch "<script>alert\(1\)</script>") (Show-Resp $r)

# C2: SQL injection
Log-Test "`n[TEST] C2. Payload SQL injection nei parametri..." -Color Yellow
$sqli = "%27%20OR%201%3D1--"
$r = Invoke-Api "${TargetUrl}?${PiccParam}=${sqli}&${CmacParam}=${sqli}&json=1"
Assert-Test "Input SQLi -> nessun 5xx e mac_valid mai true" ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# C3: path traversal / null byte
Log-Test "`n[TEST] C3. Null byte e path traversal nei parametri..." -Color Yellow
$r = Invoke-Api "${TargetUrl}?${PiccParam}=%00..%2F..%2Fetc%2Fpasswd&${CmacParam}=%00&json=1"
Assert-Test "Null byte/traversal -> nessun 5xx e mac_valid mai true" ($null -eq $r.NetError -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

# C4 (a fine suite): nessun leak di errori PHP in nessuna risposta raccolta
# (vedi sezione finale)

# ================== D. curl.exe NATIVO (cross-check) ==================
Log-Test "`n--- D. curl.exe NATIVO ---" -Color Cyan
Log-Test "`n[TEST] D1. Richiesta con curl.exe nativo Windows..." -Color Yellow
$curlPath = Get-Command "curl.exe" -ErrorAction SilentlyContinue
if ($null -ne $curlPath) {
    $curlRaw = ((& curl.exe -sS --max-time 20 -w "`n%{http_code}" "${TargetUrl}?$baseQ" -H "Accept: application/json" 2>&1) | Out-String).TrimEnd()
    $lines = $curlRaw -split "`r?`n"
    $curlCode = $lines[-1]
    $curlBody = ""
    if ($lines.Count -gt 1) { $curlBody = ($lines[0..($lines.Count - 2)] -join "`n") }
    $curlJson = $null
    try { $curlJson = $curlBody | ConvertFrom-Json } catch { }
    Assert-Test "curl.exe: stesso outcome e stesso status di Invoke-WebRequest" `
        ($null -ne $curlJson -and $curlJson.outcome -eq $rBad.Json.outcome -and $curlCode -eq [string]$rBad.Status) `
        "curl: HTTP $curlCode, body: $curlBody"
} else {
    Skip-Test "D1 curl.exe" "curl.exe non trovato nel PATH"
}

# ============ E. TEST POSITIVI (richiedono -ValidPicc / -ValidCmac) ============
Log-Test "`n--- E. TEST POSITIVI E REPLAY ---" -Color Cyan
if ($ValidPicc -ne "" -and $ValidCmac -ne "") {
    # Prima i test di manomissione (non consumano il contatore), poi l'uso valido, poi il replay.
    Log-Test "`n[TEST] E1. CMAC manomesso (ultimo nibble) su dati validi..." -Color Yellow
    $r = Invoke-Api "${TargetUrl}?${PiccParam}=${ValidPicc}&${CmacParam}=$(Flip-Last $ValidCmac)&json=1"
    Assert-Test "CMAC alterato -> mac_invalid, mac_valid=false" ($r.Json.outcome -eq "mac_invalid" -and $r.Json.mac_valid -eq $false) (Show-Resp $r)

    Log-Test "`n[TEST] E2. picc_data manomesso (primo nibble)..." -Color Yellow
    $r = Invoke-Api "${TargetUrl}?${PiccParam}=$(Flip-First $ValidPicc)&${CmacParam}=${ValidCmac}&json=1"
    Assert-Test "picc_data alterato -> 4xx, mac_valid mai true" ($r.Status -ge 400 -and $r.Status -lt 500 -and $r.Json.mac_valid -ne $true) (Show-Resp $r)

    Log-Test "`n[TEST] E3. Tap valido (primo uso)..." -Color Yellow
    $rOk = Invoke-Api "${TargetUrl}?${PiccParam}=${ValidPicc}&${CmacParam}=${ValidCmac}&json=1"
    Assert-Test "Dati validi -> HTTP 200, mac_valid=true, http_code coerente" `
        ($rOk.Status -eq 200 -and $rOk.Json.mac_valid -eq $true -and [int]$rOk.Json.http_code -eq 200) (Show-Resp $rOk)

    if ($ExpectedReplayOutcome -ne "") {
        Log-Test "`n[TEST] E4. Replay dello stesso tap (contatore gia' usato)..." -Color Yellow
        $rRe = Invoke-Api "${TargetUrl}?${PiccParam}=${ValidPicc}&${CmacParam}=${ValidCmac}&json=1"
        Assert-Test "Replay -> outcome '$ExpectedReplayOutcome' e HTTP 4xx" `
            ($rRe.Json.outcome -eq $ExpectedReplayOutcome -and $rRe.Status -ge 400 -and $rRe.Status -lt 500) (Show-Resp $rRe)
    } else {
        Skip-Test "E4 Replay" "passa -ExpectedReplayOutcome con l'outcome atteso"
    }
} else {
    Skip-Test "E1-E4 test positivi/manomissione/replay" "passa -ValidPicc e -ValidCmac letti da un tap reale non ancora verificato"
}

# ============ F. NESSUN LEAK DI ERRORI PHP IN TUTTE LE RISPOSTE ============
Log-Test "`n--- F. CONTROLLO TRASVERSALE ---" -Color Cyan
Log-Test "`n[TEST] F1. Nessun leak di errori/stack trace PHP in alcuna risposta..." -Color Yellow
$leakPattern = "(?i)(Fatal error|Warning:|Notice:|Deprecated:|Parse error|Stack trace|Uncaught|on line \d+)"
$leaks = @($script:AllBodies | Where-Object { $_ -match $leakPattern })
$leakDetail = ""
if ($leaks.Count -gt 0) {
    $s = [string]$leaks[0]
    if ($s.Length -gt 200) { $s = $s.Substring(0, 200) + "..." }
    $leakDetail = "$($leaks.Count) risposte con possibile leak. Prima: $s"
}
Assert-Test "Nessun errore PHP esposto nei body ($($script:AllBodies.Count) risposte analizzate)" ($leaks.Count -eq 0) $leakDetail

# ============================== RIEPILOGO ==============================
Log-Test "`n--------------------------------------------------------------------------" -Color Cyan
Log-Test "RIEPILOGO SUITE DI TEST POWERSHELL / CURL:"
Log-Test "- Test Totali Eseguiti : $($script:totalTests)"
Log-Test "- Test SUPERATI        : $($script:passedTests)"
Log-Test "- Test FALLITI         : $($script:totalTests - $script:passedTests)"
Log-Test "- Test SALTATI         : $($script:skippedTests)"

if ($script:passedTests -eq $script:totalTests) {
    Log-Test "`n>>> ESITO SUITE: TUTTI I TEST ESEGUITI SONO STATI SUPERATI CON SUCCESSO! <<<" -Color Green
} else {
    Log-Test "`n>>> ESITO SUITE: PRESENTE ALMENO UN FALLIMENTO, VERIFICARE I LOG. <<<" -Color Red
}
Log-Test "--------------------------------------------------------------------------`n" -Color Cyan

if ($script:passedTests -ne $script:totalTests) { exit 1 }
