<?php
declare(strict_types=1);

/**
 * SUITE COMPLETA DI TEST AUTOMATIZZATI BACKEND SERVER (PHP)
 * Progetto: NTAG 424 DNA SUN/SDM Verification Backend
 *
 * Esecuzione da riga di comando (CLI):
 *   php server/tests/run_tests.php
 *
 * Esecuzione contro un server remoto/locale attivo:
 *   php server/tests/run_tests.php --url=https://logicarts.altervista.org/verify.php
 *   php server/tests/run_tests.php --url=http://localhost/verify.php
 *
 * Genera un report dettagliato a console e registra il log in `server/tests/test_results.log`.
 */

require_once __DIR__ . '/../src/Cmac.php';
require_once __DIR__ . '/../src/Diversify.php';
require_once __DIR__ . '/../src/SunVerifier.php';
require_once __DIR__ . '/../src/TagRepository.php';

use SunVerify\Cmac;
use SunVerify\Diversify;
use SunVerify\TagRepository;

$config = require __DIR__ . '/../config.php';

// Parsing argomenti CLI
$targetUrl = null;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--url=')) {
        $targetUrl = substr($arg, 6);
    }
}

$logFile = __DIR__ . '/test_results.log';
file_put_contents($logFile, "=== INIZIO SUITE DI TEST SERVER NTAG 424 DNA [" . date('Y-m-d H:i:s') . "] ===\n\n");

function logMsg(string $msg, bool $isError = false): void {
    global $logFile;
    file_put_contents($logFile, $msg . "\n", FILE_APPEND);

    // Output colorato in console CLI
    if (PHP_SAPI === 'cli') {
        if ($isError) {
            echo "\033[31m" . $msg . "\033[0m\n";
        } else if (str_contains($msg, '[PASS]')) {
            echo "\033[32m" . $msg . "\033[0m\n";
        } else if (str_contains($msg, '[TEST]')) {
            echo "\033[33m" . $msg . "\033[0m\n";
        } else {
            echo $msg . "\n";
        }
    } else {
        echo nl2br(htmlspecialchars($msg)) . "<br>";
    }
}

/**
 * Genera sinteticamente un'URL con dati cifrati (PICCData) e firma CMAC
 * 100% autentica dal punto di vista crittografico, senza bisogno di tag fisici!
 */
function generateSyntheticTapUrl(
    string $uidHex,
    int $counter,
    string $metaReadKey,
    string $fileReadKey,
    bool $diversify,
    string $aid = '',
    string $sysId = ''
): array {
    $uidRaw = hex2bin($uidHex);

    // 1. Costruzione blocco PICCData 16 byte: Header 0xC0 (UID + Ctr) + UID (7 byte) + Ctr (3 byte LSB) + Padding (5 byte zero)
    $ctrBytes = chr($counter & 0xFF) . chr(($counter >> 8) & 0xFF) . chr(($counter >> 16) & 0xFF);
    $plainPicc = "\xC0" . $uidRaw . $ctrBytes . str_repeat("\x00", 5);

    // 2. Cifratura PICCData con metaReadKey (AES-128-CBC IV zero)
    $piccRaw = openssl_encrypt(
        $plainPicc,
        'aes-128-cbc',
        $metaReadKey,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
        str_repeat("\x00", 16)
    );
    $piccDataHex = bin2hex($piccRaw);

    // 3. Diversificazione chiave se richiesta
    $effectiveFileKey = $diversify
        ? Diversify::aes128($fileReadKey, $uidRaw, $aid, $sysId)
        : $fileReadKey;

    // 4. Derivazione Session Key SDMMAC (SV2 = 0x3C 0xC3 0x00 0x01 0x00 0x80 || UID || Ctr LSB)
    $sv2 = "\x3c\xc3\x00\x01\x00\x80" . $uidRaw . $ctrBytes;
    $macSessionKey = Cmac::generate($effectiveFileKey, $sv2);

    // 5. Calcolo CMAC e troncamento a 8 byte
    $fullCmac = Cmac::generate($macSessionKey, '');
    $cmacHex = bin2hex(Cmac::shorten($fullCmac));

    return [
        'uid'       => $uidHex,
        'picc_data' => $piccDataHex,
        'cmac'      => $cmacHex,
        'counter'   => $counter,
    ];
}

/** Esegue una chiamata GET ed ottiene la risposta JSON formattata */
function executeRequest(string $url, array $params): array {
    $queryString = http_build_query(array_merge($params, ['json' => '1']));
    $fullUrl = $url . '?' . $queryString;

    if (function_exists('curl_init')) {
        $ch = curl_init($fullUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    } else {
        $opts = [
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/json\r\n",
                'timeout' => 10,
                'ignore_errors' => true
            ]
        ];
        $context = stream_context_create($opts);
        $response = file_get_contents($fullUrl, false, $context);
        $httpCode = 200;
        if (isset($http_response_header[0]) && preg_match('#HTTP/\d\.\d\s+(\d+)#i', $http_response_header[0], $m)) {
            $httpCode = (int)$m[1];
        }
    }

    $json = json_decode((string)$response, true);
    return [
        'http_code' => $httpCode,
        'raw'       => $response,
        'json'      => $json ?? [],
        'url'       => $fullUrl
    ];
}

// Inizializzazione Connessione PDO Locale per gestione test
$dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $config['db_host'], $config['db_name']);
try {
    $pdo = new \PDO($dsn, $config['db_user'], $config['db_pass'], [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $repo = new TagRepository($pdo);
} catch (\PDOException $e) {
    logMsg("CRITICAL: Errore di connessione al DB MySQL: " . $e->getMessage(), true);
    exit(1);
}

// Determina l'URL base se non passato via CLI
if ($targetUrl === null) {
    // URL di default per test locale o Altervista
    $targetUrl = 'https://logicarts.altervista.org/verify.php';
}

logMsg("Configurazione Target Test:");
logMsg("• Target URL: " . $targetUrl);
logMsg("• DB Host: " . $config['db_host'] . " / DB Name: " . $config['db_name']);
logMsg("• Diversificazione Chiave: " . ($config['diversify_file_read_key'] ? 'ATTIVA (AN10922)' : 'DISATTIVA'));
logMsg("----------------------------------------------------------------------");

$totalTests = 0;
$passedTests = 0;

function assertTestCase(string $testName, bool $condition, string $details = ''): void {
    global $totalTests, $passedTests;
    $totalTests++;
    if ($condition) {
        $passedTests++;
        logMsg("[PASS] Test #{$totalTests}: {$testName}");
    } else {
        logMsg("[FAIL] Test #{$totalTests}: {$testName}", true);
        if ($details !== '') {
            logMsg("       Diagnostica: {$details}", true);
        }
    }
}

// ============================================================================
// SUITE DI TEST AUTOMATIZZATA
// ============================================================================

// TEST 1: Parametri Mancanti
logMsg("\n[TEST] 1. Verifica gestione Parametri Mancanti");
$res = executeRequest($targetUrl, []);
assertTestCase(
    "Parametri mancanti restituiscono HTTP 400 e outcome 'missing_params'",
    $res['http_code'] === 400 && ($res['json']['outcome'] ?? '') === 'missing_params',
    "HTTP {$res['http_code']} - Body: {$res['raw']}"
);

// TEST 2: Firma CMAC Non Valida / Payload Corrotto
logMsg("\n[TEST] 2. Verifica gestione Firma CMAC Errata");
$res = executeRequest($targetUrl, [
    'picc_data' => '00112233445566778899aabbccddeeff',
    'cmac'      => '0011223344556677'
]);
assertTestCase(
    "Payload corrotto restituisce outcome 'mac_invalid' e mac_valid = false",
    ($res['json']['outcome'] ?? '') === 'mac_invalid' && ($res['json']['mac_valid'] ?? null) === false,
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A')
);

// TEST 3: Generazione Tag Sintetico Nuovo -> Esito 'not_activated' (Pending)
logMsg("\n[TEST] 3. Scansione Tag Sintetico Nuovo (Stato Pending)");
$syntheticUid = '04' . bin2hex(random_bytes(6)); // Genera UID casuale di 7 byte (es. 04A1B2C3D4E5F6)
$tap1 = generateSyntheticTapUrl(
    $syntheticUid,
    1, // Counter = 1
    $config['meta_read_key'],
    $config['file_read_master_key'],
    $config['diversify_file_read_key'],
    $config['application_id'],
    $config['system_identifier']
);

$res = executeRequest($targetUrl, $tap1);
assertTestCase(
    "Nuovo Tag viene censito a DB ma in stato 'not_activated' (pending)",
    ($res['json']['outcome'] ?? '') === 'not_activated' &&
    ($res['json']['uid'] ?? '') === $syntheticUid &&
    ($res['json']['mac_valid'] ?? null) === true,
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A') . " - UID: " . ($res['json']['uid'] ?? 'N/A')
);

// TEST 4: Attivazione del Tag dal Backend (`upsertTag`)
logMsg("\n[TEST] 4. Abilitazione e Attivazione Tag dal Backend (`upsertTag`)");
$repo->upsertTag($syntheticUid, 'Tag Test Automatizzato Suite', 'active', -1);
$tagDb = $repo->find($syntheticUid);
assertTestCase(
    "Lo stato del tag a database diventa 'active'",
    $tagDb !== null && $tagDb['status'] === 'active',
    "Stato DB: " . ($tagDb['status'] ?? 'N/A')
);

// TEST 5: Scansione Tag Attivo con Contatore Avanzato -> Esito 'valid'
logMsg("\n[TEST] 5. Scansione Tag Attivo (Contatore = 2)");
$tap2 = generateSyntheticTapUrl(
    $syntheticUid,
    2, // Counter avanzato a 2
    $config['meta_read_key'],
    $config['file_read_master_key'],
    $config['diversify_file_read_key'],
    $config['application_id'],
    $config['system_identifier']
);

$res = executeRequest($targetUrl, $tap2);
assertTestCase(
    "Tag attivo con contatore avanzato restituisce outcome 'valid' e success = true",
    ($res['json']['outcome'] ?? '') === 'valid' &&
    ($res['json']['success'] ?? null) === true &&
    ($res['json']['counter'] ?? 0) === 2,
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A') . " - Success: " . json_encode($res['json']['success'] ?? false)
);

// TEST 6: Protezione Anti-Replay (Riesecuzione dello stesso Contatore = 2)
logMsg("\n[TEST] 6. Rilevamento Scansione Duplicata / Anti-Replay (Stesso Contatore = 2)");
$res = executeRequest($targetUrl, $tap2); // Riesegue la richiesta con lo stesso contatore 2
assertTestCase(
    "Scansione duplicata viene bloccata e classificata come 'replay_suspected'",
    ($res['json']['outcome'] ?? '') === 'replay_suspected',
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A')
);

// TEST 7: Scansione con Contatore Minore o Uguale -> Anti-Replay
logMsg("\n[TEST] 7. Scansione con Contatore Inferiore (Counter = 1)");
$tapOld = generateSyntheticTapUrl(
    $syntheticUid,
    1, // Counter vecchio 1
    $config['meta_read_key'],
    $config['file_read_master_key'],
    $config['diversify_file_read_key'],
    $config['application_id'],
    $config['system_identifier']
);
$res = executeRequest($targetUrl, $tapOld);
assertTestCase(
    "Contatore inferiore o uguale viene rifiutato con 'replay_suspected'",
    ($res['json']['outcome'] ?? '') === 'replay_suspected',
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A')
);

// TEST 8: Revoca del Tag e Verifica Rifiuto (`revoked`)
logMsg("\n[TEST] 8. Revoca del Tag e Verifica Blocco");
$repo->upsertTag($syntheticUid, null, 'revoked');
$tap3 = generateSyntheticTapUrl(
    $syntheticUid,
    3, // Counter 3
    $config['meta_read_key'],
    $config['file_read_master_key'],
    $config['diversify_file_read_key'],
    $config['application_id'],
    $config['system_identifier']
);
$res = executeRequest($targetUrl, $tap3);
assertTestCase(
    "Tag revocato restituisce outcome 'revoked'",
    ($res['json']['outcome'] ?? '') === 'revoked',
    "Outcome: " . ($res['json']['outcome'] ?? 'N/A')
);

// ============================================================================
// RIEPILOGO FINALE
// ============================================================================
logMsg("\n----------------------------------------------------------------------");
logMsg("RIEPILOGO SUITE DI TEST SERVER:");
logMsg("• Test Totali Eseguiti : {$totalTests}");
logMsg("• Test SUPERATI        : {$passedTests}");
logMsg("• Test FALLITI         : " . ($totalTests - $passedTests));

if ($passedTests === $totalTests) {
    logMsg("\n>>> ESITO SUITE: TUTTI I TEST SONO STATI SUPERATI CON SUCCESSO! <<<");
} else {
    logMsg("\n>>> ESITO SUITE: PRESENTE ALMENO UN FALLIMENTO, VERIFICARE I LOG. <<<", true);
}

logMsg("----------------------------------------------------------------------\n");
