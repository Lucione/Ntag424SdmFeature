<?php
declare(strict_types=1);
ini_set('display_errors', '0');
error_reporting(E_ALL);

/**
 * Endpoint chiamato dal browser dello smartphone quando legge il tag NFC.
 * URL attesa: https://tuodominio/verify.php?uid=<hex>&picc_data=<hex>&cmac=<hex>
 *
 * Implementa il pattern PRG (Post/Redirect/Get):
 * 1. Decifra e verifica la firma del tag.
 * 2. Se il tag non esiste a DB, viene registrato con stato 'pending' (NON attivo).
 * 3. Se il tag è 'pending', viene salvata la scansione ('not_activated') e viene mostrata
 *    la pagina informativa. Solo l'abilitazione nel backend permetterà l'esito 'valid'.
 * 4. Registra l'esito nel database (`scan_log`).
 * 5. Reindirizza il browser dell'utente a `result.php?scan_id=...&outcome=...`
 *    evitando che ricaricamenti del browser rieseguano il ciclo di verifica.
 */

require __DIR__ . '/src/Cmac.php';
require __DIR__ . '/src/Diversify.php';
require __DIR__ . '/src/SunVerifier.php';
require __DIR__ . '/src/TagRepository.php';

use SunVerify\SunVerifier;
use SunVerify\TagRepository;

$config = require __DIR__ . '/config.php';

// Determina se la richiesta proviene da un'API (es. App Mobile) o dal Browser
function isJsonRequested(): bool
{
    if (isset($_GET['format']) && strtolower($_GET['format']) === 'json') {
        return true;
    }
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    return str_contains(strtolower($accept), 'application/json');
}

function respond(int $httpStatus, string $outcome, array $extra = [], ?int $scanId = null): never
{
    if (isJsonRequested()) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code($httpStatus);
        echo json_encode(array_merge(['outcome' => $outcome], $extra), JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Reindirizzamento PRG (Post-Redirect-Get) per la visualizzazione dell'esito in HTML
    $targetUrl = 'result.php?outcome=' . urlencode($outcome);
    if ($scanId !== null) {
        $targetUrl .= '&scan_id=' . $scanId;
    }
    if (isset($extra['uid'])) {
        $targetUrl .= '&uid=' . urlencode($extra['uid']);
    }

    header('Location: ' . $targetUrl, true, 302);
    exit;
}

$uidHex = $_GET['uid'] ?? '';
$piccDataHex = $_GET['picc_data'] ?? '';
$cmacHex = $_GET['cmac'] ?? '';

if ($piccDataHex === '' || $cmacHex === '') {
    respond(400, 'missing_params');
}

$dsn = sprintf(
    'mysql:host=%s;dbname=%s;charset=%s',
    $config['db_host'],
    $config['db_name'],
    $config['db_charset'] ?? 'utf8mb4'
);

try {
    $pdo = new \PDO($dsn, $config['db_user'], $config['db_pass'], [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (\PDOException $e) {
    respond(500, 'db_connection_error');
}

$repo = new TagRepository($pdo);

$verifier = new SunVerifier(
    $config['meta_read_key'],
    $config['file_read_master_key'],
    $config['diversify_file_read_key'],
    $config['application_id'],
    $config['system_identifier'],
);

try {
    $result = $verifier->verify($piccDataHex, $cmacHex);
} catch (\InvalidArgumentException $e) {
    respond(400, 'bad_format', ['message' => $e->getMessage()]);
} catch (\Throwable $e) {
    respond(500, 'internal_error');
}

$uid = $result->uidHex;

// 1. Verificazione della firma CMAC
if (!$result->macValid) {
    $repo->register($uid, null, 'pending');
    $scanId = $repo->logScan($uid, $result->readCounter, false, 'mac_invalid');
    respond(200, 'mac_invalid', ['uid' => $uid], $scanId);
}

// 2. Registrazione Tag se mai visto prima (viene inserito in stato 'pending' = NON ATTIVO)
$existing = $repo->find($uid);
if ($existing === null) {
    $repo->register($uid, null, 'pending');
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'not_activated');
    respond(200, 'not_activated', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
}

// 3. Controllo Tag Revocato
if ($existing['status'] === 'revoked') {
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'revoked');
    respond(200, 'revoked', ['uid' => $uid], $scanId);
}

// 4. Controllo Tag Non Ancora Attivato (status = 'pending' o diverso da 'active')
if ($existing['status'] !== 'active') {
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'not_activated');
    respond(200, 'not_activated', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
}

// 5. Se il tag è 'active', procedi con il controllo Anti-Replay ed avanzamento del contatore
$counterOk = $repo->checkAndAdvanceCounter($uid, $result->readCounter);

if (!$counterOk) {
    // Scansione duplicata / Replay
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'replay');
    respond(200, 'replay_suspected', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
}

// 6. Scansione Valida, Autentica e Attiva
$scanId = $repo->logScan($uid, $result->readCounter, true, 'valid');
respond(200, 'valid', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
