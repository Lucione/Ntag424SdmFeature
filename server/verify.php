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
 * 2. Registra l'esito nel database (`scan_log`).
 * 3. Reindirizza il browser dell'utente a `result.php?scan_id=...&outcome=...`
 *    evitando che refreshes/ricaricamenti del browser rieseguano il ciclo di verifica.
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
    $repo->register($uid);
    $scanId = $repo->logScan($uid, $result->readCounter, false, 'mac_invalid');
    respond(200, 'mac_invalid', ['uid' => $uid], $scanId);
}

// 2. Registrazione Tag se mai visto prima
$existing = $repo->find($uid);
if ($existing === null) {
    $repo->register($uid);
}

// 3. Controllo Tag Revocato
if ($repo->isRevoked($uid)) {
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'revoked');
    respond(200, 'revoked', ['uid' => $uid], $scanId);
}

// 4. Controllo Anti-Replay Contatore
$counterOk = $repo->checkAndAdvanceCounter($uid, $result->readCounter);

if (!$counterOk) {
    // Scansione duplicata / Replay
    $scanId = $repo->logScan($uid, $result->readCounter, true, 'replay');
    respond(200, 'replay_suspected', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
}

// 5. Scansione Valida e Autentica
$scanId = $repo->logScan($uid, $result->readCounter, true, 'valid');
respond(200, 'valid', ['uid' => $uid, 'counter' => $result->readCounter], $scanId);
