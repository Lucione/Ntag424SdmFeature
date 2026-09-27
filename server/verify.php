<?php
declare(strict_types=1);
ini_set('display_errors', '1'); 
error_reporting(E_ALL);

/**
 * Endpoint chiamato dal browser del consumatore quando legge il tag con
 * il proprio telefono (lettura NFC nativa -> apertura URL -> questa pagina).
 * URL attesa: https://tuodominio/verify.php?picc_data=<hex>&cmac=<hex>
 * (i nomi dei parametri devono combaciare con i placeholder {PICC} e {MAC}
 * usati in NdefTemplateMaster lato Android).
 */

require __DIR__ . '/src/Cmac.php';
require __DIR__ . '/src/Diversify.php';
require __DIR__ . '/src/SunVerifier.php';
require __DIR__ . '/src/TagRepository.php';

use SunVerify\SunVerifier;
use SunVerify\TagRepository;

header('Content-Type: application/json; charset=utf-8');

function respond(int $httpStatus, string $outcome, array $extra = []): never
{
    http_response_code($httpStatus);
    echo json_encode(array_merge(['outcome' => $outcome], $extra), JSON_UNESCAPED_SLASHES);
    exit;
}

$config = require __DIR__ . '/config.php';

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
    // Non esporre credenziali/dettagli di connessione in produzione; loggare $e altrove.
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
    // Non esporre dettagli interni in produzione; loggare $e altrove.
    respond(500, 'internal_error');
}

$uid = $result->uidHex;

if (!$result->macValid) {
    $repo->register($uid); // registriamo comunque l'UID visto, anche se il MAC non torna
    $repo->logScan($uid, $result->readCounter, false, 'mac_invalid');
    respond(200, 'mac_invalid', ['uid' => $uid]);
}

$existing = $repo->find($uid);
if ($existing === null) {
    $repo->register($uid);
}

if ($repo->isRevoked($uid)) {
    $repo->logScan($uid, $result->readCounter, true, 'revoked');
    respond(200, 'revoked', ['uid' => $uid]);
}

$counterOk = $repo->checkAndAdvanceCounter($uid, $result->readCounter);

if (!$counterOk) {
    // MAC valido ma contatore non avanzato: probabile scansione duplicata,
    // URL rigiocata, o clone che condivide chiave e stato ma non il counter reale.
    $repo->logScan($uid, $result->readCounter, true, 'replay');
    respond(200, 'replay_suspected', ['uid' => $uid, 'counter' => $result->readCounter]);
}

$repo->logScan($uid, $result->readCounter, true, 'valid');
respond(200, 'valid', ['uid' => $uid, 'counter' => $result->readCounter]);
