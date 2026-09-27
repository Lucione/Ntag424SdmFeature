<?php
declare(strict_types=1);

/**
 * Pagina di visualizzazione dell'esito della verifica NFC per il consumatore.
 * Invocata via Redirect PRG da `verify.php?scan_id=...&outcome=...`
 *
 * Se l'utente ricarica la scheda o aggiorna la pagina nel browser,
 * questa pagina si limita a rileggere il record `scan_log` senza rieseguire
 * il ciclo di verifica, prevenendo falsi allarmi di Replay!
 */

require __DIR__ . '/src/TagRepository.php';

use SunVerify\TagRepository;

$scanId = isset($_GET['scan_id']) ? (int)$_GET['scan_id'] : 0;
$outcome = $_GET['outcome'] ?? 'unknown';

$scanData = null;
if ($scanId > 0) {
    $config = require __DIR__ . '/config.php';
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
        $repo = new TagRepository($pdo);
        $scanData = $repo->getScanLog($scanId);
    } catch (\Throwable $e) {
        // Gestione errore silenziosa
    }
}

// Mappatura degli esiti in configurazione visiva (Bollini di Autenticità)
$statusConfigs = [
    'valid' => [
        'badge_class'  => 'status-valid',
        'icon'         => '✓',
        'title'        => 'Prodotto Autentico e Verificato',
        'subtitle'     => 'Firma digitale crittografica NTAG 424 DNA valida',
        'description'  => 'Il chip NFC fisico è originale ed è stato verificato con successo dal server di sicurezza.',
        'color'        => '#10b981',
    ],
    'replay' => [
        'badge_class'  => 'status-warning',
        'icon'         => '⚠',
        'title'        => 'Attenzione: Scansione Duplicata',
        'subtitle'     => 'URL NFC già utilizzata in precedenza (Anti-Replay)',
        'description'  => 'Questa specifica scansione è già stata aperta in precedenza o la pagina è stata ricaricata. Per verificare nuovamente il prodotto, sfiora nuovamente il tag con il telefono.',
        'color'        => '#f59e0b',
    ],
    'replay_suspected' => [
        'badge_class'  => 'status-warning',
        'icon'         => '⚠',
        'title'        => 'Attenzione: Scansione Duplicata',
        'subtitle'     => 'URL NFC già utilizzata in precedenza (Anti-Replay)',
        'description'  => 'Questa specifica scansione è già stata aperta in precedenza o la pagina è stata ricaricata. Per verificare nuovamente il prodotto, sfiora nuovamente il tag con il telefono.',
        'color'        => '#f59e0b',
    ],
    'mac_invalid' => [
        'badge_class'  => 'status-invalid',
        'icon'         => '✕',
        'title'        => 'Prodotto Non Autentico',
        'subtitle'     => 'Firma crittografica NTAG 424 non valida',
        'description'  => 'La firma elettronica ricevuta non corrisponde. Il tag potrebbe essere un clone non autorizzato o modificato.',
        'color'        => '#ef4444',
    ],
    'revoked' => [
        'badge_class'  => 'status-invalid',
        'icon'         => '⛔',
        'title'        => 'Tag Revocato o Bloccato',
        'subtitle'     => 'Prodotto segnalato come ritirato o revocato',
        'description'  => 'Questo seriale risulta registrato ma revocato nel sistema centrale di sicurezza.',
        'color'        => '#ef4444',
    ],
    'missing_params' => [
        'badge_class'  => 'status-invalid',
        'icon'         => '?',
        'title'        => 'Parametri Scansione Mancanti',
        'subtitle'     => 'Impossibile completare la verifica',
        'description'  => 'L\'URL aperta non contiene i parametri crittografici necessari.',
        'color'        => '#6b7280',
    ],
    'unknown' => [
        'badge_class'  => 'status-invalid',
        'icon'         => '?',
        'title'        => 'Esito Scansione Non Disponibile',
        'subtitle'     => 'Impossibile determinare lo stato',
        'description'  => 'Si è verificato un problema durante il recupero dei dati di scansione.',
        'color'        => '#6b7280',
    ]
];

$effectiveOutcome = $scanData['outcome'] ?? $outcome;
$cfg = $statusConfigs[$effectiveOutcome] ?? $statusConfigs['unknown'];

$uidHex = $scanData['uid_hex'] ?? $_GET['uid'] ?? 'N/A';
$counter = $scanData['counter'] ?? 'N/A';
$label = !empty($scanData['label']) ? $scanData['label'] : 'Prodotto NTAG 424 DNA';
$createdAt = $scanData['created_at'] ?? date('Y-m-d H:i:s');
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifica Autenticità NTAG 424 DNA</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            background-color: #f3f4f6;
            color: #1f2937;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 16px;
        }

        .card {
            background-color: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
            max-width: 450px;
            width: 100%;
            overflow: hidden;
            text-align: center;
        }

        .header {
            padding: 32px 24px 24px 24px;
            background: linear-gradient(180deg, rgba(255,255,255,0.8) 0%, rgba(249,250,251,1) 100%);
            border-bottom: 1px solid #e5e7eb;
        }

        .badge-icon {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0 auto 16px auto;
            font-size: 40px;
            color: #ffffff;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .status-valid .badge-icon { background-color: #10b981; }
        .status-warning .badge-icon { background-color: #f59e0b; }
        .status-invalid .badge-icon { background-color: #ef4444; }

        .title {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 6px;
            color: #111827;
        }

        .subtitle {
            font-size: 14px;
            color: #6b7280;
            font-weight: 500;
        }

        .body-content {
            padding: 24px;
        }

        .description {
            font-size: 14px;
            line-height: 1.5;
            color: #374151;
            background-color: #f9fafb;
            padding: 14px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #f3f4f6;
        }

        .info-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 12px;
            text-align: left;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 12px;
            background-color: #f8fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }

        .info-label {
            font-size: 13px;
            color: #64748b;
            font-weight: 600;
        }

        .info-value {
            font-size: 13px;
            color: #0f172a;
            font-weight: 700;
            font-family: monospace;
        }

        .footer {
            padding: 16px 24px;
            background-color: #f8fafc;
            border-top: 1px solid #e2e8f0;
            font-size: 12px;
            color: #94a3b8;
        }
    </style>
</head>
<body>

<div class="card <?= htmlspecialchars($cfg['badge_class']) ?>">
    <div class="header">
        <div class="badge-icon">
            <?= htmlspecialchars($cfg['icon']) ?>
        </div>
        <h1 class="title"><?= htmlspecialchars($cfg['title']) ?></h1>
        <p class="subtitle"><?= htmlspecialchars($cfg['subtitle']) ?></p>
    </div>

    <div class="body-content">
        <p class="description">
            <?= htmlspecialchars($cfg['description']) ?>
        </p>

        <div class="info-grid">
            <div class="info-row">
                <span class="info-label">Prodotto / Etichetta</span>
                <span class="info-value"><?= htmlspecialchars($label) ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">UID Hardware Tag</span>
                <span class="info-value"><?= htmlspecialchars(strtoupper($uidHex)) ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Contatore Lettura</span>
                <span class="info-value">#<?= htmlspecialchars((string)$counter) ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Data e Ora Scansione</span>
                <span class="info-value"><?= htmlspecialchars($createdAt) ?></span>
            </div>
        </div>
    </div>

    <div class="footer">
        NTAG 424 DNA Security Verification • LogicArts
    </div>
</div>

</body>
</html>
