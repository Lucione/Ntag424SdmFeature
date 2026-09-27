<?php
declare(strict_types=1);

namespace SunVerify;

final class TagRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /** Ritorna la riga del tag, oppure null se non è mai stato visto prima. */
    public function find(string $uidHex): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM tags WHERE uid_hex = :uid');
        $stmt->execute(['uid' => strtolower(trim($uidHex))]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /** Registra un tag mai visto prima come 'active' con contatore -1. */
    public function register(string $uidHex, ?string $label = null): void
    {
        $stmt = $this->pdo->prepare(
            "INSERT IGNORE INTO tags (uid_hex, label, status, last_counter) VALUES (:uid, :label, 'active', -1)"
        );
        $stmt->execute(['uid' => strtolower(trim($uidHex)), 'label' => $label]);
    }

    /**
     * Aggiunge o aggiorna (UPSERT) i dati di un tag nel database MySQL.
     * Permette la gestione del ciclo di vita: aggiornamento etichetta, cambio stato ('active' / 'revoked')
     * e risincronizzazione dell'ultimo contatore di lettura.
     */
    public function upsertTag(
        string $uidHex,
        ?string $label = null,
        string $status = 'active',
        int $lastCounter = -1
    ): void {
        $uidHex = strtolower(trim($uidHex));
        $sql = "INSERT INTO tags (uid_hex, label, status, last_counter, first_seen_at)
                VALUES (:uid, :label, :status, :last_counter, NOW())
                ON DUPLICATE KEY UPDATE
                    label        = IF(:label_update IS NOT NULL AND :label_update != '', :label_update2, label),
                    status       = VALUES(status),
                    last_counter = GREATEST(last_counter, VALUES(last_counter)),
                    last_seen_at = IF(VALUES(last_counter) >= 0, NOW(), last_seen_at)";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'uid'           => $uidHex,
            'label'         => $label,
            'status'        => $status,
            'last_counter'  => $lastCounter,
            'label_update'  => $label,
            'label_update2' => $label,
        ]);
    }

    /**
     * Verifica anti-replay: accetta la scansione solo se $counter è STRETTAMENTE
     * maggiore dell'ultimo contatore accettato per questo UID, e in tal caso
     * aggiorna last_counter. Ritorna false in caso di replay/clone sospetto.
     *
     * Usa una transazione per evitare race condition fra due richieste
     * concorrenti sullo stesso UID (es. due tap quasi simultanei).
     */
    public function checkAndAdvanceCounter(string $uidHex, int $counter): bool
    {
        $uidHex = strtolower(trim($uidHex));
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('SELECT last_counter FROM tags WHERE uid_hex = :uid FOR UPDATE');
            $stmt->execute(['uid' => $uidHex]);
            $lastCounter = $stmt->fetchColumn();

            if ($lastCounter === false) {
                // Non dovrebbe succedere se register() è stata chiamata prima, ma per sicurezza:
                $lastCounter = -1;
            }

            if ($counter <= (int)$lastCounter) {
                $this->pdo->rollBack();
                return false; // replay o contatore non avanzato: sospetto
            }

            $update = $this->pdo->prepare(
                'UPDATE tags SET last_counter = :counter, last_seen_at = NOW() WHERE uid_hex = :uid'
            );
            $update->execute(['counter' => $counter, 'uid' => $uidHex]);

            $this->pdo->commit();
            return true;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function isRevoked(string $uidHex): bool
    {
        $row = $this->find($uidHex);
        return $row !== null && $row['status'] === 'revoked';
    }

    /** Registra la scansione nella tabella `scan_log` e restituisce l'ID del log generato (`scan_id`). */
    public function logScan(string $uidHex, ?int $counter, bool $macValid, string $outcome): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO scan_log (uid_hex, counter, mac_valid, outcome, ip, user_agent)
             VALUES (:uid, :counter, :mac_valid, :outcome, :ip, :ua)'
        );
        $stmt->execute([
            'uid' => strtolower(trim($uidHex)),
            'counter' => $counter,
            'mac_valid' => $macValid ? 1 : 0,
            'outcome' => $outcome,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    /** Recupera i dettagli di una scansione salvata per ID e unisce le informazioni del tag (label). */
    public function getScanLog(int $scanId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT s.*, t.label, t.status AS tag_status
             FROM scan_log s
             LEFT JOIN tags t ON s.uid_hex = t.uid_hex
             WHERE s.id = :id'
        );
        $stmt->execute(['id' => $scanId]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }
}
