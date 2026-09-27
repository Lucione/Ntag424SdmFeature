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
        $stmt->execute(['uid' => $uidHex]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /** Registra un tag mai visto prima come 'active' con contatore -1. */
    public function register(string $uidHex, ?string $label = null): void
    {
        $stmt = $this->pdo->prepare(
            "INSERT IGNORE INTO tags (uid_hex, label, status, last_counter) VALUES (:uid, :label, 'active', -1)"
        );
        $stmt->execute(['uid' => $uidHex, 'label' => $label]);
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
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('SELECT last_counter FROM tags WHERE uid_hex = :uid');
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

    public function logScan(string $uidHex, ?int $counter, bool $macValid, string $outcome): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO scan_log (uid_hex, counter, mac_valid, outcome, ip, user_agent)
             VALUES (:uid, :counter, :mac_valid, :outcome, :ip, :ua)'
        );
        $stmt->execute([
            'uid' => $uidHex,
            'counter' => $counter,
            'mac_valid' => $macValid ? 1 : 0,
            'outcome' => $outcome,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        ]);
    }
}
