-- Schema MySQL/MariaDB per la verifica anticontraffazione basata su SUN/SDM.
-- Crea il database con:
--   mysql -u utente -p nome_db < schema.sql

CREATE TABLE IF NOT EXISTS tags (
    uid_hex       CHAR(14)     NOT NULL,              -- UID del tag, 7 byte in hex minuscolo
    label         VARCHAR(255) DEFAULT NULL,          -- riferimento interno (lotto, prodotto, ecc.)
    status        ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
    last_counter  INT          NOT NULL DEFAULT -1,   -- ultimo SDMReadCtr accettato
    first_seen_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  DATETIME     DEFAULT NULL,
    PRIMARY KEY (uid_hex)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    uid_hex     CHAR(14)     NOT NULL,
    counter     INT          DEFAULT NULL,
    mac_valid   TINYINT(1)   NOT NULL,                -- 0/1
    outcome     ENUM('valid', 'mac_invalid', 'replay', 'unknown_format', 'revoked') NOT NULL,
    ip          VARCHAR(45)  DEFAULT NULL,             -- IPv4 o IPv6
    user_agent  VARCHAR(512) DEFAULT NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_scan_log_uid (uid_hex),
    KEY idx_scan_log_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
