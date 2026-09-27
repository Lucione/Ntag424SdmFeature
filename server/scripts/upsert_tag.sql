-- ============================================================================
-- SCRIPT MYSQL: Aggiunta e Aggiornamento Tag (Upsert & Lifecycle Management)
-- Progetto: NTAG 424 DNA SUN/SDM Verification Backend
-- Tabella Target: tags (schema.sql)
-- ============================================================================

USE `my_logicarts`; -- Sostituire con il nome del DB se differente (es. config.php)

DELIMITER //

-- ----------------------------------------------------------------------------
-- PROCEDURE ALMACENATA: sp_upsert_tag
-- Descrizione: Inserisce un nuovo tag NTAG 424 DNA se non esiste, oppure ne
--              aggiorna l'etichetta (label), lo stato (active/pending/revoked) e/o
--              il contatore di lettura (last_counter).
-- Parametri:
--   p_uid_hex      : UID del chip NTAG 424 DNA (7 byte / 14 caratteri HEX)
--   p_label        : Etichetta/Lotto/Descrizione prodotto associato
--   p_status       : Stato del tag ('active', 'pending', 'revoked')
--   p_last_counter : Ultimo SDMReadCtr registrato/accettato (-1 per default nuovo tag)
-- ----------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS `sp_upsert_tag` //

CREATE PROCEDURE `sp_upsert_tag`(
    IN p_uid_hex       CHAR(14),
    IN p_label         VARCHAR(255),
    IN p_status        ENUM('active', 'pending', 'revoked'),
    IN p_last_counter  INT
)
BEGIN
    -- Normalizza l'UID in minuscolo per consistenza di ricerca
    SET p_uid_hex = LOWER(TRIM(p_uid_hex));

    -- Se p_status è NULL, imposta il default 'pending' (richiede abilitazione backend)
    IF p_status IS NULL THEN
        SET p_status = 'pending';
    END IF;

    -- Se p_last_counter è NULL, imposta il default -1
    IF p_last_counter IS NULL THEN
        SET p_last_counter = -1;
    END IF;

    -- Esegue l'UPSERT (INSERT ... ON DUPLICATE KEY UPDATE)
    INSERT INTO `tags` (
        `uid_hex`,
        `label`,
        `status`,
        `last_counter`,
        `first_seen_at`,
        `last_seen_at`
    ) VALUES (
        p_uid_hex,
        p_label,
        p_status,
        p_last_counter,
        NOW(),
        IF(p_last_counter >= 0, NOW(), NULL)
    )
    ON DUPLICATE KEY UPDATE
        `label`        = IF(p_label IS NOT NULL AND p_label != '', p_label, `tags`.`label`),
        `status`       = p_status,
        `last_counter` = GREATEST(`tags`.`last_counter`, p_last_counter),
        `last_seen_at` = IF(p_last_counter >= 0, NOW(), `tags`.`last_seen_at`);

    -- Restituisce lo stato aggiornato del tag
    SELECT
        `uid_hex`,
        `label`,
        `status`,
        `last_counter`,
        `first_seen_at`,
        `last_seen_at`
    FROM `tags`
    WHERE `uid_hex` = p_uid_hex;
END //

DELIMITER ;

-- ============================================================================
-- ESEMPI PRATICI DI UTILIZZO E ISTRUZIONI SQL DIRETTE
-- ============================================================================

-- 1. ESEMPIO CHIAMATA PROCEDURA: Registrazione nuovo tag (in stato 'pending' in attesa di abilitazione)
-- CALL sp_upsert_tag('049f50824f1390', 'Lotto Vino 2024 - Bottiglia #001', 'pending', -1);

-- 2. ESEMPIO CHIAMATA PROCEDURA: Abilitazione / Attivazione tag dal Backend
-- CALL sp_upsert_tag('049f50824f1390', 'Lotto Vino 2024 - Bottiglia #001 (Attivato)', 'active', -1);

-- 3. ESEMPIO CHIAMATA PROCEDURA: Revoca di un tag rubato o compromesso
-- CALL sp_upsert_tag('049f50824f1390', NULL, 'revoked', -1);

-- ----------------------------------------------------------------------------
-- 4. ISTRUZIONE SQL UPSERT DIRETTA PER ATTIVAZIONE DA BACKEND
-- ----------------------------------------------------------------------------
/*
UPDATE `tags` SET `status` = 'active', `label` = 'Prodotto Verificato e Attivato' WHERE `uid_hex` = '049f50824f1390';
*/
