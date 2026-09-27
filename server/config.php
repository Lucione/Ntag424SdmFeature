<?php
declare(strict_types=1);

// Copia questo file in config.php e valorizzalo. NON committare config.php:
// contiene le chiavi che, se rubate, permettono di clonare/falsificare i tag.

return [
    // Chiave usata SOLO per decifrare il PICCData (impostata su ChangeFileSettings
    // come chiave associata a SDMMetaRead). NON va diversificata per UID: serve
    // proprio a scoprire l'UID, quindi deve essere la stessa per tutti i tag
    // che condividono questo slot di chiave.
    'meta_read_key' => hex2bin('00112233445566778899AABBCCDDEEFF'),

    // Chiave master usata per il MAC dei dati dinamici (SDMFileRead).
    // Se 'diversify_file_read_key' è true, la chiave EFFETTIVA per ogni tag
    // sarà AN10922::aes128(fileReadMasterKey, uid, applicationId, systemIdentifier) -
    // deve essere IDENTICA a quella usata in fase di personalizzazione del tag
    // (vedi KeyInfo.generateKeyForCardUid() nell'app Android).
    'file_read_master_key' => hex2bin('00112233445566778899AABBCCDDEEFF'),
    'diversify_file_read_key' => true,

    // Devono combaciare esattamente con applicationId/systemIdentifier usati
    // in fase di personalizzazione (vedi KeyInfo.java nell'app Android).
    'application_id' => hex2bin('3042F5'),
    'system_identifier' => '',

    // Credenziali del database MySQL fornite da Altervista
    // (Pannello di controllo -> Database MySQL -> Amministra database).
    // Su Altervista nome db e utente coincidono di solito, del tipo "my_xxxxx".
    'db_host' => 'localhost', // alcuni account usano un host tipo "mysql.xxxxx.altervista.org"
    'db_name' => 'my_logicarts',
    'db_user' => 'logicarts',
    'db_pass' => '',
    'db_charset' => 'utf8mb4',
];
