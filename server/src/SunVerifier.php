<?php
declare(strict_types=1);

namespace SunVerify;

final class SunVerificationResult
{
    public function __construct(
        public readonly bool $macValid,
        public readonly string $uidHex,
        public readonly int $readCounter,
    ) {
    }
}

/**
 * Verifica messaggi SUN (Secure Unique NFC) prodotti dalla Secure Dynamic
 * Messaging di NTAG 424 DNA, in modalità AES (non LRP).
 *
 * Presuppone la configurazione più comune per anticontraffazione:
 *  - PICCData mirrorato CIFRATO (SDMMetaRead = 0h..4h), contiene UID + SDMReadCtr
 *  - SDMMAC calcolato con SDMFileReadKey (eventualmente diversificata per UID)
 *  - Nessun dato di file aggiuntivo cifrato (SDMENCFileData disabilitato);
 *    se lo abiliti, vedi il metodo decryptFileData() più sotto.
 */
final class SunVerifier
{
    public function __construct(
        /** Chiave usata SOLO per decifrare PICCData (NON diversificata: serve a scoprire l'UID). */
        private readonly string $metaReadKey,
        /** Chiave master usata per il MAC dei dati dinamici (SDMFileReadKey). */
        private readonly string $fileReadMasterKey,
        /** Se true, la SDMFileReadKey effettiva è AN10922::aes128($fileReadMasterKey, uid, aid, sysId). */
        private readonly bool $diversifyFileReadKey = true,
        private readonly string $applicationId = '',
        private readonly string $systemIdentifier = '',
    ) {
    }

    /**
     * Decifra il blocco PICCData (16 byte, AES-CBC con IV zero - equivalente
     * a un singolo blocco ECB) e ne estrae UID e SDMReadCtr.
     * Rif. datasheet NT4H2421Gx §9.3.3/9.3.4.
     */
    public function decryptPiccData(string $piccDataRaw): array
    {
        if (strlen($piccDataRaw) !== 16) {
            throw new \InvalidArgumentException('PICCData deve essere di 16 byte');
        }
        $plain = openssl_decrypt(
            $piccDataRaw,
            'aes-128-cbc',
            $this->metaReadKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            str_repeat("\x00", 16)
        );
        if ($plain === false) {
            throw new \RuntimeException('Decifratura PICCData fallita');
        }

        $tag = ord($plain[0]);
        $hasUid = (bool)($tag & 0b1000_0000);
        $hasCtr = (bool)($tag & 0b0100_0000);
        $uidLen = $tag & 0b0000_1111;

        $offset = 1;
        $uid = '';
        if ($hasUid) {
            $uid = substr($plain, $offset, $uidLen);
            $offset += $uidLen;
        }
        $counter = 0;
        if ($hasCtr) {
            $ctrBytes = substr($plain, $offset, 3);
            // SDMReadCtr è LSB-first sull'interfaccia binaria (datasheet §9.3.1)
            $counter = ord($ctrBytes[0]) | (ord($ctrBytes[1]) << 8) | (ord($ctrBytes[2]) << 16);
        }

        return [
            'hasUid' => $hasUid,
            'hasCounter' => $hasCtr,
            'uid' => $uid,
            'counter' => $counter,
        ];
    }

    /** Costruisce SV2 e deriva SesSDMFileReadMACKey (datasheet §9.3.9.1). */
    private function deriveMacSessionKey(string $fileReadKey, string $uid, int $counter): string
    {
        $ctrBytes = chr($counter & 0xFF) . chr(($counter >> 8) & 0xFF) . chr(($counter >> 16) & 0xFF);
        $sv2 = "\x3c\xc3\x00\x01\x00\x80" . $uid . $ctrBytes;
        // Con UID a 7 byte + counter a 3 byte, SV2 è già esattamente 16 byte: nessun padding necessario.
        if (strlen($sv2) < 16) {
            $sv2 = str_pad($sv2, 16, "\x00");
        }
        return Cmac::generate($fileReadKey, $sv2);
    }

    /**
     * Verifica completa: decifra PICCData, deriva la chiave di sessione,
     * calcola l'SDMMAC atteso e lo confronta con quello ricevuto dal tag.
     *
     * @param string $piccDataHex hex del parametro `picc_data` nella URL
     * @param string $cmacHex     hex del parametro `cmac` nella URL (8 byte)
     * @param string $dynamicData byte "in chiaro" coperti dal MAC oltre a PICCData
     *                            (vuoto se non usi SDMENCFileData / mirroring extra)
     */
    public function verify(string $piccDataHex, string $cmacHex, string $dynamicData = ''): SunVerificationResult
    {
        $piccDataRaw = $this->hexToBin($piccDataHex, 16, 'picc_data');
        $cmacRaw = $this->hexToBin($cmacHex, 8, 'cmac');

        $picc = $this->decryptPiccData($piccDataRaw);
        if (!$picc['hasUid'] || !$picc['hasCounter']) {
            // Per l'uso anticontraffazione servono entrambi: senza non c'è nulla da tracciare
            return new SunVerificationResult(false, bin2hex($picc['uid']), $picc['counter']);
        }

        $fileReadKey = $this->diversifyFileReadKey
            ? Diversify::aes128($this->fileReadMasterKey, $picc['uid'], $this->applicationId, $this->systemIdentifier)
            : $this->fileReadMasterKey;

        $macKey = $this->deriveMacSessionKey($fileReadKey, $picc['uid'], $picc['counter']);
        $fullMac = Cmac::generate($macKey, $dynamicData);
        $expectedShort = Cmac::shorten($fullMac);

        $valid = hash_equals($expectedShort, $cmacRaw);

        return new SunVerificationResult($valid, bin2hex($picc['uid']), $picc['counter']);
    }

    private function hexToBin(string $hex, int $expectedLen, string $fieldName): string
    {
        $hex = trim($hex);
        if (!ctype_xdigit($hex) || strlen($hex) !== $expectedLen * 2) {
            throw new \InvalidArgumentException("Parametro '$fieldName' non valido (atteso hex di $expectedLen byte)");
        }
        return hex2bin($hex);
    }
}
