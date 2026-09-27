<?php
declare(strict_types=1);

namespace SunVerify;

/**
 * Diversificazione chiave AES-128 secondo NXP AN10922 §2.2.
 * DiversifiedKey = AES128-CMAC(masterKey, 0x01 || UID || AID || SystemIdentifier)
 *
 * Solo il caso a 128 bit è implementato: è quello usato da NTAG 424 DNA
 * per le chiavi applicative (SDMFileReadKey compresa).
 */
final class Diversify
{
    private const DIV_CONSTANT_128 = "\x01";

    /**
     * @param string $masterKey 16 byte, chiave master da diversificare
     * @param string $uid       7 byte, UID del tag
     * @param string $aid       byte dell'Application ID (usati solo come "sale" concordato)
     * @param string $systemIdentifier byte opzionali di identificazione sistema (può essere '')
     */
    public static function aes128(string $masterKey, string $uid, string $aid = '', string $systemIdentifier = ''): string
    {
        $input = self::DIV_CONSTANT_128 . $uid . $aid . $systemIdentifier;
        if (strlen($input) - 1 > 31) {
            // Limite AN10922 §2.2: M (senza la costante) può essere lungo al massimo 31 byte
            throw new \InvalidArgumentException('Input di diversificazione troppo lungo (max 31 byte per UID+AID+SystemIdentifier)');
        }
        return Cmac::generate($masterKey, $input);
    }
}
