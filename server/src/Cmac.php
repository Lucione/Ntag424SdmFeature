<?php
declare(strict_types=1);

namespace SunVerify;

/**
 * AES-128 CMAC (NIST SP800-38B / RFC 4493).
 * Nessuna libreria PHP standard offre CMAC: viene costruito sopra
 * AES-128-ECB (usato solo come cifratura di singolo blocco, mai in
 * modalità ECB "vera" su dati multi-blocco).
 */
final class Cmac
{
    private const BLOCK = 16;
    private const RB = 0x87; // Costante di riduzione per GF(2^128), AES a blocchi da 128 bit

    /** Cifra un singolo blocco di 16 byte con AES-128 (nessun padding, nessun IV). */
    private static function aesEncryptBlock(string $key, string $block): string
    {
        $out = openssl_encrypt(
            $block,
            'aes-128-ecb',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        if ($out === false || strlen($out) !== self::BLOCK) {
            throw new \RuntimeException('Errore cifratura AES');
        }
        return $out;
    }

    private static function xor16(string $a, string $b): string
    {
        return $a ^ $b; // PHP fa XOR byte-a-byte su stringhe di uguale lunghezza
    }

    /** Shift a sinistra di 1 bit su una stringa di byte, con riporto separato. */
    private static function shiftLeft1WithCarry(string $s): array
    {
        $len = strlen($s);
        $out = str_repeat("\x00", $len);
        $carry = 0;
        for ($i = $len - 1; $i >= 0; $i--) {
            $b = ord($s[$i]);
            $out[$i] = chr((($b << 1) | $carry) & 0xFF);
            $carry = ($b & 0x80) ? 1 : 0;
        }
        return [$out, $carry];
    }

    /** Genera le due subkey K1, K2 secondo RFC 4493 §2.3. */
    private static function generateSubkeys(string $key): array
    {
        $zero = str_repeat("\x00", self::BLOCK);
        $l = self::aesEncryptBlock($key, $zero);

        [$k1, $carry1] = self::shiftLeft1WithCarry($l);
        if ($carry1) {
            $k1[self::BLOCK - 1] = chr(ord($k1[self::BLOCK - 1]) ^ self::RB);
        }

        [$k2, $carry2] = self::shiftLeft1WithCarry($k1);
        if ($carry2) {
            $k2[self::BLOCK - 1] = chr(ord($k2[self::BLOCK - 1]) ^ self::RB);
        }

        return [$k1, $k2];
    }

    /**
     * Calcola il CMAC completo a 16 byte di $message con la chiave AES-128 $key.
     * $key e il risultato sono stringhe binarie di byte grezzi (non hex).
     */
    public static function generate(string $key, string $message): string
    {
        if (strlen($key) !== self::BLOCK) {
            throw new \InvalidArgumentException('La chiave CMAC deve essere di 16 byte (AES-128)');
        }

        [$k1, $k2] = self::generateSubkeys($key);

        $len = strlen($message);
        $n = intdiv($len + self::BLOCK - 1, self::BLOCK); // numero di blocchi, arrotondato per eccesso
        $n = max($n, 1); // anche il messaggio vuoto occupa un blocco (verrà paddato)

        $completeLastBlock = ($len > 0) && ($len % self::BLOCK === 0);

        // Estrae l'ultimo blocco e lo prepara (padding + XOR con K1/K2)
        if ($completeLastBlock) {
            $lastBlock = substr($message, ($n - 1) * self::BLOCK, self::BLOCK);
            $lastBlock = self::xor16($lastBlock, $k1);
        } else {
            $lastBlockRaw = substr($message, ($n - 1) * self::BLOCK);
            $padded = $lastBlockRaw . "\x80" . str_repeat("\x00", self::BLOCK - strlen($lastBlockRaw) - 1);
            $lastBlock = self::xor16($padded, $k2);
        }

        $x = str_repeat("\x00", self::BLOCK);
        for ($i = 0; $i < $n - 1; $i++) {
            $block = substr($message, $i * self::BLOCK, self::BLOCK);
            $x = self::aesEncryptBlock($key, self::xor16($x, $block));
        }
        $x = self::aesEncryptBlock($key, self::xor16($x, $lastBlock));

        return $x;
    }

    /**
     * Tronca un CMAC a 16 byte agli 8 byte "pari" richiesti da NTAG 424 DNA:
     * i byte con indice dispari (0-based) del CMAC completo, cioè i byte
     * 2°, 4°, 6°... in numerazione a partire da 1 (vedi AN12196 pag. 21).
     */
    public static function shorten(string $fullCmac): string
    {
        if (strlen($fullCmac) !== self::BLOCK) {
            throw new \InvalidArgumentException('shorten() richiede un CMAC di 16 byte');
        }
        $out = '';
        for ($i = 1; $i < self::BLOCK; $i += 2) {
            $out .= $fullCmac[$i];
        }
        return $out;
    }
}
