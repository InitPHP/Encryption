<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Integration;

use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Sodium;
use PHPUnit\Framework\TestCase;

/**
 * Verifies that ciphertext from one handler cannot be misinterpreted by the
 * other. Each handler has its own on-wire layout following the shared 2-byte
 * header; the rest of the bytes are not interchangeable.
 *
 * @requires extension openssl
 * @requires extension sodium
 */
final class CrossHandlerTest extends TestCase
{
    private const KEY = 'cross-handler-shared-key';

    public function testOpenSSLCannotDecryptSodiumCiphertext(): void
    {
        $sodium = new Sodium(['key' => self::KEY]);
        $openssl = new OpenSSL(['key' => self::KEY]);
        $ciphertext = $sodium->encrypt(['payload' => 'cross']);

        $this->expectException(EncryptionException::class);

        $openssl->decrypt($ciphertext);
    }

    public function testSodiumCannotDecryptOpenSSLCiphertext(): void
    {
        $openssl = new OpenSSL(['key' => self::KEY]);
        $sodium = new Sodium(['key' => self::KEY]);
        $ciphertext = $openssl->encrypt(['payload' => 'cross']);

        $this->expectException(EncryptionException::class);

        $sodium->decrypt($ciphertext);
    }
}
