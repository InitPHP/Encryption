<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Integration;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\OpenSSL;
use InitPHP\Encryption\Sodium;
use PHPUnit\Framework\TestCase;

/**
 * Documents the BC-break introduced in 2.0: ciphertexts produced by 1.x do
 * not carry a version byte, so feeding 1.x-shaped data into a 2.x handler
 * must produce a clear, recognisable error rather than a silent failure or
 * undefined behaviour.
 *
 * We cannot include real 1.x-produced ciphertexts without depending on the
 * 1.x release, so we synthesise input that LOOKS like 1.x output to a 2.x
 * parser: a hex-encoded blob whose first byte is something other than the
 * documented v2 magic.
 *
 * @requires extension openssl
 * @requires extension sodium
 */
final class LegacyFormatRejectionTest extends TestCase
{
    private const KEY = 'legacy-format-test-key';

    public function testOpenSSLRejectsV1ShapedCiphertext(): void
    {
        // Mimic 1.x output: hex-encoded blob without a 2-byte header, just
        // bytes whose first byte happens to be != FORMAT_VERSION.
        $fake = bin2hex(\chr(0x01) . random_bytes(64));

        $handler = new OpenSSL(['key' => self::KEY]);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unsupported ciphertext format version');

        $handler->decrypt($fake);
    }

    public function testSodiumRejectsV1ShapedCiphertext(): void
    {
        $fake = bin2hex(\chr(0x01) . random_bytes(64));

        $handler = new Sodium(['key' => self::KEY]);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unsupported ciphertext format version');

        $handler->decrypt($fake);
    }

    public function testErrorMessageGuidesUsersTowardsV2(): void
    {
        $fake = bin2hex(\chr(0x01) . random_bytes(64));
        $handler = new OpenSSL(['key' => self::KEY]);

        try {
            $handler->decrypt($fake);
            self::fail('expected EncryptionException for v1 input');
        } catch (EncryptionException $e) {
            $message = $e->getMessage();

            self::assertStringContainsString(\sprintf('0x%02x', BaseHandler::FORMAT_VERSION), $message);
            self::assertStringContainsString('1.x', $message);
        }
    }
}
