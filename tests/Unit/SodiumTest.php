<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Unit;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\Sodium;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @requires extension sodium
 */
final class SodiumTest extends TestCase
{
    private const KEY = 'unit-test-secret-key';

    /**
     * @param array<string, mixed> $options
     */
    private function handler(array $options = []): Sodium
    {
        return new Sodium(['key' => self::KEY] + $options);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function jsonRoundTripProvider(): array
    {
        return [
            'string' => ['hello'],
            'utf8' => ['çığör — λ — 漢字'],
            'empty string' => [''],
            'int' => [42],
            'float' => [3.5],
            'true' => [true],
            'false' => [false],
            'null' => [null],
            'flat array' => [['a', 'b', 'c']],
            'nested assoc' => [['x' => 1, 'y' => ['z' => [1, 2]]]],
        ];
    }

    #[DataProvider('jsonRoundTripProvider')]
    public function testRoundTripUnderJsonSerializer(mixed $value): void
    {
        $handler = $this->handler(['serializer' => BaseHandler::SERIALIZER_JSON]);

        self::assertSame($value, $handler->decrypt($handler->encrypt($value)));
    }

    public function testRoundTripUnderPhpSerializerCarriesBinaryPayloads(): void
    {
        $handler = $this->handler(['serializer' => BaseHandler::SERIALIZER_PHP]);
        $value = "\x00\x01\x02\xff raw bytes";

        self::assertSame($value, $handler->decrypt($handler->encrypt($value)));
    }

    public function testCiphertextDiffersAcrossCalls(): void
    {
        $handler = $this->handler();
        $a = $handler->encrypt('same plaintext');
        $b = $handler->encrypt('same plaintext');

        self::assertNotSame($a, $b, 'random nonce should produce different ciphertexts');
    }

    public function testCiphertextIsHexEncoded(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        self::assertMatchesRegularExpression('/^[0-9a-f]+$/', $ciphertext);
    }

    public function testCiphertextStartsWithFormatVersionByte(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        self::assertSame(BaseHandler::FORMAT_VERSION, hexdec(substr($ciphertext, 0, 2)));
    }

    public function testKeyDerivationAcceptsArbitraryUserKeyLength(): void
    {
        // A 14-byte key (which is shorter than SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        // 1.x silently failed here, 2.x must derive a valid 32-byte key.
        $shortHandler = new Sodium(['key' => 'short-key-1234']);
        $longHandler = new Sodium(['key' => str_repeat('long-key-material-', 8)]);

        self::assertSame('hello', $shortHandler->decrypt($shortHandler->encrypt('hello')));
        self::assertSame('hello', $longHandler->decrypt($longHandler->encrypt('hello')));
    }

    public function testKeyDerivationIsDeterministicForSameUserKey(): void
    {
        $a = new Sodium(['key' => 'same-user-key']);
        $b = new Sodium(['key' => 'same-user-key']);
        $ciphertext = $a->encrypt('shared secret');

        self::assertSame('shared secret', $b->decrypt($ciphertext));
    }

    public function testDecryptRejectsTamperedCiphertext(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        // Flip the last byte.
        $lastBytePos = \strlen($ciphertext) - 2;
        $original = substr($ciphertext, $lastBytePos, 2);
        $flipped = \sprintf('%02x', hexdec($original) ^ 0xff);
        $tampered = substr_replace($ciphertext, $flipped, $lastBytePos, 2);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Sodium decryption failed');

        $handler->decrypt($tampered);
    }

    public function testDecryptRejectsNonHex(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('hex-encoded');

        $this->handler()->decrypt('not-hex-at-all-zzz');
    }

    public function testDecryptRejectsTruncated(): void
    {
        $this->expectException(EncryptionException::class);

        $this->handler()->decrypt(bin2hex(str_repeat("\x00", 10)));
    }

    public function testDecryptRejectsWrongVersionByte(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');
        $forged = '01' . substr($ciphertext, 2);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unsupported ciphertext format version');

        $handler->decrypt($forged);
    }

    public function testWrongKeyCannotDecrypt(): void
    {
        $encrypt = $this->handler();
        $ciphertext = $encrypt->encrypt('hello');
        $decrypt = new Sodium(['key' => 'a-different-secret']);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Sodium decryption failed');

        $decrypt->decrypt($ciphertext);
    }

    public function testEncryptRejectsMissingKey(): void
    {
        $handler = new Sodium();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('"key"');

        $handler->encrypt('hello');
    }

    public function testEncryptRejectsEmptyKey(): void
    {
        $handler = new Sodium(['key' => '']);

        $this->expectException(EncryptionException::class);

        $handler->encrypt('hello');
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function invalidBlocksizeProvider(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
            'float' => [16.5],
            'array' => [[16]],
            'non-numeric string' => ['sixteen'],
        ];
    }

    #[DataProvider('invalidBlocksizeProvider')]
    public function testEncryptRejectsInvalidBlocksize(mixed $blocksize): void
    {
        $handler = $this->handler(['blocksize' => $blocksize]);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('blocksize');

        $handler->encrypt('hello');
    }

    public function testBlocksizeAcceptsStringDigits(): void
    {
        $handler = $this->handler(['blocksize' => '32']);

        self::assertSame('hello', $handler->decrypt($handler->encrypt('hello')));
    }

    public function testExplicitNullBlocksizeFallsBackToDefault(): void
    {
        // null is treated as "use default" via the ?? operator. This is a
        // deliberate PHP idiom; pass a real invalid value (0, -1, ...) if
        // you want to surface a configuration error.
        $handler = $this->handler(['blocksize' => null]);

        self::assertSame('hello', $handler->decrypt($handler->encrypt('hello')));
    }

    public function testPerCallOptionsDoNotMutateHandlerState(): void
    {
        $handler = $this->handler(['blocksize' => 16]);
        $handler->encrypt('x', ['blocksize' => 64]);

        self::assertSame(16, $handler->getOption('blocksize'));
    }

    public function testJsonIsTheDefaultSerializer(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        self::assertSame(0x00, hexdec(substr($ciphertext, 2, 2)));
    }

    public function testPhpSerializerIsOptIn(): void
    {
        $handler = $this->handler(['serializer' => BaseHandler::SERIALIZER_PHP]);
        $ciphertext = $handler->encrypt('hello');

        self::assertSame(0x01, hexdec(substr($ciphertext, 2, 2)));
    }
}
