<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Unit;

use InitPHP\Encryption\BaseHandler;
use InitPHP\Encryption\Exceptions\EncryptionException;
use InitPHP\Encryption\OpenSSL;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @requires extension openssl
 */
final class OpenSSLTest extends TestCase
{
    private const KEY = 'unit-test-secret-key';

    /**
     * @param array<string, mixed> $options
     */
    private function handler(array $options = []): OpenSSL
    {
        return new OpenSSL(['key' => self::KEY] + $options);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function jsonRoundTripProvider(): array
    {
        return [
            'string' => ['hello, world'],
            'utf8' => ['çığör — λ — 漢字'],
            'empty string' => [''],
            'int' => [42],
            'negative int' => [-1],
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
        $ciphertext = $handler->encrypt($value);

        self::assertSame($value, $handler->decrypt($ciphertext));
    }

    public function testRoundTripUnderPhpSerializer(): void
    {
        $handler = $this->handler(['serializer' => BaseHandler::SERIALIZER_PHP]);
        // php_serialize is 8-bit clean, so binary survives.
        $value = "\x00\x01\x02\xff raw bytes";

        self::assertSame($value, $handler->decrypt($handler->encrypt($value)));
    }

    public function testCiphertextDiffersAcrossCalls(): void
    {
        $handler = $this->handler();
        $a = $handler->encrypt('same plaintext');
        $b = $handler->encrypt('same plaintext');

        self::assertNotSame($a, $b, 'random IV should produce different ciphertexts');
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
        $firstByte = hexdec(substr($ciphertext, 0, 2));

        self::assertSame(BaseHandler::FORMAT_VERSION, $firstByte);
    }

    public function testPerCallOptionsDoNotMutateHandlerState(): void
    {
        $handler = $this->handler(['cipher' => 'AES-256-CTR']);
        $handler->encrypt('x', ['cipher' => 'AES-128-CTR']);

        self::assertSame('AES-256-CTR', $handler->getOption('cipher'));
    }

    public function testDecryptRejectsTamperedCiphertext(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        // Flip the last byte to corrupt the ciphertext.
        $lastBytePos = \strlen($ciphertext) - 2;
        $original = substr($ciphertext, $lastBytePos, 2);
        $flipped = \sprintf('%02x', hexdec($original) ^ 0xff);
        $tampered = substr_replace($ciphertext, $flipped, $lastBytePos, 2);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('HMAC verification failed');

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

        $this->handler()->decrypt('ab');
    }

    public function testDecryptRejectsWrongVersionByte(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');

        // Replace the first byte (version) with 0x01 (v1).
        $forged = '01' . substr($ciphertext, 2);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unsupported ciphertext format version');

        $handler->decrypt($forged);
    }

    public function testDecryptRejectsTooShortForCipher(): void
    {
        $handler = $this->handler();
        // Valid header (2 bytes) but no HMAC/IV/ciphertext at all.
        $tooShort = bin2hex(\chr(BaseHandler::FORMAT_VERSION) . \chr(0x00));

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('too short');

        $handler->decrypt($tooShort);
    }

    public function testEncryptRejectsMissingKey(): void
    {
        $handler = new OpenSSL();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('"key"');

        $handler->encrypt('hello');
    }

    public function testEncryptRejectsEmptyKey(): void
    {
        $handler = new OpenSSL(['key' => '']);

        $this->expectException(EncryptionException::class);

        $handler->encrypt('hello');
    }

    public function testEncryptRejectsUnknownCipher(): void
    {
        $handler = $this->handler(['cipher' => 'no-such-cipher-xyz']);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown OpenSSL cipher');

        $handler->encrypt('hello');
    }

    public function testEncryptRejectsUnknownAlgo(): void
    {
        $handler = $this->handler(['algo' => 'no-such-algo']);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown HMAC hashing algorithm');

        $handler->encrypt('hello');
    }

    public function testJsonIsTheDefaultSerializer(): void
    {
        $handler = $this->handler();
        $ciphertext = $handler->encrypt('hello');
        $secondByte = hexdec(substr($ciphertext, 2, 2));

        self::assertSame(0x00, $secondByte, 'second byte is the serializer flag, 0x00 = JSON');
    }

    public function testPhpSerializerIsOptIn(): void
    {
        $handler = $this->handler(['serializer' => BaseHandler::SERIALIZER_PHP]);
        $ciphertext = $handler->encrypt('hello');
        $secondByte = hexdec(substr($ciphertext, 2, 2));

        self::assertSame(0x01, $secondByte);
    }

    public function testDifferentAlgorithmsRoundTripCleanly(): void
    {
        $handler = $this->handler(['algo' => 'sha512', 'cipher' => 'AES-256-CBC']);

        self::assertSame(['hello'], $handler->decrypt($handler->encrypt(['hello'])));
    }

    public function testWrongKeyCannotDecrypt(): void
    {
        $encrypt = $this->handler();
        $ciphertext = $encrypt->encrypt('hello');
        $decrypt = new OpenSSL(['key' => 'a-different-secret']);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('HMAC verification failed');

        $decrypt->decrypt($ciphertext);
    }
}
