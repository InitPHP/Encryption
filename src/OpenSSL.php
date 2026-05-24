<?php

declare(strict_types=1);

namespace InitPHP\Encryption;

use InitPHP\Encryption\Exceptions\EncryptionException;

/**
 * Encrypts and decrypts arbitrary PHP values with OpenSSL plus an
 * encrypt-then-MAC construction.
 *
 * Ciphertext layout (binary, then hex-encoded):
 *
 *     [1B VERSION] [1B SERIALIZER] [N B HMAC] [M B IV] [... ciphertext ...]
 *
 * - VERSION is {@see BaseHandler::FORMAT_VERSION} (0x02).
 * - SERIALIZER is the serializer flag chosen at encrypt time.
 * - HMAC length equals strlen(hash_hmac($algo, '', '', true)) for the
 *   configured algorithm and authenticates VERSION || SERIALIZER || IV || ciphertext.
 * - IV length equals openssl_cipher_iv_length($cipher); may be zero for
 *   stream ciphers that take no IV.
 *
 * @phpstan-import-type EncryptionOptions from BaseHandler
 */
final class OpenSSL extends BaseHandler
{
    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If the openssl extension is not loaded.
     */
    public function __construct(array $options = [])
    {
        if (!\extension_loaded('openssl')) {
            throw new EncryptionException('The "openssl" extension is required by the OpenSSL handler.');
        }
        parent::__construct($options);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If configuration is invalid or OpenSSL fails to encrypt.
     */
    public function encrypt(mixed $data, array $options = []): string
    {
        $options = $this->resolveOptions($options);
        $key = $this->requireKey($options);
        $cipher = $this->resolveCipher($options);
        $algo = $this->resolveAlgo($options);
        $serializerFlag = $this->serializerFlag($options);

        $payload = $this->serializePayload($data, $serializerFlag);
        $secret = hash_hkdf($algo, $key);

        $ivLength = $this->ivLength($cipher);
        $iv = $ivLength > 0 ? random_bytes($ivLength) : '';

        $ciphertext = openssl_encrypt($payload, $cipher, $secret, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new EncryptionException(
                'OpenSSL encryption failed: ' . (openssl_error_string() ?: 'unknown error'),
            );
        }

        $header = \chr(self::FORMAT_VERSION) . \chr($serializerFlag);
        $hmac = hash_hmac($algo, $header . $iv . $ciphertext, $secret, true);

        return bin2hex($header . $hmac . $iv . $ciphertext);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If the ciphertext is malformed, the format
     *                             version is unsupported, HMAC verification fails,
     *                             or OpenSSL fails to decrypt.
     */
    public function decrypt(string $data, array $options = []): mixed
    {
        $options = $this->resolveOptions($options);
        $key = $this->requireKey($options);
        $cipher = $this->resolveCipher($options);
        $algo = $this->resolveAlgo($options);

        $binary = @hex2bin($data);
        if ($binary === false) {
            throw new EncryptionException('Ciphertext is not valid hex-encoded data.');
        }

        if (\strlen($binary) < 2) {
            throw new EncryptionException('Ciphertext is shorter than the 2-byte header.');
        }

        $version = \ord($binary[0]);
        if ($version !== self::FORMAT_VERSION) {
            throw new EncryptionException(\sprintf(
                'Unsupported ciphertext format version 0x%02x; expected 0x%02x. Ciphertexts produced by 1.x are not readable by 2.x.',
                $version,
                self::FORMAT_VERSION,
            ));
        }
        $serializerFlag = \ord($binary[1]);

        $secret = hash_hkdf($algo, $key);
        $hmacLength = \strlen(hash_hmac($algo, '', '', true));
        $ivLength = $this->ivLength($cipher);

        $minLength = 2 + $hmacLength + $ivLength;
        if (\strlen($binary) < $minLength) {
            throw new EncryptionException(
                'Ciphertext is too short for the configured algorithm and cipher.',
            );
        }

        $header = substr($binary, 0, 2);
        $hmacGiven = substr($binary, 2, $hmacLength);
        $iv = $ivLength > 0 ? substr($binary, 2 + $hmacLength, $ivLength) : '';
        $ciphertext = substr($binary, 2 + $hmacLength + $ivLength);

        $hmacExpected = hash_hmac($algo, $header . $iv . $ciphertext, $secret, true);
        if (!hash_equals($hmacExpected, $hmacGiven)) {
            throw new EncryptionException(
                'HMAC verification failed; ciphertext is corrupted or has been tampered with.',
            );
        }

        $plain = openssl_decrypt($ciphertext, $cipher, $secret, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            throw new EncryptionException(
                'OpenSSL decryption failed: ' . (openssl_error_string() ?: 'unknown error'),
            );
        }

        return $this->unserializePayload($plain, $serializerFlag);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException
     */
    private function resolveCipher(array $options): string
    {
        $cipher = $options['cipher'] ?? '';
        if (!\is_string($cipher) || $cipher === '') {
            throw new EncryptionException('The "cipher" option is required and must be a non-empty string.');
        }

        $cipherLower = strtolower($cipher);
        foreach (openssl_get_cipher_methods() as $available) {
            if (strtolower($available) === $cipherLower) {
                return $cipher;
            }
        }

        throw new EncryptionException(\sprintf('Unknown OpenSSL cipher "%s".', $cipher));
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException
     */
    private function resolveAlgo(array $options): string
    {
        $algo = $options['algo'] ?? '';
        if (!\is_string($algo) || $algo === '') {
            throw new EncryptionException('The "algo" option is required and must be a non-empty string.');
        }

        $algoLower = strtolower($algo);
        foreach (hash_hmac_algos() as $available) {
            if (strtolower($available) === $algoLower) {
                return $algo;
            }
        }

        throw new EncryptionException(\sprintf('Unknown HMAC hashing algorithm "%s".', $algo));
    }

    /**
     * @throws EncryptionException
     */
    private function ivLength(string $cipher): int
    {
        $length = openssl_cipher_iv_length($cipher);
        if ($length === false) {
            throw new EncryptionException(\sprintf('Unable to determine IV length for cipher "%s".', $cipher));
        }

        return $length;
    }
}
