<?php

declare(strict_types=1);

namespace InitPHP\Encryption;

use InitPHP\Encryption\Exceptions\EncryptionException;
use SodiumException;

/**
 * Encrypts and decrypts arbitrary PHP values with libsodium's
 * crypto_secretbox AEAD construction.
 *
 * Ciphertext layout (binary, then hex-encoded):
 *
 *     [1B VERSION] [1B SERIALIZER] [24B NONCE] [... secretbox (MAC || ciphertext) ...]
 *
 * - VERSION is {@see BaseHandler::FORMAT_VERSION} (0x02).
 * - SERIALIZER is the serializer flag chosen at encrypt time.
 * - The user-supplied "key" option may be of any non-empty length; it is
 *   passed through {@see sodium_crypto_generichash()} to obtain a
 *   SODIUM_CRYPTO_SECRETBOX_KEYBYTES-byte derived key. The derived key never
 *   leaves this handler and is wiped from memory in a finally block.
 *
 * @phpstan-import-type EncryptionOptions from BaseHandler
 */
final class Sodium extends BaseHandler
{
    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If the sodium extension is not loaded.
     */
    public function __construct(array $options = [])
    {
        if (!\extension_loaded('sodium')) {
            throw new EncryptionException('The "sodium" extension is required by the Sodium handler.');
        }
        parent::__construct($options);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If configuration is invalid or libsodium fails.
     */
    public function encrypt(mixed $data, array $options = []): string
    {
        $options = $this->resolveOptions($options);
        $userKey = $this->requireKey($options);
        $blocksize = $this->resolveBlocksize($options);
        $serializerFlag = $this->serializerFlag($options);

        $payload = $this->serializePayload($data, $serializerFlag);

        $secret = $this->deriveKey($userKey);

        try {
            try {
                $padded = sodium_pad($payload, $blocksize);
            } catch (SodiumException $e) {
                throw new EncryptionException('Sodium padding failed: ' . $e->getMessage(), 0, $e);
            }

            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $box = sodium_crypto_secretbox($padded, $nonce, $secret);

            $header = \chr(self::FORMAT_VERSION) . \chr($serializerFlag);

            return bin2hex($header . $nonce . $box);
        } finally {
            sodium_memzero($secret);
        }
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException If the ciphertext is malformed, the format
     *                             version is unsupported, authentication fails,
     *                             or unpadding/deserialization fails.
     */
    public function decrypt(string $data, array $options = []): mixed
    {
        $options = $this->resolveOptions($options);
        $userKey = $this->requireKey($options);
        $blocksize = $this->resolveBlocksize($options);

        $binary = @hex2bin($data);
        if ($binary === false) {
            throw new EncryptionException('Ciphertext is not valid hex-encoded data.');
        }

        $minLength = 2 + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
        if (\strlen($binary) < $minLength) {
            throw new EncryptionException('Ciphertext is too short to contain a v2 Sodium payload.');
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

        $nonce = substr($binary, 2, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = substr($binary, 2 + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $secret = $this->deriveKey($userKey);

        try {
            $padded = sodium_crypto_secretbox_open($box, $nonce, $secret);
            if ($padded === false) {
                throw new EncryptionException(
                    'Sodium decryption failed; ciphertext is corrupted or has been tampered with.',
                );
            }

            try {
                $payload = sodium_unpad($padded, $blocksize);
            } catch (SodiumException $e) {
                throw new EncryptionException('Sodium unpadding failed: ' . $e->getMessage(), 0, $e);
            }

            return $this->unserializePayload($payload, $serializerFlag);
        } finally {
            sodium_memzero($secret);
        }
    }

    /**
     * Derive a {@see SODIUM_CRYPTO_SECRETBOX_KEYBYTES}-byte key from arbitrary
     * user-supplied key material.
     */
    private function deriveKey(string $userKey): string
    {
        return sodium_crypto_generichash($userKey, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @phpstan-param EncryptionOptions $options
     *
     * @throws EncryptionException
     */
    private function resolveBlocksize(array $options): int
    {
        $value = $options['blocksize'] ?? 16;
        if (!\is_int($value) && !(\is_string($value) && ctype_digit($value))) {
            throw new EncryptionException('The "blocksize" option must be a positive integer.');
        }
        $blocksize = (int) $value;
        if ($blocksize < 1) {
            throw new EncryptionException('The "blocksize" option must be a positive integer.');
        }

        return $blocksize;
    }
}
