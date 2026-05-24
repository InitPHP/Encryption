<?php

declare(strict_types=1);

namespace InitPHP\Encryption;

use InitPHP\Encryption\Exceptions\EncryptionException;

/**
 * Contract every encryption handler must implement.
 *
 * Handlers translate arbitrary PHP values into an opaque, hex-encoded
 * ciphertext string and back. The encoding, key derivation and
 * authentication strategy are entirely up to the implementation; callers
 * only see the {@see encrypt()} / {@see decrypt()} pair.
 */
interface HandlerInterface
{
    /**
     * Encrypt a value and return its ciphertext.
     *
     * @param mixed                $data    Any value the configured serializer can encode.
     * @param array<string, mixed> $options Per-call option overrides merged on top of the
     *                                      handler's persistent options.
     *
     * @throws EncryptionException When configuration is invalid or the underlying
     *                             primitive fails to encrypt.
     */
    public function encrypt(mixed $data, array $options = []): string;

    /**
     * Decrypt a ciphertext produced by the same handler version.
     *
     * @param string               $data    Ciphertext previously returned by {@see encrypt()}.
     * @param array<string, mixed> $options Per-call option overrides merged on top of the
     *                                      handler's persistent options.
     *
     * @throws EncryptionException When the ciphertext is malformed, the format version
     *                             is unsupported, authentication fails, or deserialization fails.
     */
    public function decrypt(string $data, array $options = []): mixed;

    /**
     * Merge the given options on top of the current configuration.
     *
     * Option keys are case-insensitive.
     *
     * @param array<string, mixed> $options
     */
    public function setOptions(array $options = []): static;
}
