<?php

declare(strict_types=1);

namespace InitPHP\Encryption;

use InitPHP\Encryption\Exceptions\EncryptionException;

/**
 * Convenience factory for handler instantiation.
 *
 * Accepts either a fully-qualified class name (which will be instantiated
 * with the given options) or an already-constructed handler instance (whose
 * options will be merged with the given overrides).
 */
final class Encrypt
{
    /**
     * @template T of HandlerInterface
     *
     * @param class-string<T>|T    $handler Fully-qualified handler class name, or
     *                                      an already-constructed handler instance.
     * @param array<string, mixed> $options Options to apply on top of the handler's
     *                                      defaults. Keys are case-insensitive.
     *
     * @return T
     *
     * @throws EncryptionException If the class name does not exist, the resulting
     *                             object does not implement {@see HandlerInterface},
     *                             or the handler's own constructor rejects the options.
     */
    public static function use(string|HandlerInterface $handler, array $options = []): HandlerInterface
    {
        if (\is_string($handler)) {
            if (!class_exists($handler)) {
                throw new EncryptionException(\sprintf('Handler class "%s" does not exist.', $handler));
            }

            $instance = new $handler($options);
            if (!$instance instanceof HandlerInterface) {
                throw new EncryptionException(\sprintf(
                    'Handler class "%s" must implement %s.',
                    $handler,
                    HandlerInterface::class,
                ));
            }

            /** @var T $instance */
            return $instance;
        }

        if ($options !== []) {
            $handler->setOptions($options);
        }

        return $handler;
    }
}
