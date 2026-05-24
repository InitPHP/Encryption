<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Exceptions;

use RuntimeException;

/**
 * Thrown by every failure mode of the package: invalid configuration, missing
 * required options, tampered ciphertext, unsupported format version, missing
 * extensions, or any error raised by the underlying cryptographic primitives.
 *
 * Catching this exception is sufficient to handle every error path the
 * library can produce.
 */
class EncryptionException extends RuntimeException
{
}
