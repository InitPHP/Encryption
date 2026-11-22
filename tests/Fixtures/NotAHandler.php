<?php

declare(strict_types=1);

namespace InitPHP\Encryption\Tests\Fixtures;

/**
 * A class that intentionally does not implement
 * {@see \InitPHP\Encryption\HandlerInterface}. Exists only to exercise the
 * "class is not a handler" error path of {@see \InitPHP\Encryption\Encrypt::use()}.
 */
final class NotAHandler
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(public readonly array $options = []) {}
}
