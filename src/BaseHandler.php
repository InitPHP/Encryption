<?php
/**
 * BaseEncryption.php
 *
 * This file is part of InitPHP.
 *
 * @author     Muhammet ŞAFAK <info@muhammetsafak.com.tr>
 * @copyright  Copyright © 2022 InitPHP
 * @license    http://initphp.github.io/license.txt  MIT
 * @version    1.0
 * @link       https://www.muhammetsafak.com.tr
 */

declare(strict_types=1);

namespace InitPHP\Encryption;

use const CASE_LOWER;

use function array_merge;
use function array_change_key_case;
use function strtolower;
use function mb_substr;

abstract class BaseHandler implements HandlerInterface
{

    protected array $options = [
        'algo'      => 'SHA256',
        'cipher'    => 'AES-256-CTR',
        'key'       => null,
        'blocksize' => 16,
    ];

    abstract public function encrypt($data, array $options = []): string;

    abstract public function decrypt($data, array $options = []);

    public function __construct(array $options = [])
    {
        $this->setOptions($options);
    }

    public function setOptions(array $options = []): self
    {
        if(empty($options)){
            return $this;
        }
        $this->options = array_merge($this->options, array_change_key_case($options, CASE_LOWER));
        return $this;
    }

    public function setOption(string $name, $value): self
    {
        $this->options[strtolower($name)] = $value;
        return $this;
    }

    public function getOption(string $name, $default = null)
    {
        $name = strtolower($name);
        return $this->options[$name] ?? $default;
    }

    public function getOptions(): array
    {
        return $this->options ?? [];
    }

    protected function options(array $options = []): array
    {
        return empty($options) ? $this->options : array_merge($this->options, array_change_key_case($options, CASE_LOWER));
    }

    protected function substr($str, int $offset, ?int $length = null): string
    {
        return mb_substr($str, $offset, $length, '8bit');
    }

}
