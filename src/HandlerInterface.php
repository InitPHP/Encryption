<?php
/**
 * HandlerInterface.php
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

interface HandlerInterface
{

    public function encrypt($data, array $options = []): string;

    public function decrypt($data, array $options = []);

    public function setOptions(array $options = []): HandlerInterface;

}
