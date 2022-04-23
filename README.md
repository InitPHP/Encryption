# Encryption
PHP OpenSSL/Sodium Encryption and Decryption

[![Latest Stable Version](http://poser.pugx.org/initphp/encryption/v)](https://packagist.org/packages/initphp/encryption) [![Total Downloads](http://poser.pugx.org/initphp/encryption/downloads)](https://packagist.org/packages/initphp/encryption) [![Latest Unstable Version](http://poser.pugx.org/initphp/encryption/v/unstable)](https://packagist.org/packages/initphp/encryption) [![License](http://poser.pugx.org/initphp/encryption/license)](https://packagist.org/packages/initphp/encryption) [![PHP Version Require](http://poser.pugx.org/initphp/encryption/require/php)](https://packagist.org/packages/initphp/encryption)

## Requirements

- PHP 7.4 or higher
- MB_String extension
- Depending on usage: 
  - OpenSSL extesion
  - Sodium extension


## Installation

```
composer require initphp/encryption
```

## Configuration

```php 
$options = [
    'algo'      => 'SHA256',
    'cipher'    => 'AES-256-CTR',
    'key'       => null,
    'blocksize' => 16,
];
```

- `algo` : Used by OpenSSL handler only. The algorithm to use to sign the data.
- `cipher` : Used by OpenSSL handler only. The encryption algorithm that will be used to encrypt the data.
- `key` : The top secret key string to use for encryption.
- `blocksize` : It is used for sodium handler only. It is used in the `sodium_pad()` and `sodium_unpad()` functions.


## Usage

```php 
require_once "vendor/autoload.php";
use \InitPHP\Encryption\Encrypt;

// OpenSSL Handler
/** @var $openssl \InitPHP\Encryption\HandlerInterface */
$openssl = Encrypt::use(\InitPHP\Encryption\OpenSSL::class, [
    'algo'      => 'SHA256',
    'cipher'    => 'AES-256-CTR',
    'key'       => 'TOP_Secret_Key',
]);

// Sodium Handler
/** @var $sodium \InitPHP\Encryption\HandlerInterface */
$sodium = Encrypt::use(\InitPHP\Encryption\Sodium::class, [
    'key'       => 'TOP_Secret_Key',
    'blocksize' => 16,
]);
```

### Methods

#### `encrypt()`

```php 
public function encrypt(mixed $data, array $options = []): string;
```

#### `decrypt()`

```php 
public function decrypt(string $data, array $options = []): mixed;
```

## Writing Your Own Handler

```php 
namespace App;

use \InitPHP\Encryption\{HandlerInterface, BaseHandler};

class MyHandler extends BaseHandler implements HandlerInterface
{
    public function encrypt($data, array $options = []): string
    {
        $options = $this->options($options);
        // ... process
    }

    public function decrypt($data, array $options = [])
    {
        $options = $this->options($options);
        // ... process
    }
}
```

```php 
use \InitPHP\Encryption\Encrypt;

$myhandler = Encrypt::use(\App\MyHandler::class);
```

## Getting Help

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Getting Involved

> All contributions to this project will be published under the MIT License. By submitting a pull request or filing a bug, issue, or feature request, you are agreeing to comply with this waiver of copyright interest.

There are two primary ways to help:

- Using the issue tracker, and
- Changing the code-base.
    
### Using the issue tracker

Use the issue tracker to suggest feature requests, report bugs, and ask questions. This is also a great way to connect with the developers of the project as well as others who are interested in this solution.

Use the issue tracker to find ways to contribute. Find a bug or a feature, mention in the issue that you will take on that effort, then follow the Changing the code-base guidance below.

### Changing the code-base

Generally speaking, you should fork this repository, make changes in your own fork, and then submit a pull request. All new code should have associated unit tests that validate implemented features and the presence or lack of defects. Additionally, the code should follow any stylistic and architectural guidelines prescribed by the project. In the absence of such guidelines, mimic the styles and patterns in the existing code-base.

## Credits

- [Muhammet ŞAFAK](https://www.muhammetsafak.com.tr)

## License

Copyright &copy; 2022 [MIT License](./LICENSE)
