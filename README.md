Drupal 7 Password Hasher
===================

[![Build Status](https://img.shields.io/travis/selfsimilar/drupal7_password_hasher/main.svg?style=flat-square)](https://travis-ci.org/selfsimilar/drupal7_password_hasher)

This is the Drupal 7 password hasher code, reformatted in to a PSR-4 compliant
library class for use in PHP projects that need to import legacy Drupal 7 user
accounts. Drupal 7 is licensed under the GPLv3, and as this borrows directly
from that code, I have licensed this code similarly. Thanks to
[HauteLook](https://github.com/hautelook) for the
[Modernized Openwall Phpass](https://github.com/hautelook/phpass) package for
inspiration.

Usage
-----

```php
<?php

namespace Your\Namespace;

use Selfsimilar\D7PasswordHasher\Hasher;

require_once(__DIR__ . "/vendor/autoload.php");

// Constructor take the iteration count for number of cycles to hash, but by
// default uses the Drupal 7 stock number. You may need to check your Drupal 7
// installation for the value of `password_count_log2` (e.g. `drush
// variable-get password_count_log2`). If it is set and different than 15,
// you will need to pass it to the Hasher() constructor.
$passwordHasher = new Hasher();

$password = $passwordHasher->HashPassword('secret');
var_dump($password);

$passwordMatch = $passwordHasher->CheckPassword('secret',
  "$2a$08$0RK6Yw6j9kSIXrrEOc3dwuDPQuT78HgR0S3/ghOFDEpOGpOkARoSu");
var_dump($passwordMatch);
```
