<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;

use Selfsimilar\D7PasswordHasher\Hasher;

class HasherTest extends TestCase
{

    protected $hasher;

    protected function setUp(): void
    {
        $this->hasher = new Hasher();
    }

    public function test_checker_will_match_output_of_hasher()
    {
      $hash = $this->hasher->HashPassword('foo');
      $response = $this->hasher->CheckPassword('foo', $hash);
      $this->assertTrue($response);
    }
}
