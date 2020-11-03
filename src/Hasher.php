<?php

// This is a thin wrapper class around Drupal 7's
// [password.inc](https://api.drupal.org/api/drupal/includes%21password.inc/7.x)
// which is itself // is a slightly modified version of
// [Phpass](https://github.com/hautelook/phpass)
// I have lightly modified the code to make it PSR-4 compatible.

namespace Selfsimilar\D7PasswordHasher;

class Hasher
{
  private const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  /**
   * The standard log2 number of iterations for password stretching. This should
   * increase by 1 every Drupal version in order to counteract increases in the
   * speed and power of computers available to crack the hashes.
   */
  private const DRUPAL_HASH_COUNT = 15;

  /**
   * The minimum allowed log2 number of iterations for password stretching.
   */
  private const DRUPAL_MIN_HASH_COUNT = 7;

  /**
   * The maximum allowed log2 number of iterations for password stretching.
   */
  private const DRUPAL_MAX_HASH_COUNT = 30;

  /**
   * The expected (and maximum) number of characters in a hashed password.
   */
  private const DRUPAL_HASH_LENGTH = 55;
  private $iteration_count_log2;
  private $random_state;

  /**
   * Constructor
   *
   */
  public function __construct(int $iteration_count_log2 = NULL)
  {
    $this->iteration_count_log2 = $iteration_count_log2 ?? self::DRUPAL_HASH_COUNT;
    $this->random_state = microtime();
  }

  public function HashPassword($password)
  {
    return $this->crypt_private(
      'sha512',
      $password,
      $this->generate_salt($this->iteration_count_log2)
    );
  }

  /**
   * @param String $password
   * @param String $stored_hash
   * @return boolean
   */
  public function CheckPassword($password, $stored_hash)
  {
    if (substr($stored_hash, 0, 2) == 'U$') {

      // This may be an updated password from user_update_7000(). Such hashes
      // have 'U' added as the first character and need an extra md5().
      $stored_hash = substr($stored_hash, 1);
      $password = md5($password);
    }
    else {
      $stored_hash = $stored_hash;
    }
    $type = substr($stored_hash, 0, 3);
    switch ($type) {
    case '$S$':

      // A normal Drupal 7 password using sha512.
      $hash = $this->crypt_private('sha512', $password, $stored_hash);
      break;

    case '$H$':

      // phpBB3 uses "$H$" for the same thing as "$P$".
    case '$P$':

      // A phpass password generated using md5.  This is an
      // imported password or from an earlier Drupal version.
      $hash = $this->crypt_private('md5', $password, $stored_hash);
      break;

    default:
      return FALSE;
    }
    return $hash && $stored_hash == $hash;
  }

  /**
   * Parse the log2 iteration count from a stored hash or setting string.
   */
  public function get_count_log2($setting) {
    return strpos(self::ITOA64, $setting[3]);
  }

  /**
   * Hash a password using a secure stretched hash.
   *
   * By using a salt and repeated hashing the password is "stretched". Its
   * security is increased because it becomes much more computationally costly
   * for an attacker to try to break the hash by brute-force computation of the
   * hashes of a large number of plain-text words or strings to find a match.
   *
   * @param $algo
   *   The string name of a hashing algorithm usable by hash(), like 'sha256'.
   * @param $password
   *   Plain-text password up to 512 bytes (128 to 512 UTF-8 characters) to hash.
   * @param $setting
   *   An existing hash or the output of generate_salt().  Must be
   *   at least 12 characters (the settings and salt).
   *
   * @return
   *   A string containing the hashed password (and salt) or FALSE on failure.
   *   The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
   */
  public function crypt_private($algo, $password, $setting)
  {

    // Prevent DoS attacks by refusing to hash large passwords.
    if (strlen($password) > 512) {
      return FALSE;
    }

    // The first 12 characters of an existing hash are its setting string.
    $setting = substr($setting, 0, 12);
    if ($setting[0] != '$' || $setting[2] != '$') {
      return FALSE;
    }
    $count_log2 = $this->get_count_log2($setting);

    // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
    if ($count_log2 < self::DRUPAL_MIN_HASH_COUNT || $count_log2 > self::DRUPAL_MAX_HASH_COUNT) {
      return FALSE;
    }
    $salt = substr($setting, 4, 8);

    // Hashes must have an 8 character salt.
    if (strlen($salt) != 8) {
      return FALSE;
    }

    // Convert the base 2 logarithm into an integer.
    $count = 1 << $count_log2;

    // We rely on the hash() function being available in PHP 5.2+.
    $hash = hash($algo, $salt . $password, TRUE);
    do {
      $hash = hash($algo, $hash . $password, TRUE);
    } while (--$count);
    $len = strlen($hash);
    $output = $setting . $this->base64_encode($hash, $len);

    // base64_encode() of a 16 byte MD5 will always be 22 characters.
    // base64_encode() of a 64 byte sha512 will always be 86 characters.
    $expected = 12 + ceil(8 * $len / 6);
    return strlen($output) == $expected ? substr($output, 0, self::DRUPAL_HASH_LENGTH) : FALSE;
  }

  /**
   * Generates a random base 64-encoded salt prefixed with settings for the hash.
   *
   * Proper use of salts may defeat a number of attacks, including:
   *  - The ability to try candidate passwords against multiple hashes at once.
   *  - The ability to use pre-hashed lists of candidate passwords.
   *  - The ability to determine whether two users have the same (or different)
   *    password without actually having to guess one of the passwords.
   *
   * @param $count_log2
   *   Integer that determines the number of iterations used in the hashing
   *   process. A larger value is more secure, but takes more time to complete.
   *
   * @return
   *   A 12 character string containing the iteration count and a random salt.
   */
  public function generate_salt($count_log2) {
    $output = '$S$';

    // Ensure that $count_log2 is within set bounds.
    $count_log2 = $this->enforce_log2_boundaries($count_log2);

    // We encode the final log2 iteration count in base 64.
    $itoa64 = self::ITOA64;
    $output .= $itoa64[$count_log2];

    // 6 bytes is the standard salt for a portable phpass hash.
    $output .= $this->base64_encode($this->get_random_bytes(6), 6);
    return $output;
  }

  /**
   * Ensures that $count_log2 is within set bounds.
   *
   * @param $count_log2
   *   Integer that determines the number of iterations used in the hashing
   *   process. A larger value is more secure, but takes more time to complete.
   *
   * @return
   *   Integer within set bounds that is closest to $count_log2.
   */
  public function enforce_log2_boundaries($count_log2) {
    if ($count_log2 < self::DRUPAL_MIN_HASH_COUNT) {
      return self::DRUPAL_MIN_HASH_COUNT;
    }
    elseif ($count_log2 > self::DRUPAL_MAX_HASH_COUNT) {
      return self::DRUPAL_MAX_HASH_COUNT;
    }
    return (int) $count_log2;
  }

  /**
   * Encodes bytes into printable base 64 using the *nix standard from crypt().
   *
   * @param $input
   *   The string containing bytes to encode.
   * @param $count
   *   The number of characters (bytes) to encode.
   *
   * @return
   *   Encoded string
   */
  public function base64_encode($input, $count) {
    $output = '';
    $i = 0;
    $itoa64 = self::ITOA64;
    do {
      $value = ord($input[$i++]);
      $output .= $itoa64[$value & 0x3f];
      if ($i < $count) {
        $value |= ord($input[$i]) << 8;
      }
      $output .= $itoa64[$value >> 6 & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      if ($i < $count) {
        $value |= ord($input[$i]) << 16;
      }
      $output .= $itoa64[$value >> 12 & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      $output .= $itoa64[$value >> 18 & 0x3f];
    } while ($i < $count);
    return $output;
  }

    /**
     * @param  int $count
     * @return String
     */
    public function get_random_bytes($count)
    {
        $output = '';

        if (is_callable('random_bytes')) {
            return random_bytes($count);
        }

        if (@is_readable('/dev/urandom') &&
            ($fh = @fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->random_state =
                    md5(microtime() . $this->random_state);
                $output .=
                    pack('H*', md5($this->random_state));
            }
            $output = substr($output, 0, $count);
        }

        return $output;
    }
}
