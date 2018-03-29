<?php

/**
 * @file
 * Contains code for sanitizing user input from the request.
 */

/**
 * Sanitizes user input from the request.
 */
class LagoonRequestSanitizer {

  /**
   * Tracks whether the request was already sanitized.
   */
  protected static $sanitized = FALSE;

  /**
   * Modifies the request to strip dangerous keys from user input.
   */
  public static function sanitize() {
    if (!self::$sanitized) {
      $whitelist = array();
      $log_sanitized_keys = TRUE;

      // Process query string parameters.
      $get_sanitized_keys = array();
      $_GET = self::stripDangerousValues($_GET, $whitelist, $get_sanitized_keys);
      if ($log_sanitized_keys && $get_sanitized_keys) {
        error_log(sprintf('Sanitised GET - keys: %s', implode(', ', $get_sanitized_keys)));
      }

      // Process request body parameters.
      $post_sanitized_keys = array();
      $_POST = self::stripDangerousValues($_POST, $whitelist, $post_sanitized_keys);
      if ($log_sanitized_keys && $post_sanitized_keys) {
        error_log(sprintf('Sanitised POST - keys: %s', implode(', ', $post_sanitized_keys)));
      }

      // Process cookie parameters.
      $cookie_sanitized_keys = array();
      $_COOKIE = self::stripDangerousValues($_COOKIE, $whitelist, $cookie_sanitized_keys);
      if ($log_sanitized_keys && $cookie_sanitized_keys) {
        error_log(sprintf('Sanitised COOKIE - keys: %s', implode(', ', $cookie_sanitized_keys)));
      }

      // Process request parameters.
      $request_sanitized_keys = array();
      $_REQUEST = self::stripDangerousValues($_REQUEST, $whitelist, $request_sanitized_keys);
      if ($log_sanitized_keys && $request_sanitized_keys) {
        error_log(sprintf('Sanitised REQUEST - keys: %s', implode(', ', $request_sanitized_keys)));
      }


      self::$sanitized = TRUE;
    }
  }

  /**
   * Strips dangerous keys from the provided input.
   *
   * @param mixed $input
   *   The input to sanitize.
   * @param string[] $whitelist
   *   An array of keys to whitelist as safe.
   * @param string[] $sanitized_keys
   *   An array of keys that have been removed.
   *
   * @return mixed
   *   The sanitized input.
   */
  protected static function stripDangerousValues($input, array $whitelist, array &$sanitized_keys) {
    if (is_array($input)) {
      foreach ($input as $key => $value) {
        if ($key !== '' && $key[0] === '#' && !in_array($key, $whitelist, TRUE)) {
          unset($input[$key]);
          $sanitized_keys[] = $key;
        }
        else {
          $input[$key] = self::stripDangerousValues($input[$key], $whitelist, $sanitized_keys);
        }
      }
    }
    return $input;
  }

}

LagoonRequestSanitizer::sanitize();