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
        syslog(LOG_NOTICE, sprintf('Sanitized GET: %s', @serialize($get_sanitized_keys)));
      }
      // Process request body parameters.
      $post_sanitized_keys = array();
      $_POST = self::stripDangerousValues($_POST, $whitelist, $post_sanitized_keys);
      if ($log_sanitized_keys && $post_sanitized_keys) {
        syslog(LOG_NOTICE, sprintf('Sanitized POST: %s', @serialize($post_sanitized_keys)));
      }
      // Process cookie parameters.
      $cookie_sanitized_keys = array();
      $_COOKIE = self::stripDangerousValues($_COOKIE, $whitelist, $cookie_sanitized_keys);
      if ($log_sanitized_keys && $cookie_sanitized_keys) {
        syslog(LOG_NOTICE, sprintf('Sanitized COOKIE: %s', @serialize($cookie_sanitized_keys)));
      }
      // Process request parameters.
      $request_sanitized_keys = array();
      $_REQUEST = self::stripDangerousValues($_REQUEST, $whitelist, $request_sanitized_keys);
      self::$sanitized = TRUE;
    }
  }

  /**
   * Removes the destination if it is dangerous.
   *
   * Note this can only be called after common.inc has been included.
   *
   * @return bool
   *   TRUE if the destination has been removed from $_GET, FALSE if not.
   */
  public static function cleanDestination() {
    $dangerous_keys = array();
    $log_sanitized_keys = TRUE;

    $parts = self::drupal_parse_url($_GET['destination']);
    // If there is a query string, check its query parameters.
    if (!empty($parts['query'])) {
      $whitelist = array();

      self::stripDangerousValues($parts['query'], $whitelist, $dangerous_keys);
      if (!empty($dangerous_keys)) {
        // The destination is removed rather than sanitized to mirror the
        // handling of external destinations.
        unset($_GET['destination']);
        unset($_REQUEST['destination']);
        if ($log_sanitized_keys) {
          syslog(LOG_NOTICE, sprintf('Potentially unsafe destination removed from query string parameters (GET) because it contained the following keys: %s', @serialize($dangerous_keys)));
        }
        return TRUE;
      }
    }
    return FALSE;
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
          $sanitized_keys[$key] = $input[$key];
          unset($input[$key]);
        }
        else {
          $input[$key] = self::stripDangerousValues($input[$key], $whitelist, $sanitized_keys);
        }
      }
    }
    return $input;
  }

  /**
   * Parses a URL string into its path, query, and fragment components.
   *
   * This function splits both internal paths like @code node?b=c#d @endcode and
   * external URLs like @code https://example.com/a?b=c#d @endcode into their
   * component parts. See
   * @link http://tools.ietf.org/html/rfc3986#section-3 RFC 3986 @endlink for an
   * explanation of what the component parts are.
   *
   * Note that, unlike the RFC, when passed an external URL, this function
   * groups the scheme, authority, and path together into the path component.
   *
   * @param string $url
   *   The internal path or external URL string to parse.
   *
   * @return array
   *   An associative array containing:
   *   - path: The path component of $url. If $url is an external URL, this
   *     includes the scheme, authority, and path.
   *   - query: An array of query parameters from $url, if they exist.
   *   - fragment: The fragment component from $url, if it exists.
   *
   * @see drupal_goto()
   * @see l()
   * @see url()
   * @see http://tools.ietf.org/html/rfc3986
   *
   * @ingroup php_wrappers
   */
  public static function drupal_parse_url($url) {
    $options = array(
      'path' => NULL,
      'query' => array(),
      'fragment' => '',
    );
  
    // External URLs: not using parse_url() here, so we do not have to rebuild
    // the scheme, host, and path without having any use for it.
    if (strpos($url, '://') !== FALSE) {
      // Split off everything before the query string into 'path'.
      $parts = explode('?', $url);
      $options['path'] = $parts[0];
      // If there is a query string, transform it into keyed query parameters.
      if (isset($parts[1])) {
        $query_parts = explode('#', $parts[1]);
        parse_str($query_parts[0], $options['query']);
        // Take over the fragment, if there is any.
        if (isset($query_parts[1])) {
          $options['fragment'] = $query_parts[1];
        }
      }
    }
    // Internal URLs.
    else {
      // parse_url() does not support relative URLs, so make it absolute. E.g. the
      // relative URL "foo/bar:1" isn't properly parsed.
      $parts = parse_url('http://example.com/' . $url);
      // Strip the leading slash that was just added.
      $options['path'] = substr($parts['path'], 1);
      if (isset($parts['query'])) {
        parse_str($parts['query'], $options['query']);
      }
      if (isset($parts['fragment'])) {
        $options['fragment'] = $parts['fragment'];
      }
    }
    // The 'q' parameter contains the path of the current page if clean URLs are
    // disabled. It overrides the 'path' of the URL when present, even if clean
    // URLs are enabled, due to how Apache rewriting rules work. The path
    // parameter must be a string.
    if (isset($options['query']['q']) && is_string($options['query']['q'])) {
      $options['path'] = $options['query']['q'];
      unset($options['query']['q']);
    }
  
    return $options;
  }


}
LagoonRequestSanitizer::sanitize();

if (isset($_GET['destination'])) {
  LagoonRequestSanitizer::cleanDestination();
}