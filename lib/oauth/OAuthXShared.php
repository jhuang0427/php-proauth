<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

class OAuthShared
{
	/**
	 * Returns $default if $arr[$key] is unset.
	 **/
	public static function getIfSet(&$arr, $key, $default = NULL)
	{
		if(isset($arr) && is_array($arr) && !empty($arr[$key]))
		{
			return $arr[$key];
		}

		return $default;
	}

	/**
	 * Encodes the given string (or array!) according to RFC 3986, as defined
	 * by the OAuth Core specs section 3.6. "Percent Encoding".
	 **/
	public static function urlEncode($input)
	{
		if(is_array($input))
		{
			return array_map(array(__CLASS__, 'urlEncode'), $input);
		}
		elseif(is_scalar($input))
		{
			if(defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 50300)
			{
				// rawurlencode is RFC 3986 compliant, starting with PHP 5.3.0...
				return rawurlencode($input);
			}
			else
			{
				return str_replace(array('+', '%7E'), array('%20', '~'), rawurlencode($input));
			}
		}
		else
		{
			throw new Exception('Unsupported parameter type for ' . __FUNCTION__);
		}
	}

	/**
	 * Works similarly to http_build_query, but uses our custom URL encoding method.
	 **/
	public static function joinParametersMap(array $params)
	{
		$str = '';

		foreach($params as $key => $value)
		{
			// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
			// Each name-value pair is separated by an '&' character (ASCII code 38)

			if(!empty($str)) $str .= '&';
			$str .= self::urlEncode($key) . '=' . self::urlEncode($value);
		}

		return $str;
	}

	/**
	 * URL decodes the given string (or array!)...
	 **/
	public static function urlDecode($input)
	{
		if(is_array($input))
		{
			return array_map(array(__CLASS__, 'urlDecode'), $input);
		}
		elseif(is_scalar($input))
		{
			// we use urldecode (instead of rawurldecode) here, because section 3.4.1.3.1. of the specs says:
			// <quote>While the encoding rules specified in this specification for the purpose of constructing the
			// signature base string exclude the use of a + character (ASCII code 43) to represent an encoded
			// space character (ASCII code 32), this practice is widely used in application/x-www-form-urlencoded
			// encoded values, and MUST be properly decoded.</quote>
			return urldecode($input);
		}
		else
		{
			throw new Exception('Unsupported parameter type for ' . __FUNCTION__);
		}
	}

	/**
	 * I'd love to use PHP's parse_str for this, but unfortunately, it adheres to the "magic_quotes_gpc" setting
	 * and replaces characters in parameter names, which is unacceptable.
	 * @return array
	 **/
	public static function splitParametersMap($input)
	{
		$result = array();

		$pairs = explode('&', $input);
		foreach($pairs as $pair)
		{
			if(!empty($pair))
			{
				$pair = explode('=', $pair);

				if(count($pair) == 2)
				{
					$result[self::urlDecode($pair[0])] = self::urlDecode(self::getIfSet($pair, 1, ''));
				}
			}
		}

		return $result;
	}

	/**
	 * Returns a random string consisting of letters and numbers
	 **/
	public static function randomString($length)
	{
		$s = '';
		for($i = 0; $i < $length; $i++)
		{
			switch(mt_rand(0, mt_rand(3, 4)))
			{
				case $i % 2:
					$s .= mt_rand(0, 9); break;
				case ($i + 1) % 2:
					$s .= chr(mt_rand(65, 90)); break;
				default:
					$s .= chr(mt_rand(97, 122));
			}
		}
		return $s;
	}

	/**
	 * Generates and returns a most probably unique nonce with a length of about 27 characters.
	 **/
	public static function generateNonce()
	{
		$nonce = uniqid(mt_rand()) . '/' . microtime(true);
		$nonce = base64_encode(sha1($nonce, true));
		$nonce = rtrim($nonce, '=');
		return $nonce;
	}

	/**
	 * Creates and configures a curl resource/instance in $ch
	 * so it can be used as an OAuth client.
	 **/
	public static function setUpCurl(&$ch)
	{
		$ch = curl_init();
		// set all the necessary curl options...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_FAILONERROR, false);

		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
		curl_setopt($ch, CURLOPT_TIMEOUT, 30);

		curl_setopt($ch, CURLOPT_USERAGENT, 'php-proauth/1.0 (http://code.google.com/p/php-proauth/) using libcurl');

		// ignore this stupid and soon-to-be-deprecated warning:
		// CURLOPT_FOLLOWLOCATION cannot be activated when in safe_mode or an open_basedir is set.
		@curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_MAXREDIRS, 10);

		// to avoid possibly unwanted SSL problems. :TODO: make this configurable.
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

		// enable compression where supported:
		curl_setopt($ch, CURLOPT_ENCODING, '');
	}

	/**
	 * Splits the headers off the $body of an HTTP response. Splits the headers
	 * into the $headers array and fills out $status_code.
	 **/
	public static function splitHttpResponse($_except_class, $response, array &$headers, &$body, &$status_code)
	{
		// ignore leading proxy response headers:
		// patch by D. of SC 2012-09-15
		if(preg_match('~^(HTTP/\d\.\d\s+\d+\s+[ \w]+\r?\n\r?\n)HTTP/~i', $response, $match))
		{
			$response = substr($response, strlen($match[1]));
		}

		// some boring checks, etc:
		$headers_end = strpos($response, "\r\n\r\n");

		if($headers_end === false)
		{
			$headers_end = strpos($response, "\n\n");
		}

		if($headers_end === false)
		{
			// response without body...
			$headers_end = strlen($response);
		}

		// parse and verify the first line:
		if(!preg_match('~^HTTP/(\d\.\d)\s+(\d+)\s+([ \w]+)\r?\n~i', $response, $match))
		{
			throw new $_except_class('Failed to parse HTTP response: No HTTP/ found.');
		}
		list(, $http_version, $status_code, $response_descr) = $match;
		$status_code = (int)$status_code;

		// parse the headers...
		// http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
		// the link is just for reference, we do not actually implement
		// all of the specs :(
		$header_str = trim(substr($response, 0, $headers_end));
		$headers = array();

		$lines = preg_split('~\r?\n~', $header_str);
		array_shift($lines); // remove the first line.
		$header_name = '';
		foreach($lines as $line)
		{
			if(preg_match('~^[ \t]+(.+)~', $line, $match))
			{
				if(empty($header_name))
				{
					throw new $_except_class('Error while parsing HTTP response headers: Continuated header without name.');
				}
				$headers[$header_name] .= ' ' . $match[1];
			}
			elseif(preg_match('~^(.+?):\s*(.*?)$~', $line, $match))
			{
				$header_name = strtolower($match[1]);
				$headers[$header_name] = trim($match[2]);
			}
			else
			{
				throw new $_except_class('Error while parsing HTTP response headers: Weird-looking/unsupported header line.');
			}
		}

		// assign the body content:
		$body = ltrim(substr($response, $headers_end));

		unset($response); // release some memory.
	}
}

