<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

require_once _OAUTH_LIB_DIR . 'OAuthXShared.php';

class OAuthException extends Exception
{
	protected $http_status_code;
	protected $oauth_problem, $oauth_problem_extra_info;

	/**
	 * Standard constructor. The http_status_code should be set
	 * according to the recommendations in section 3.2. of the OAuth Core specs.
	 * @param int http_status_code
	 **/
	public function __construct($error_msg, $http_status_code = 500, $oauth_problem = '', array $oauth_problem_extra_info = NULL)
	{
		parent::__construct($error_msg);

		$this->http_status_code = (int)$http_status_code;
		$this->oauth_problem = $oauth_problem;
		$this->oauth_problem_descr = $oauth_problem_extra_info;
	}

	/**
	 * Sends the HTTP response header. Does *not* output the error description.
	 * Use getMessage() to get the error message.
	 **/
	public function sendHttpResponseHeader()
	{
		$status_codes = array(400 => 'Bad Request',
			401 => 'Authorization Required',
			500 => 'Internal Server Error');

		$status_descr = OAuthShared::getIfSet($status_codes, $this->http_status_code);

		if(empty($status_descr))
		{
			throw new Exception('OAuthException with unsupported HTTP response code "' . $this->http_status_code . '"');
		}

		header('HTTP/1.0 ' . $this->http_status_code . ' ' . $status_descr);
	}

	/**
	 * Returns a string that follows the guidelines at
	 * http://oauth.pbworks.com/ProblemReporting if an oauth_problem
	 * has been specified in the constructor or an empty string otherwise.
	 * The returned string can be used in a WWW-Authenticate header, or as
	 * the body part of the response.
	 * @return array
	 **/
	public function getOAuthProblemData()
	{
		if(empty($this->oauth_problem))
		{
			return array();
		}

		$params = array('oauth_problem' => $this->oauth_problem,
			'oauth_problem_advice' => $this->getMessage());

		if(is_array($this->oauth_problem_extra_info))
		{
			$params = array_merge($params, $this->oauth_problem_extra_info);
		}

		return $params;
	}

	/**
	 * Returns this error's HTTP status code, e.g. 401 or 500.
	 **/
	public function getHttpStatusCode()
	{
		return $this->http_status_code;
	}
}


class OAuthUtil
{
	/**
	 * Returns true if a parameter with the name $name is part of the OAuth specs.
	 **/
	static public function isKnownOAuthParameter($name)
	{
		$names = array('oauth_consumer_key', 'oauth_token', 'oauth_signature_method', 'oauth_signature', 'oauth_verifier',
			'oauth_timestamp', 'oauth_nonce', 'oauth_version', 'oauth_callback', 'oauth_error_in_response_body');

		return in_array($name, $names, true);
	}

	/**
	 * Returns an array of all HTTP request headers. The key names will
	 * be all lowercase, for RFC 2612 section 4.2 requires
	 * them to be treated case-insensitively.
	 **/
	static public function getPageRequestHeaders()
	{
		$headers = array();

		if(function_exists('apache_request_headers'))
		{
			$temp_headers = apache_request_headers();

			foreach($temp_headers as $key => $value) { $headers[strtolower($key)] = $value; }
		}
		else
		{
			foreach($_SERVER as $key => $value)
			{
				if(strpos($key, 'HTTP_') === 0)
				{
					// transform e.g. "HTTP_USER_AGENT" into "user-agent":
					$header_name = substr($key, 5);
					$header_name = strtolower($header_name);
					$header_name = strtr($header_name, '_', '-');

					$headers[$header_name] = $value;
				}
			}

			if(!isset($headers['content-type']))
			{
				if(isset($_SERVER['CONTENT_TYPE']))
				{
					// re: http://code.google.com/p/oauth/issues/detail?id=142
					$headers['content-type'] = $_SERVER['CONTENT_TYPE'];
				}
				elseif(isset($_ENV['CONTENT_TYPE']))
				{
					// re: http://code.google.com/p/oauth/issues/detail?id=118
					$_SERVER['content-type'] = $_ENV['CONTENT_TYPE'];
				}
			}
		}

		return $headers;
	}

	/**
	 * Parses an HTTP Authorization header according to section 3.5.1. of the OAuth Core specs.
	 * @param header_string string e.g. 'OAuth realm="...", oauth_token="..." ...'
	 * @param allow_all_param_names bool If this is false, only the "realm" and isKnownOAuthParameter()s will be returned.
	 * @return array An array with all the oauth parameters (unencoded!) and the realm string, or false if the header is not an OAuth header.
	 **/
	static public function parseHttpAuthorizationHeader($header_string, $allow_all_param_names = false)
	{
		// The extension auth-scheme (as defined by RFC2617) is "OAuth" and is case-insensitive.
		if(!preg_match('~^OAuth\s+(.+)$~si', $header_string, $match))
		{
			return false;
		}

		$params = array();

		// Parameters are separated by a comma character (ASCII code 44) and OPTIONAL linear whitespace per RFC2617:
		$pairs = preg_split('~,\s*~', $match[1]);

		foreach($pairs as $pair)
		{
			$syntax_error = true;

			// For each parameter, the name is immediately followed by an '=' character (ASCII code 61),
			// a '"' character (ASCII code 34), the parameter value (MAY be empty),
			// and another '"' character (ASCII code 34).
			$pair = explode('=', $pair, 2);

			if(count($pair) == 2)
			{
				$name = trim($pair[0]);
				$value = trim($pair[1]);

				if(strlen($value) >= 2 && $value[0] == '"' && substr($value, -1) == '"')
				{
					// Parameter names and values are encoded per Parameter Encoding.
					$name = OAuthShared::urlDecode($name);
					$value = OAuthShared::urlDecode(substr($value, 1, -1));

					if(strpos($value, '"') === false && ($allow_all_param_names || self::isKnownOAuthParameter($name) || $name == 'realm'))
					{
						// The OPTIONAL realm parameter is added and interpreted per RFC2617.
						$syntax_error = false;
						$params[$name] = $value;
					}
				}
			}

			if($syntax_error)
			{
				throw new OAuthException('Syntax or name error while parsing Authorization header.');
			}
		}

		if(count($params) == 0)
		{
			throw new OAuthException('Woops, an Authorization header without any parameters?');
		}

		return $params;
	}

	/**
	 * Normalizes the given URL according to section 3.4.1.2. of the OAuth Core specs.
	 **/
	static public function normalizeRequestURL($url)
	{
		if(!filter_var($url, FILTER_VALIDATE_URL))
		{
			throw new OAuthException('Attempted to normalize an invalid URL: "' . $url . '"');
		}

		$parts = parse_url($url);

		$scheme = strtolower($parts['scheme']);
		$default_port = ($scheme == 'https' ? 443 : 80);

		$host = strtolower($parts['host']);
		$port = (int)OAuthShared::getIfSet($parts, 'port', $default_port);

		// Note that HTTP does not allow empty absolute paths, so the URL
		// 'http://example.com' is equivalent to 'http://example.com/' and
		// should be treated as such for the purposes of OAuth signing (rfc2616, section 3.2.1)!
		$path = OAuthShared::getIfSet($parts, 'path', '/');

		if($port != $default_port)
		{
			$host .= ':' . $port;
		}

		return $scheme . '://' . $host . $path;
	}
}


class OAuthConsumer
{
	protected $key;
	protected $secret;

	/**
	 * @param key string
	 * @param secret string
	 **/
	public function __construct($key, $secret)
	{
		if(!is_string($key) || !is_string($secret))
		{
			throw new OAuthException('Consumer key and secret MUST be string values.');
		}

		$this->key = $key;
		$this->secret = $secret;
	}

	public function getKey() { return $this->key; }
	public function getSecret() { return $this->secret; }
}


class OAuthToken
{
	protected $token;
	protected $secret;
	protected $additional_params = array();

	/**
	 * @param token string
	 * @param secret string
	 **/
	public function __construct($token, $secret)
	{
		if(!is_string($token) || !is_string($secret))
		{
			throw new OAuthException('Token and secret MUST be string values.');
		}

		$this->token = $token;
		$this->secret = $secret;
	}

	public function getToken() { return $this->token; }
	public function getSecret() { return $this->secret; }

	/**
	 * Sets an additional parameter.
	 * Mainly useful in combination with __toString.
	 * Escaping any of the arguments is not necessary.
	 **/
	public function setAdditionalParam($name, $value)
	{
		if($name != 'oauth_token' && $name != 'oauth_secret')
		{
			$this->additional_params[$name] = $value;
		}
	}

	public function __toString()
	{
		$params = array('oauth_token' => $this->token,
			'oauth_token_secret' => $this->secret);

		$params = array_merge($this->additional_params, $params);

		return OAuthShared::joinParametersMap($params);
	}
}

