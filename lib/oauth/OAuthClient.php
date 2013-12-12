<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

namespace proauth;

if(!defined('_OAUTH_LIB_DIR'))
{
	define('_OAUTH_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH_LIB_DIR . 'OAuthUtil.php';
require_once _OAUTH_LIB_DIR . 'OAuthRequest.php';
require_once _OAUTH_LIB_DIR . 'OAuthSignature.php';


abstract class OAuthClientBase
{
	protected $consumer;
	protected $token;
	protected $signature_method;

	public function __construct(OAuthConsumer $consumer, OAuthSignatureMethod $signature_method, OAuthToken $token = NULL)
	{
		$this->consumer = $consumer;
		$this->token = $token;
		$this->signature_method = $signature_method;
	}

	/**
	 * returns an OAuthClientRequest instance that can be set up further, as necessary, and then
	 * be submitted.
	 **/
	public function createRequest($url, array $get_params = array(), array $post_params = array())
	{
		$req = new OAuthClientRequest($this, (count($post_params) > 0 ? 'POST' : 'GET'), $url);

		$req->setGetParameters($get_params);
		$req->setPostParameters($post_params);

		if(is_object($this->token))
		{
			$req->setToken($this->token);
		}

		return $req;
	}

	/**
	 * @see createRequest
	 **/
	public function createPostRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this, 'POST', $url);

		$req->setPostParameters($params);

		if(is_object($this->token))
		{
			$req->setToken($this->token);
		}

		return $req;
	}

	/**
	 * @see createRequest
	 **/
	public function createGetRequest($url, array $params = array())
	{
		$req = new OAuthClientRequest($this, 'GET', $url);

		$req->setGetParameters($params);

		if(is_object($this->token))
		{
			$req->setToken($this->token);
		}

		return $req;
	}

	/**
	 * @return OAuthToken
	 **/
	public function getToken() { return $this->token; }

	/**
	 * @return OAuthConsumer
	 **/
	public function getConsumer() { return $this->consumer; }

	/**
	 * @return OAuthSignatureMethod
	 **/
	public function getSignatureMethod() { return $this->signature_method; }

	/**
	 * Implements section 2.1. Temporary Credentials.
	 * @param request_token_url string The target endpoint URL.
	 * @param params array Additional parameters. Usually none. Will be sent via GET.
	 * @param assume_www_encoded boolean Read OAuthClientResponse::forceWwwEncodedBodyInterpretation().
	 * @return An OAuthToken instance with the new temporary request credentials.
	 **/
	public function _getTempToken($request_token_url, array $params = array(), $assume_www_encoded = false)
	{
		// :TODO: We only support GET for request_temp_token...
		$req = $this->createGetRequest($request_token_url, $params);

		$response = $this->executeRequest($req);

		if($assume_www_encoded)
		{
			// I hate twitter so much...
			$response->forceWwwEncodedBodyInterpretation();
		}

		$token_key = $response->getBodyParamValue('oauth_token');
		$token_secret = $response->getBodyParamValue('oauth_token_secret');

		if(empty($token_key) || empty($token_secret))
		{
			throw new OAuthException('We tried hard, but did not get a request/temp token from the server.',
				$response->getStatusCode());
		}

		return new OAuthToken($token_key, $token_secret);
	}

	/**
	 * Implements section 2.3. Token Credentials.
	 * @param access_token_url string The target endpoint URL.
	 * @param params array Additional parameters. Usually none. Will be sent via POST.
	 * @param token OAuthToken The token to use for signing this request.
	 * @param assume_www_encoded boolean Read OAuthClientResponse::forceWwwEncodedBodyInterpretation().
	 * @return An OAuthToken instance with the new authenticated credentials.
	 **/
	public function _getAccessToken($access_token_url, array $params = array(), OAuthToken $token = NULL, $assume_www_encoded = false)
	{
		if(is_null($token))
		{
			// the $token argument is useful for clients that are not HTTP driven.
			$token = $this->token;
		}

		// :TODO: We only support POST for access_token...
		$req = $this->createPostRequest($access_token_url, $params);
		$req->setToken($token);

		$response = $this->executeRequest($req);

		if($assume_www_encoded)
		{
			// Did I already mention that I hate twitter?
			$response->forceWwwEncodedBodyInterpretation();
		}

		$token_key = $response->getBodyParamValue('oauth_token');
		$token_secret = $response->getBodyParamValue('oauth_token_secret');

		if(empty($token_key) || empty($token_secret))
		{
			throw new OAuthException('We tried hard, but did not get an access token from the server.',
				$response->getStatusCode());
		}

		return new OAuthToken($token_key, $token_secret);
	}

	/**
	 * @return OAuthClientResponse
	 **/
	abstract public function executeRequest(OAuthRequest $req);
}


class OAuthClientRequest extends OAuthRequest
{
	protected $client;
	protected $signed = false;
	protected $token;

	/**
	 * Usually invoked by OAuthClient. It's not recommended to create instances by other means.
	 **/
	public function __construct(OAuthClientBase $client, $http_method, $url)
	{
		parent::__construct();

		$this->client = $client;

		if(strcasecmp($http_method, 'POST') && strcasecmp($http_method, 'GET'))
		{
			throw new OAuthException('Unsupported HTTP method "' . $http_method . '" in OAuthClientRequest.');
		}
		$this->http_method = $http_method;

		if(!filter_var($url, FILTER_VALIDATE_URL))
		{
			throw new OAuthException('Invalid URL "' . $url . '" to OAuthClientRequest.');
		}

		// :TODO: handle URLs with GET query parameters.
		// maybe parse them, or throw an error.
		$this->request_url = $url;

		$this->params_oauth['oauth_consumer_key'] = $client->getConsumer()->getKey();

		// we do not add oauth_version=1.0 since it's optional (section 3.1.)

		// use client token per default:
		$this->setToken(NULL);
	}

	/**
	 * Replaces the existing GET query parameters.
	 **/
	public function setGetParameters(array $new_params)
	{
		$this->params_get = $new_params;
		$this->signed = false;
	}

	/**
	 * Replaces the existing POST parameters.
	 **/
	public function setPostParameters(array $new_params)
	{
		$this->params_post = $new_params;
		$this->signed = false;
	}

	/**
	 * Signs the request. You are asked to immediately send it to the
	 * Service Provider after signing it.
	 **/
	public function sign()
	{
		// :TODO: Only add timestamp+nonce if the signature method requires it.
		$this->params_oauth['oauth_timestamp'] = time();
		$this->params_oauth['oauth_nonce'] = OAuthShared::generateNonce();

		$this->params_oauth['oauth_signature_method'] = $this->client->getSignatureMethod()->getName();
		$this->params_oauth['oauth_signature'] =
			$this->client->getSignatureMethod()->buildSignature($this, $this->client->getConsumer(), $this->token);

		if(empty($this->params_oauth['oauth_signature']))
		{
			throw new OAuthException('Signing the request completely and utterly failed.');
		}

		$this->signed = true;
	}

	/**
	 * @return bool The current parameters of this request have been signed.
	 **/
	public function isSigned() { return $this->signed; }

	/**
	 * Returns a string like "OAuth realm="...", oauth_token="..".
	 **/
	public function getAuthorizationHeader()
	{
		$result = 'OAuth ';

		$params = array();

		if(!empty($this->realm))
		{
			$params['realm'] = $this->realm;
		}

		// possible problem: if params_oauth contained a value named
		// realm, it would overwrite the real realm. It shouldn't, however.
		$params = array_merge($params, $this->params_oauth);

		foreach($params as $key => $value)
		{
			// we could also spread the header over multiple lines, but some very
			// stupid HTTP servers may not support that, so all goes on one line!
			$result .= OAuthShared::urlEncode($key) . '="' . OAuthShared::urlEncode($value) . '", ';
		}

		return rtrim($result, ', ');
	}

	public function setToken(OAuthToken $token = NULL)
	{
		$this->token = is_object($token) ? $token : $this->client->getToken();

		if(!is_null($token))
		{
			$this->params_oauth['oauth_token'] = $this->token->getToken();
		}
	}
}


class OAuthCurlClient extends OAuthClientBase
{
	protected $curl_handle = NULL;

	/**
	 * @see OAuthClientBase::__construct
	 **/
	public function __construct(OAuthConsumer $consumer, OAuthSignatureMethod $signature_method, OAuthToken $token = NULL)
	{
		parent::__construct($consumer, $signature_method, $token);

		OAuthShared::setUpCurl($this->curl_handle);
	}

	/**
	 * Executes the given request using libcurl.
	 * Returns an OAuthClientResponse instance or
	 * throws an OAuchException on errors.
	 * @return OAuthClientResponse
	 **/
	public function executeRequest(OAuthRequest $req)
	{
		$req->sign();

		$http_headers = array();

		// Use the Authorization header for oauth protocol parameters:
		$http_headers[] = 'Authorization: ' . $req->getAuthorizationHeader();

		// Add GET parameters to the URL:
		$url = $req->getRequestUrl(true);
		$query_str = OAuthShared::joinParametersMap($req->getGetParameters());
		if(!empty($query_str)) $url .= '?' . $query_str;

		curl_setopt($this->curl_handle, CURLOPT_URL, $url);

		// Add POST parameters, if there are any.
		if($req->getHttpMethod() == 'POST')
		{
			$http_headers[] = 'Expect:'; // avoid stupid HTTP status code 100.
			$http_headers[] = 'Content-Type: application/x-www-form-urlencoded';

			curl_setopt($this->curl_handle, CURLOPT_POST, true);
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, OAuthShared::joinParametersMap($req->getPostParameters()));
		}
		else
		{
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, array());
			curl_setopt($this->curl_handle, CURLOPT_HTTPGET, true);
		}

		$http_headers[] = 'Accept: application/x-www-form-urlencoded, application/json, text/xml, */*';

		curl_setopt($this->curl_handle, CURLOPT_HTTPHEADER, $http_headers);

		// Fetch the response synchronously:
		$response = curl_exec($this->curl_handle);
		$info = curl_getinfo($this->curl_handle);

		if(empty($response) || OAuthShared::getIfSet($info, 'http_code') == 0)
		{
			// :TODO: not happy we throw this one here, should be moved to the base client class.
			throw new OAuthException('Contacting the remote server failed due to a network error: ' . curl_error($this->curl_handle), 0);
		}

		// If we received some response, create an OAuthClientResponse instance from it.
		return OAuthClientResponse::fromResponseStr($this, $response);
	}

	/**
	 * Simple destructor, some cleanup, etc. Boring.
	 **/
	public function __destruct()
	{
		if($this->curl_handle)
		{
			curl_close($this->curl_handle);
		}
	}
}


class OAuthClientResponse
{
	protected $headers = array();
	protected $body;
	protected $status_code;
	protected $body_params = array();
	protected $client;

	/**
	 * Constructs a response instance from an HTTP response's headers and body.
	 * Will throw on 400 and 401 return codes, if an oauth_problem has been specified.
	 **/
	public function __construct(OAuthClientBase $client, array $headers, &$body, $status_code = 0)
	{
		$this->client = $client;

		// copy the body...
		$this->body = $body;

		// Update this->status_code, if necessary.
		// some derived classes may have set it already.
		if($status_code > 0)
		{
			$this->status_code = $status_code;
		}

		// need to lower case all header names :(
		foreach($headers as $key => $value)
		{
			$this->headers[strtolower($key)] = $value;
		}
		$headers = $this->headers;

		// will hold parameters from an www-form-urlencoded body:
		$body_params = array();

		// If the response content type is www-form-urlencoded, parse the body:
		if(preg_match('~^application/x-www-form-urlencoded~i', OAuthShared::getIfSet($headers, 'content-type', '')))
		{
			$body_params = OAuthShared::splitParametersMap($body);
		}

		if($this->status_code == 400 || $this->status_code == 401)
		{
			// The error codes 400 and 401 are suggested to have special meanings
			// in section 3.2. of the specs.
			$description = 'An error occured'; $problem = ''; $problem_extra_info = array();
			$problem_params = array();

			// If the server included a WWW-Authenticate response header,
			// it may include oauth_problem parameters. Therfore, parse it:
			if(isset($headers['www-authenticate']))
			{
				$problem_params = OAuthUtil::parseHttpAuthorizationHeader($headers['www-authenticate'], true);
				// :TODO: Maybe save the realm some place?
				unset($problem_params['realm']);
			}

			// If the WWW-Authenticate response header doesn't have an oauth_problem,
			// look for it in the body.
			if(empty($problem_params['oauth_problem']))
			{
				$problem_params = $body_params;
			}

			// Handle the oauth_problem parameter along the guidelines
			// that http://oauth.pbworks.com/ProblemReporting suggests.
			if(!empty($problem_params['oauth_problem']))
			{
				// We found an oauth_problem parameter. Let's identify it.
				$problem = $problem_params['oauth_problem'];
				unset($problem_params['oauth_problem']);

				// Form a human-readable problem description:
				$advice = $problem;

				if(!empty($problem_params['oauth_problem_advice']))
				{
					$advice .= ': ' . $problem_params['oauth_problem_advice'];
				}
				unset($problem_params['oauth_problem_advice']);

				// The rest of the parameters probably contains more useful
				// information about the error.
				$problem_extra_info = $problem_params;
				unset($problem_params);

				if(!empty($advice))
				{
					$description .= ' - ' . $advice;
				}

				// Bubble up this error.
				throw new OAuthException($description, $this->status_code, $problem, $problem_extra_info);
			}
		}

		$this->body_params = $body_params;
	}

	/**
	 * Constructs a response instance from a complete HTTP response string, including the headers.
	 **/
	public static function fromResponseStr(OAuthClientBase $client, &$complete_response_str)
	{
		$headers = array();
		$body = '';
		$status_code = 0;

		OAuthShared::splitHttpResponse('OAuthException', $complete_response_str, $headers, $body, $status_code);
		unset($complete_response_str);

		return new self($client, $headers, $body, $status_code);
	}

	/**
	 * Returns the HTTP status code. Most probably between 100 and 500-something.
	 **/
	public function getStatusCode()
	{
		return $this->status_code;
	}

	/**
	 * Returns the value of the HTTP header with the name $header_name.
	 **/
	public function getHeaderValue($header_name)
	{
		return OAuthShared::getIfSet($this->headers, strtolower($header_name), '');
	}

	/**
	 * If the body has been www-form-urlencoded, this method will return
	 * the value of the parameter that has the name $body_param_name.
	 **/
	public function getBodyParamValue($body_param_name)
	{
		return OAuthShared::getIfSet($this->body_params, $body_param_name, '');
	}

	/**
	 * Returns the entire response body as a string.
	 **/
	public function getBody()
	{
		return $this->body;
	}

	/**
	 * The existence of this method is an abomination. However,
	 * popular Web 2.0 service twitter sends their tokens as text/html
	 * instead of application/x-www-form-urlencoded, so here we go.
	 * This method parses the body of this response into parameters.
	 * Use getBodyParamValue after calling this method to get the parameters.
	 * @return boolean Returns true if any decent looking parameters have been extracted.
	 **/
	public function forceWwwEncodedBodyInterpretation()
	{
		$tmp = OAuthShared::splitParametersMap($this->body);

		if(is_array($tmp))
		{
			$this->body_params = $tmp;

			return (count($tmp) > 0);
		}

		return false;
	}
}

