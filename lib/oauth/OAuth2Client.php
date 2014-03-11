<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

namespace proauth;

if(!defined('_OAUTH2_LIB_DIR'))
{
	define('_OAUTH2_LIB_DIR', dirname(__FILE__) . '/');
}

require_once _OAUTH2_LIB_DIR . 'OAuth2Util.php';
require_once _OAUTH2_LIB_DIR . 'OAuth2Request.php';
require_once _OAUTH2_LIB_DIR . 'OAuth2Signature.php';


/* some constants for OAuth2AccessTokenObtainer's constructor */

define('OAUTH2_FLOW_USER_AGENT', 1);
define('OAUTH2_FLOW_WEB_SERVER', 2);
define('OAUTH2_FLOW_DEVICE', 3);
define('OAUTH2_FLOW_USER_PASS', 4);
define('OAUTH2_FLOW_CLIENT_CREDENTIALS', 5);
define('OAUTH2_FLOW_ASSERTION', 6);

// please note that the values of the above constants have to match
// the order in the array in OAuth2AccessTokenObtainer::__construct.


abstract class OAuth2ClientBase
{
	/**
	 * Endpoint URLs
	 **/
	protected $url_authorization, $url_token;
	/**
	 * Client ID and optional secret
	 **/
	protected $client_id, $client_secret;
	/**
	 * If an access token has been obtained (previously or just now),
	 * it will be stored here.
	 * @type OAuth2AccessToken
	 **/
	protected $access_token = NULL;
	/**
	 * An instance of a class derived from OAuth2SignatureMethod
	 **/
	protected $access_secret_type = NULL;
	/**
	 * Whether making requests using a 'bearer token' (=without secret) and therefore
	 * without cryptographic signature over a plain text channel is allowed.
	 **/
	protected $allow_unprotected = false;


	public function __construct(OAuth2AccessToken $access_token = NULL)
	{
		$this->access_token = $access_token;
	}

	/**
	 * Sets the endpoint URLs that are used for obtaining and refreshing access tokens.
	 **/
	public function setEndpoints($url_authorization, $url_token)
	{
		if(filter_var($url_authorization, FILTER_VALIDATE_URL) && preg_match('~^https://.+$~ui', $url_authorization))
		{
			$this->url_authorization = $url_authorization;
		}
		else
		{
			throw new OAuth2Exception('Invalid authorization endpoint URL. Needs to be a valid https:// URL.');
		}

		if(filter_var($url_token, FILTER_VALIDATE_URL) && preg_match('~^https://.+$~ui', $url_token))
		{
			$this->url_token = $url_token;
		}
		else
		{
			throw new OAuth2Exception('Invalid token endpoint URL. Needs to be a valid https:// URL.');
		}
	}

	/**
	 * Sets the client ID and an optional secret string that is used for
	 * obtaining and refreshing access tokens.
	 **/
	public function setClientId($id, $secret = NULL)
	{
		$this->client_id = (string)$id;
		$this->client_secret = (string)$secret;
	}

	public function getAuthEndpointUrl() { return $this->url_authorization; }
	public function getTokenEndpointUrl() { return $this->url_token; }

	public function getClientId() { return $this->client_id; }
	public function getClientSecret() { return $this->client_secret; }

	public function getAllowUnprotected() { return $this->allow_unprotected; }
	public function setAllowUnprotected($b) { $this->allow_unprotected = (bool)$b; }

	/**
	 * All auth flows besides 'device' can optionally issue a token+secret instead
	 * of a bearer token. To enable this behavior, make sure to set up a signature
	 * method that your target server supports.
	 **/
	public function setAccessSecretType(OAuth2SignatureMethod $inst)
	{
		$this->access_secret_type = $inst;
	}

	public function getAccessSecretType()
	{
		return $this->access_secret_type;
	}

	public function _setAccessToken(OAuth2AccessToken $token)
	{
		$this->access_token = $token;
	}

	public function getAccessToken()
	{
		return $this->access_token;
	}

	/**
	 * @see OAuth2AccessTokenObtainer
	 * @return OAuth2AccessTokenObtainer
	 **/
	public function getAccessTokenObtainer($flow_type)
	{
		return new OAuth2AccessTokenObtainer($flow_type, $this);
	}

	/**
	 * returns an OAuth2ClientRequest instance that can be set up further, as necessary, and then
	 * be submitted.
	 * @return OAuth2ClientRequest
	 **/
	public function createRequest($url, array $get_params = array(), array $post_params = array())
	{
		$req = new OAuth2ClientRequest((count($post_params) > 0 ? 'POST' : 'GET'), $url,
			$this->getAccessToken(), $this->getAccessSecretType(), $this->getAllowUnprotected());

		$req->setGetParameters($get_params);
		$req->setPostParameters($post_params);

		return $req;
	}

	/**
	 * @see createRequest
	 * @return OAuth2ClientRequest
	 **/
	public function createPostRequest($url, array $params)
	{
		if(count($params) == 0)
		{
			throw new OAuth2Exception('Can not make a POST request without any parameters.');
		}

		return $this->createRequest($url, array(), $params);
	}

	/**
	 * @see createRequest
	 * @return OAuth2ClientRequest
	 **/
	public function createGetRequest($url, array $params = array())
	{
		return $this->createRequest($url, $params, array());
	}

	/**
	 * @return OAuth2ClientResponse
	 **/
	abstract public function executeRequest(OAuth2ClientRequest $req);
	/**
	 * @return string, response incl. headers
	 **/
	abstract public function doSimplePostRequest($url, array $post_params, array $request_headers = array());
	/**
	 * @return string, response incl. headers
	 **/
	abstract public function doSimpleGetRequest($url, array $get_params, array $request_headers = array());
}


class OAuth2CurlClient extends OAuth2ClientBase
{
	protected $curl_handle;

	public function __construct(OAuth2AccessToken $access_token = NULL)
	{
		parent::__construct($access_token);

		OAuthShared::setUpCurl($this->curl_handle);
	}

	public function executeRequest(OAuth2ClientRequest $req)
	{
		$req->sign();

		$headers = array(
				'Authorization: ' . $req->getAuthorizationHeader()
			);

		$raw_response = $this->doSimpleRequest($req->getHttpMethod() == 'POST',
			$req->getRequestUrl(), $req->getGetParameters(), $req->getPostParameters(),
			$headers);

		return OAuth2ClientResponse::fromResponseStr($raw_response);
	}

	protected function doSimpleRequest($post, $url, array $get_params, array $post_params, array $request_headers = array())
	{
		$query_str = OAuthShared::joinParametersMap($get_params);

		if(!empty($query_str))
		{
			$url .= (strpos($url, '?') === false ? '?' : '&'); // this feels hacky...
			$url .= $query_str;
		}

		curl_setopt($this->curl_handle, CURLOPT_URL, $url);

		if($post)
		{
			$request_headers[] = 'Expect:'; // avoid stupid HTTP status code 100.
			$request_headers[] = 'Content-Type: application/x-www-form-urlencoded';

			curl_setopt($this->curl_handle, CURLOPT_POST, true);
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, OAuthShared::joinParametersMap($post_params));
		}
		else
		{
			curl_setopt($this->curl_handle, CURLOPT_POSTFIELDS, array());
			curl_setopt($this->curl_handle, CURLOPT_HTTPGET, true);
		}

		$request_headers[] = 'Accept: application/x-www-form-urlencoded, application/json, text/xml, */*';

		curl_setopt($this->curl_handle, CURLOPT_HTTPHEADER, $request_headers);

		$response = curl_exec($this->curl_handle);
		$info = curl_getinfo($this->curl_handle);

		if(empty($response) || OAuthShared::getIfSet($info, 'http_code') == 0)
		{
			throw new OAuth2Exception('Contacting the remote server failed due to a network error: ' . curl_error($this->curl_handle), 0);
		}

		return $response;
	}

	public function doSimplePostRequest($url, array $post_params, array $request_headers = array())
	{
		return $this->doSimpleRequest(true, $url, array(), $post_params, $request_headers);
	}

	public function doSimpleGetRequest($url, array $get_params, array $request_headers = array())
	{
		return $this->doSimpleRequest(false, $url, $get_params, array(), $request_headers);
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


class OAuth2AccessTokenObtainer
{
	protected $flow_type;
	protected $client;

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $redirect_uri;

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $state_string = '';

	/**
	 * Used for: user_agent and web_server
	 **/
	protected $immediate = false;


	public function __construct($flow_type, OAuth2ClientBase $client_instance)
	{
		$valid_flow_types = array('user_agent', 'web_server', 'device',
			'username', 'client_cred', 'assertion');

		if(is_string($flow_type) && in_array($flow_type, $valid_flow_types))
		{
			$this->flow_type = $flow_type;
		}
		else
		{
			$type_index = (int)$flow_type;

			if($type_index > 0 && $type_index <= count($valid_flow_types))
			{
				$this->flow_type = $valid_flow_types[$type_index];
			}
			else
			{
				throw new OAuth2Exception('Unknown Access Token Auth Flow Type.');
			}
		}

		/*** :TODO: ***/
		if($this->flow_type != 'user_agent' && $this->flow_type != 'web_server')
		{
			throw new OAuth2Exception('Sorry, this version of the library only supports the ' .
				'user_agent and web_server authentication flow types.');
		}
		/*** :TODO: ***/

		$this->client = $client_instance;
	}

	public function setRedirectUrl($url)
	{
		if(filter_var($url, FILTER_VALIDATE_URL))
		{
			$this->redirect_url = $url;
		}
		else
		{
			throw new OAuth2Exception('Invalid redirect URL.');
		}
	}

	public function setStateData($data)
	{
		$this->state_string = (string)$data;
	}

	public function getStateData() { return $this->state_string; }

	public function setImmediate($bool)
	{
		$this->immediate = (bool)$bool;
	}

	/**
	 * Use this for the user_agent and web_server authentication flows.
	 * It returns the URL of the authorization endpoint where you should redirect
	 * your visitor's browser to. You can use @webFlowRedirect to do that.
	 * Working in full accordance with sections 3.5.1.1. and 3.5.2.1. of the oauth2 draft.
	 **/
	public function webFlowGetRedirectUrl(array $additional_params = array())
	{
		if($this->flow_type != 'user_agent' && $this->flow_type != 'web_server')
		{
			throw new Exception('You cannot use webFlowGetRedirectUrl() with authentication flow types other than user_agent and web_server.');
		}

		$url = $this->client->getAuthEndpointUrl();

		if(empty($url))
		{
			throw new OAuth2Exception('The client class instance has not been assigned an authorization endpoint URL.');
		}

		$params = array('type' => $this->flow_type,
			'client_id' => $this->client->getClientId());

		if(empty($params['client_id']))
		{
			throw new OAuth2Exception('The client class instance is missing a client ID.');
		}

		if(!empty($this->redirect_url))
		{
			$params['redirect_uri'] = $this->redirect_url;
		}

		if(!empty($this->state_string))
		{
			if(strpos($this->redirect_url, '?') !== false)
			{
				throw new OAuth2Exception('You can not set a state parameter and use a query ' .
					'string in the redirect URL at the same time.');
			}

			$params['state'] = $this->state_string;
		}

		$params['immediate'] = ($this->immediate ? 'true' : 'false');

		if($this->flow_type == 'user_agent' && !is_null($this->client->getAccessSecretType()))
		{
			// the user_agent flow can optionally receive a secret with the access token.
			$params['secret_type'] = $this->client->getAccessSecretType()->getName();
		}

		$params = array_merge($additional_params, $params);

		return $url . '?' . http_build_query($params, '', '&');
	}

	/**
	 * @see webFlowGetRedirectUrl
	 **/
	public function webFlowRedirect(array $additional_params = array())
	{
		$url = $this->webFlowGetRedirectUrl($additional_params);
		header('HTTP/1.0 302 Found');
		header('Location: ' . $url);
	}

	/**
	 * Used for the web_server flow. Call this to extract the information from the
	 * query string the authorization server put together.
	 * If the user authorized the app, you can use @getStateData etc.
	 * IMPORTANT: Before calling this, you need to use setRedirectUrl to set the redirect URL to
	 * the exact same value as you did during the first redirect request (i.e. call to webFlowRedirect).
	 **/
	public function webServerDidUserAuthorize()
	{
		if($this->flow_type != 'web_server')
		{
			throw new Exception('You cannot use webServerDidUserAuthorize() with an authentication flow type other than web_server.');
		}

		// extract the state string (= user data):
		$this->state_string = OAuthShared::getIfSet($_GET, 'state', '');

		// check for the error parameter:
		$error = OAuthShared::getIfSet($_GET, 'error');

		if($error == 'user_denied')
		{
			return false;
		}
		elseif(!empty($error))
		{
			throw new OAuth2Exception('Unknown error parameter!', $error);
		}

		$code = OAuthShared::getIfset($_GET, 'code');

		if(empty($code))
		{
			throw new OAuth2Exception('Missing code parameter! The auth server should have redirect here using ?code=xxxx');
		}

		// no error parameter has been passed, we have a code, so the user should have authorized the app.

		$params = array('type' => 'web_server',
			'client_id' => $this->client->getClientId(),
			'code' => $code);

		if(empty($params['client_id']))
		{
			throw new OAuth2Exception('The client class instance is missing a client ID.');
		}

		$clnt_secret = $this->client->getClientSecret();
		if(!empty($clnt_secret))
		{
			$params['client_secret'] = $clnt_secret;
		}

		if(!empty($this->redirect_url))
		{
			$params['redirect_uri'] = $this->redirect_url;
		}

		if(!is_null($this->client->getAccessSecretType()))
		{
			// the user_agent flow can optionally receive a secret with the access token.
			$params['secret_type'] = $this->client->getAccessSecretType()->getName();
		}

		$http_response = $this->client->doSimplePostRequest($this->client->getTokenEndpointURL(), $params);

		$headers = array();
		$body = '';
		$status_code = 0;

		OAuthShared::splitHttpResponse('proauth\OAuth2Exception', $http_response, $headers, $body, $status_code);
		unset($http_response);

		if($status_code != 200)
		{
			throw new OAuth2Exception('While fetching the access token, the server did not return an OK status code.');
		}

		/* Yay for servers not adhering to the specs when it comes to simple things like the correct Content-Type...
			... so we don't check the Content-Type header for now. We will later, so FIX YOUR SHIT! */

		// get response params:
		$params = OAuthShared::splitParametersMap($body);

		if(empty($params['access_token']))
		{
			throw new OAuth2Exception('The server replied, but did not deliver an access token.');
		}

		if(empty($params['access_token_secret']) && !is_null($this->client->getAccessSecretType()))
		{
			throw new OAuth2Exception('We requested a cryptographic secret with the token, but the server did not deliver one.');
		}

		$expires = (int)OAuthShared::getIfSet($params, 'expires_in', 0);
		if($expires > 0) $expires += time();

		$token = new OAuth2AccessToken($params['access_token'], $expires,
			OAuthShared::getIfSet($params, 'refresh_token', ''),
			OAuthShared::getIfSet($params, 'access_token_secret', ''));

		$this->client->_setAccessToken($token);

		return true;
	}
}


class OAuth2ClientRequest extends OAuth2Request
{
	protected $timestamp = 0;
	protected $nonce = '';

	/**
	 * @type OAuth2AccessToken instance
	 **/
	protected $access_token = NULL;
	/**
	 * @type OAuth2SignatureMethod instance
	 **/
	protected $secret_sig_method = NULL;

	protected $signed = false;

	/**
	 * Usually invoked by and through OAuth2ClientBase.
	 **/
	public function __construct($http_method, $url, OAuth2AccessToken $token,
		OAuth2SignatureMethod $sig_method = NULL, $allow_unprotected = false)
	{
		parent::__construct();

		if(!is_null($sig_method) && !$token->hasSecret())
		{
			throw new OAuth2Exception('Can\'t sign a token without a secret. Did you really intend to specify a signature method?');
		}

		$this->access_token = $token;
		$this->secret_sig_method = $sig_method;

		if(strcasecmp($http_method, 'POST') && strcasecmp($http_method, 'GET'))
		{
			throw new OAuth2Exception('Unsupported HTTP method "' . $http_method . '" in OAuth2ClientRequest.');
		}

		if(!filter_var($url, FILTER_VALIDATE_URL))
		{
			throw new OAuth2Exception('Invalid URL "' . $url . '" to OAuth2ClientRequest.');
		}

		if(!$allow_unprotected && is_null($sig_method) &&
			strcasecmp(parse_url($url, PHP_URL_SCHEME), 'https') != 0)
		{
			throw new OAuth2Exception('Trying to make a request without a token secret over an unencrypted channel. ' .
				'Use OAuth2Client->setAllowUnprotected(true) to allow this.');
		}

		$this->http_method = strtoupper($http_method);
		$this->request_url = $url;
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
	 * @return bool Whether the current parameters of this request have been signed.
	 **/
	public function isSigned()
	{
		return $this->signed;
	}

	/**
	 * Signs the request. You are asked to immediately send it to the
	 * Service Provider after signing it.
	 **/
	public function sign()
	{
		$this->params_header = array('token' => $this->access_token->getToken());

		if(!is_null($this->secret_sig_method))
		{
			// :TODO: Only add timestamp+nonce if the signature method requires it.
			$this->params_header['nonce'] = OAuthShared::generateNonce();
			$this->params_header['timestamp'] = time();
			$this->params_header['algorithm'] = $this->secret_sig_method->getName();

			$this->params_header['signature'] = '';//:TODO:
		}

		$this->signed = true;
	}

	/**
	 * Returns the contents of the HTTP Authorization header that need(s) to be
	 * used for making the request to the protected resource.
	 **/
	public function getAuthorizationHeader()
	{
		$result = 'Token ';

		foreach($this->params_header as $key => $value)
		{
			if(strpos($value, '"') !== false)
			{
				throw new OAuth2Exception('There\'s a quote char in one of the parameters for the Authorization header. This isn\'t supposed to happen.');
			}

			// :TODO: find out whether this really is not supposed to be urlEncoded.
			$result .= $key . '="' . $value . '", ';
		}

		return rtrim($result, ', ');
	}

}


class OAuth2ClientResponse
{
	protected $headers = array();
	protected $body;
	protected $status_code;

	/**
	 * Constructs a response instance from an HTTP response's headers and body.
	 **/
	public function __construct(array $headers, &$body, $status_code = 0)
	{
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
	}

	/**
	 * Constructs a response instance from a complete HTTP response string, including the headers.
	 **/
	public static function fromResponseStr($complete_response_str)
	{
		$headers = array();
		$body = '';
		$status_code = 0;

		OAuthShared::splitHttpResponse('proauth\OAuth2Exception', $complete_response_str, $headers, $body, $status_code);
		unset($complete_response_str);

		return new self($headers, $body, $status_code);
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
	 * Returns the entire response body as a string.
	 **/
	public function getBody()
	{
		return $this->body;
	}
}
