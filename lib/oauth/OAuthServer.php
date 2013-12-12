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
require_once _OAUTH_LIB_DIR . 'OAuthServerBackend.php';


class OAuthServer
{
	protected $backend;
	protected $user_data = NULL;
	protected $signature_methods = array();
	protected $superglobals_auto_export;

	/**
	 * @param OAuthServerBackend backend The backend. Yeah.
	 * @param bool superglobals_auto_export If true, OAuthServerRequest parameters validated against \
	 *   this class will be exported as $_GET, $_POST and $_REQUEST automatically.
	 **/
	public function __construct(OAuthServerBackend $backend, $superglobals_auto_export = false)
	{
		$this->backend = $backend;
		$this->superglobals_auto_export = $superglobals_auto_export;
	}

	/**
	 * Registers a supported signature method.
	 **/
	public function addSignatureMethod(OAuthSignatureMethod $method)
	{
		$this->signature_methods[strtoupper($method->getName())] = $method;
	}

	/**
	 * For internal use, checks if the OAuth version of $req is okay.
	 **/
	protected function checkOAuthVersion(OAuthServerRequest $req)
	{
		$version = $req->getOAuthVersion();

		if(!version_compare($version, '1.0', '=='))
		{
			throw new OAuthException('OAuth version "' . $version . '" is not supported!',
				400, 'version_rejected', array('oauth_acceptable_versions' => '1.0-1.0'));
		}

		return $version;
	}

	/**
	 * For internal use, returns an OAuthConsumer instance.
	 **/
	protected function getConsumer(OAuthServerRequest $req)
	{
		$consumer_key = $req->getConsumerKey();

		if(!$consumer_key)
		{
			throw new OAuthException('Invalid consumer key.', 401, 'consumer_key_unknown');
		}

		$consumer = $this->backend->getConsumerByKey($consumer_key);

		if($consumer === OAuthServerBackend::RESULT_RATE_LIMITED)
		{
			throw new OAuthException('Too many requests have been made. Throttling.', 401, 'consumer_key_refused');
		}
		elseif($consumer === OAuthServerBackend::RESULT_DISABLED)
		{
			throw new OAuthException('This consumer key has been disabled permanently.', 401, 'consumer_key_rejected');
		}
		elseif($consumer === OAuthServerBackend::RESULT_NOT_FOUND)
		{
			throw new OAuthException('Consumer not found.', 500);
		}
		elseif(!$consumer instanceof OAuthConsumer)
		{
			throw new OAuthException('Backend returned an incorrect value from getConsumerByKey');
		}

		return $consumer;
	}

	/**
	 * For internal use, returns the appropriate OAuthSignatureMethod instance.
	 **/
	protected function getSignatureMethod(OAuthServerRequest $req)
	{
		$method = strtoupper($req->getSignatureMethod());

		if(!isset($this->signature_methods[$method]))
		{
			throw new OAuthException('Signature method "' . $method . '" not supported.', 400, 'signature_method_rejected');
		}

		return $this->signature_methods[$method];
	}

	/**
	 * For internal use, checks nonce, timestamp and token!
	 **/
	protected function checkSignature(OAuthServerRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL)
	{
		$req->getNonceAndTimeStamp($nonce, $timestamp);

		$result = $this->backend->checkNonceAndTimeStamp($nonce, (int)$timestamp, $consumer, $token);

		if($result == OAuthServerBackend::RESULT_OK)
		{
			$sig_method = $this->getSignatureMethod($req);

			if(!$sig_method->checkSignature($req, $consumer, $token))
			{
				throw new OAuthException('Invalid signature.', 401, 'signature_invalid');
			}

			if($this->superglobals_auto_export)
			{
				$req->exportAsSuperglobals();
			}
		}
		elseif($result == OAuthServerBackend::RESULT_DUPE_NONCE)
		{
			throw new OAuthException('A previously used nonce has been used again.', 401, 'nonce_used');
		}
		elseif($result == OAuthServerBackend::RESULT_BAD_TIMESTAMP)
		{
			throw new OAuthException('The request timestamp is invalid.', 401, 'timestamp_refused');
		}
		elseif($result == OAuthServerBackend::RESULT_BAD_TOKEN)
		{
			throw new OAuthException('The token is invalid, or has expired.', 401, 'token_rejected');
		}
		else
		{
			throw new OAuthException('Backend returned an incorrect value from checkNonceAndTimeStamp');
		}
	}

	/**
	 * Auth Flow Server API: Implements section 2.1. "Temporary Credentials" of the OAuth Core specs.
	 **/
	public function requestToken()
	{
		$req = new OAuthServerRequest();

		// check basic premises...
		$this->checkOAuthVersion($req);

		$consumer = $this->getConsumer($req);

		// this request does not require a token.
		$this->checkSignature($req, $consumer, NULL);

		// store a callback_url, if we have one:
		$callback_url = $req->getCallbackParameter();

		// generate a temp secret:
		$temp_secret = OAuthShared::randomString(40);

		do
		{
			// and a temp token:
			$new_token = new OAuthToken(OAuthShared::randomString(20), $temp_secret);
			// and validate it with the backend to make sure it's unique:
			$result = $this->backend->addTempToken($consumer, $new_token, $callback_url);
		} while($result == OAuthServerBackend::RESULT_DUPE);

		if($result != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('Creating a temporary token failed.');
		}

		// The specs say "oauth_callback_confirmed: MUST be present and set to true.
		// The parameter is used to differentiate from previous versions of the protocol."
		// But we feel free to also use "false", if no callback was given.
		$new_token->setAdditionalParam('oauth_callback_confirmed', (empty($callback_url) ? 'false' : 'true'));

		return $new_token;
	}

	/**
	 * Auth Flow Server API: Implements the first part of section
	 * 2.2. "Resource Owner Authorization" of the OAuth Core specs.
	 * @param user_idf string
	 **/
	public function authorize_checkToken($token_str, $user_idf, $callback_url)
	{
		$consumer = NULL;

		if($this->backend->checkTempToken($token_str, $user_idf, $callback_url, $consumer) != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('The token is invalid, or has expired.', 401, 'token_rejected');
		}

		// ok, nice, the request seems to be okay. Cool.
		// The server frontend can now render the "Hello user, plz authorize this app!" page.
		return $consumer;
	}

	/**
	 * Auth Flow Server API: Implements the second part of section 2.2.
	 **/
	public function authorize_result($token_str, $user_idf, $authorized)
	{
		// We do not need to check for an OAuthRequest, since this won't be one.
		if($authorized)
		{
			$callback_url = $this->backend->getTempTokenCallback($token_str, $user_idf);

			if($this->backend->validateCallbackURL($token_str, $callback_url) != OAuthServerBackend::RESULT_OK ||
				($callback_url != 'oob' && !filter_var($callback_url, FILTER_VALIDATE_URL)))
			{
				throw new OAuthException('The backend failed to deliver a valid callback for this temporary token!');
			}

			$verifier = $this->backend->generateVerifier($callback_url);
			$redirect = false;

			if($this->backend->authorizeTempToken($token_str, $user_idf, $verifier, $redirect) != OAuthServerBackend::RESULT_OK)
			{
				throw new OAuthException('Backend was unable to authorize the temporary token!');
			}

			if($redirect)
			{
				if(filter_var($callback_url, FILTER_VALIDATE_URL))
				{
					$oauth_params = array('oauth_token' => $token_str, 'oauth_verifier' => $verifier);

					// merge the oauth_token and oauth_verifier parameters and possible
					// parameters from a query string in $callback_url. Pretty gross.
					$url = OAuthUtil::normalizeRequestURL($callback_url) . '?';

					$params = array();
					parse_str(parse_url($callback_url, PHP_URL_QUERY), $params);

					$params = array_merge($params, $oauth_params);

					header('HTTP/1.0 301 Permanently Moved'); // :TODO: send a more appropriate status code.
					header('Location: ' . $url . http_build_query($params, '', '&'));
				}
				else
				{
					throw new OAuthException('The client failed to provide a valid oauth_callback!');
				}
			}

			return true;
		}
		else
		{
			if($this->backend->deleteTempToken($token_str, $user_idf) != OAuthServerBackend::RESULT_OK)
			{
				throw new OAuthException('Backend was unable to revoke the temporary token!');
			}
		}

		return true;
	}

	/**
	 * Auth Flow Server API: Implements section 2.3. "Token Credentials".
	 **/
	public function accessToken()
	{
		$req = new OAuthServerRequest();

		$this->checkOAuthVersion($req);

		$consumer = $this->getConsumer($req);

		$token_str = $req->getTokenParameter();
		$token_secret = '';

		// this request has to be signed using the temporary credentials.

		if($this->backend->checkAuthedTempToken($consumer, $token_str, $token_secret) != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('The token is invalid, or has expired.', 401, 'token_rejected');
		}

		if(empty($token_secret))
		{
			throw new OAuthException('Empty token secret in OAuthServer::accessToken.');
		}

		$token = new OAuthToken($token_str, $token_secret);

		$this->checkSignature($req, $consumer, $token);

		$access_secret = OAuthShared::randomString(40);

		if($this->backend->checkVerifier($token_str, $req->getVerifierParameter()) != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('The provided oauth_verifier did not match the token.', 401, 'verifier_invalid');
		}

		do
		{
			$new_token = new OAuthToken(OAuthShared::randomString(20), $access_secret);
			$result = $this->backend->exchangeTempToken($consumer, $token, $new_token);
		} while($result == OAuthServerBackend::RESULT_DUPE);

		if($result != OAuthServerBackend::RESULT_OK)
		{
			throw new OAuthException('Creating an authorized token failed.');
		}

		return $new_token;
	}

	/**
	 * Use this method to verify an API call and its parameters.
	 * If the verification succeeds, you can use the parameters from $_GET and $_POST.
	 * @param bool requires_user Defines whether the call needs a user or if a valid consumer and signature are enough. \
	 *  If this is false, but the request still has a non-empty oauth_token, the user data will be checked and returned as usual.
	 * @return mixed Returns the user data that the backend associated with the access_token session.
	 **/
	public function verifyApiCall($requires_user = true)
	{
		$req = new OAuthServerRequest();

		$this->checkOAuthVersion($req);

		$consumer = $this->getConsumer($req);

		$token = NULL;
		$user_data = true;
		$token_str = $req->getTokenParameter();

		if($requires_user || !empty($token_str))
		{
			$token_secret = '';
			$user_data = NULL;

			$result = $this->backend->getAccessTokenInfo($consumer, $token_str, $token_secret, $user_data);
			if($consumer === OAuthServerBackend::RESULT_RATE_LIMITED)
			{
				throw new OAuthException('Too many requests have been made. Throttling.', 401, 'user_refused');
			}
			elseif($result == OAuthServerBackend::RESULT_OPERATION_NOT_PERMITTED)
			{
				throw new OAuthException('Operation not permitted.', 401, 'permission_denied');
			}
			elseif($result != OAuthServerBackend::RESULT_OK)
			{
				throw new OAuthException('The token is invalid, or has expired.', 401, 'token_rejected');
			}

			$token = new OAuthToken($token_str, $token_secret);
		}
		// If no user is required (and the token is empty), we only check the signature
		// with the consumer credentials, oauth version and signature.
		// If it's nice, we return true, and throw otherwise.

		$this->checkSignature($req, $consumer, $token);

		return $user_data;
	}
}


class OAuthServerRequest extends OAuthRequest
{
	public function __construct()
	{
		parent::__construct();

		// Determine HTTP method...
		$this->http_method = OAuthShared::getIfSet($_SERVER, 'REQUEST_METHOD');

		if(empty($this->http_method))
		{
			// :TODO: find out if this actually happens and how bad the fallback is.
			$this->http_method = (count($_POST) > 0 ? 'POST' : 'GET');
		}


		// Determine request URL:
		$host = OAuthShared::getIfSet($_SERVER, 'HTTP_HOST');

		if(empty($host))
		{
			throw new OAuthException('The requesting client did not send the HTTP Host header which is required by this implementation.', 400);
		}

		$scheme = (OAuthShared::getIfSet($_SERVER, 'HTTPS', 'off') === 'on' ? 'https' : 'http');

		$port = (int)$_SERVER['SERVER_PORT'];

		if(preg_match('~^(.+):(\d+)$~', $host, $match))
		{
			if(false)
			{
				// this check breaks with NAT and mod_proxy and stuff. :TODO: figure it out.
				if((int)$match[2] != $port)
				{
					throw new OAuthException('Bad port in the HTTP Host header.', 400);
				}
			}
			else
			{
				$port = (int)$match[2];
			}

			$host = $match[1];
		}

		// courtesy: http://stackoverflow.com/questions/106179/regular-expression-to-match-hostname-or-ip-address
		if(!preg_match('~^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$~', $host)
			&& !filter_var($host, FILTER_VALIDATE_IP))
		{
			throw new OAuthException('Invalid HTTP Host header.', 400);
		}

		$this->request_url = $scheme . '://' . $host .
			($port == ($scheme == 'https' ? 443 : 80) ? '' : ':' . $port) .
			$_SERVER['REQUEST_URI'];

		if(!filter_var($this->request_url, FILTER_VALIDATE_URL))
		{
			throw new OAuthException('Unable to form a valid URL from the request.');
		}

		$page_request_headers = OAuthUtil::getPageRequestHeaders();

		// extract oauth parameters from the Authorization
		// HTTP header. If present, these take precedence over
		// GET and POST parameters.
		$header_parameters = OAuthShared::getIfSet($page_request_headers, 'authorization');

		if(!empty($header_parameters))
		{
			$header_parameters = OAuthUtil::parseHttpAuthorizationHeader($header_parameters);
			$realm = '';

			if(is_array($header_parameters) && count($header_parameters) > 0)
			{
				$realm = OAuthShared::getIfSet($header_parameters, 'realm');
				unset($header_parameters['realm']);

				$this->params_oauth = $header_parameters;
			}

			$this->setRealm($realm);
		}

		// The next paragraphs refers to sections 3.4.1.3.1. and 3.5. of the OAuth Core specs.

		// We rely on PHP to parse the $_POST and $_GET parameters for us.
		// This *could* break in some weird cases, but I am not aware of any
		// situation out in the wild where that would happen. PHP uses
		// urldecode() to decode the parameters, which works in accordance to
		// section 3.4.1.3.1. of the Core specs.
		// C.f. OAuthShared::urlDecode()

		$this->params_post = array();
		$this->params_get = array();

		$content_type = trim(OAuthShared::getIfSet($page_request_headers, 'content-type'));

		if(preg_match('~^application/x-www-form-urlencoded~i', $content_type))
		{
			// extract POST parameters...
			foreach($_POST as $key => $value)
			{
				if(OAuthUtil::isKnownOAuthParameter($key))
				{
					if(!isset($this->params_oauth[$key]))
					{
						$this->params_oauth[$key] = $value;
					}
					else
					{
						throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.', 400);
					}
				}
				else
				{
					$this->params_post[$key] = $value;
				}
			}
		}

		// extract GET parameters...
		foreach($_GET as $key => $value)
		{
			if(OAuthUtil::isKnownOAuthParameter($key))
			{
				if(!isset($this->params_oauth[$key]))
				{
					$this->params_oauth[$key] = $value;
				}
				else
				{
					throw new OAuthException('You cannot specify the "' . $key . '" parameter multiple times.', 400);
				}
			}
			else
			{
				if(isset($this->params_post[$key]))
				{
					throw new OAuthException('We do not support GET and POST parameters with the same name.', 400);
				}

				$this->params_get[$key] = $value;
			}
		}

		// whew, done with the parameter extraction.

		if(count($this->params_oauth) == 0)
		{
			// the Service Provider can now send
			// header('WWW-Authenticate: OAuth realm="http://sp.example.com/"');
			// if he deems it necessary.
			throw new NonOAuthRequestException();
		}
	}

	/**
	 * Overwrites the $_GET, $_POST and $_REQUEST superglobals with the data from this
	 * request. They won't contain any known oauth_ parameters and $_REQUEST will
	 * be cookie-parameter free.
	 **/
	public function exportAsSuperglobals()
	{
		// POST parameters would take precedence here, but we do not
		// support POST and GET parameters of the same name, so
		// yeah. Just writing this down here so we know later.
		$_REQUEST = array_merge($this->params_get, $this->params_post);

		$_GET = $this->params_get;
		$_POST = $this->params_post;

		// we cannot validate file uploads right now,
		// if there were any files, $_POST will be empty too
		// (because Content-Type isn't application/x-www-form-urlencoded)
		$_FILES = array();
	}

	/**
	 * Returns the oauth_callback parameter's value or an empty string.
	 **/
	public function getCallbackParameter()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_callback', '');
	}

	/**
	 * Returns the oauth_token parameter's value or an empty string.
	 **/
	public function getTokenParameter()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_token', '');
	}

	/**
	 * Returns the oauth_verifier parameter's value or an empty string.
	 **/
	public function getVerifierParameter()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_verifier', '');
	}
}


class NonOAuthRequestException extends Exception {}
