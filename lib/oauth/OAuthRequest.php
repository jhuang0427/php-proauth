<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

/**
 * Class that wraps a request to an OAuth enabled API...
 * Will be used by OAuth clients/consumers and servers.
 **/
class OAuthRequest
{
	protected $http_method;
	protected $request_url;

	protected $params_get = array();
	protected $params_post = array();
	protected $params_oauth = array();

	protected $realm = '';

	/**
	 * Do not allow this class to be instantiated directly
	 * You will have to use one of OAuthServerRequest/OAuthClientRequest classes.
	 **/
	protected function __construct()
	{
	}

	/**
	 * Returns the signature base string, as defined by section 3.4.1. of the OAuth Core specs.
	 **/
	public function getSignatureBaseString()
	{
		$parts = array(
			$this->getHttpMethod(),
			$this->getRequestUrl(true),
			$this->getSignableParametersString()
		);

		$parts = OAuthShared::urlEncode($parts);

		return implode('&', $parts);
	}

	/**
	 * Returns a normalized string of all signable parameters, as defined
	 * by sections 3.4.1.3. and 3.4.1.3.2. of the OAuth Core specs.
	 **/
	protected function getSignableParametersString()
	{
		$params = array_merge($this->params_oauth, $this->params_get, $this->params_post);

		unset($params['oauth_signature']);

		// parameters are sorted by name, using lexicographical byte value ordering:
		uksort($params, 'strcmp');

		// again: we do not support multiple parameters with the same name!

		return OAuthShared::joinParametersMap($params);
	}

	/**
	 * Returns the OAuth protocol version this request uses.
	 **/
	public function getOAuthVersion()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_version', '1.0');
	}

	/**
	 * Returns the consumer key or false if none is set.
	 **/
	public function getConsumerKey()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_consumer_key', false);
	}

	/**
	 * Fills out the nonce and timestamp variables and returns true if both are non-empty.
	 **/
	public function getNonceAndTimeStamp(&$nonce, &$timestamp)
	{
		$nonce = OAuthShared::getIfSet($this->params_oauth, 'oauth_nonce', false);
		$timestamp = OAuthShared::getIfSet($this->params_oauth, 'oauth_timestamp', false);

		return (!empty($nonce) && !empty($timestamp));
	}

	/**
	 * Returns the signature method parameter's value or an empty string.
	 **/
	public function getSignatureMethod()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_signature_method', '');
	}

	/**
	 * Returns the signature parameter's value or an empty string.
	 **/
	public function getSignatureParameter()
	{
		return OAuthShared::getIfSet($this->params_oauth, 'oauth_signature', '');
	}

	/**
	 * Gets the realm value from/for the Authorization header.
	 **/
	public function getRealm()
	{
		return $this->realm;
	}

	/**
	 * Sets the realm value for the Authorization header.
	 **/
	public function setRealm($new_realm)
	{
		$this->realm = $new_realm;
	}

	/**
	 * @return string
	 **/
	public function getHttpMethod()
	{
		return strtoupper($this->http_method);
	}

	/**
	 * @return string
	 **/
	public function getRequestUrl($normalize = false)
	{
		if(!$normalize)
		{
			return $this->request_url;
		}
		else
		{
			return OAuthUtil::normalizeRequestURL($this->request_url);
		}
	}

	/**
	 * @return array
	 **/
	public function getPostParameters()
	{
		return $this->params_post;
	}

	/**
	 * @return array
	 **/
	public function getGetParameters()
	{
		return $this->params_get;
	}
}
