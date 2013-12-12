<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

namespace proauth;

/**
 * Defines an abstract base class (OAuthSignatureMethod) that
 * can be used for OAuth signature calculation and comparison.
 * Also defines some signature method implementations.
 **/

/**
 * The base class that all signature method classes have to be derived from.
 **/
abstract class OAuthSignatureMethod
{
	/**
	 * Must return the name of the method, e.g. HMAC-SHA1 or PLAINTEXT.
	 * @return string
	 **/
	abstract public function getName();
	/**
	 * Must build the signature string from the given parameters and return it.
	 * @return string
	 **/
	abstract public function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL);

	/**
	 * Compares the given $signature_string with the one that is defined by req, consumer and token.
	 * If $signature_string is NULL, the oauth_signature parameter from $req will be used.
	 * @return bool
	 **/
	public function checkSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL, $signature_string = NULL)
	{
		$correct_string = $this->buildSignature($req, $consumer, $token);

		if(is_null($signature_string))
		{
			$signature_string = $req->getSignatureParameter();
		}

		// extra checks to make sure we never allow obviously faulty signature strings:
		return (is_string($signature_string) &&
			is_string($correct_string) &&
			!empty($signature_string) &&
			strcmp($correct_string, $signature_string) == 0);
	}
}


/**
 * Implements the PLAINTEXT signature method, as defined by
 * section 3.4.4. of the specs.
 **/
class OAuthSignaturePlainText extends OAuthSignatureMethod
{
	public function getName()
	{
		return 'PLAINTEXT';
	}

	public function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL)
	{
		$key_parts = array(
			$consumer->getSecret(),
			is_object($token) ? $token->getSecret() : ''
		);

		$key_parts = OAuthShared::urlEncode($key_parts);
		return implode('&', $key_parts);
	}
}


/**
 * Implements the RSA-SHA signature method, as defined by
 * section 3.4.3. of the specs.
 * This is the most widespread and best tested and documented
 * method and should therefore be used in 99% of all cases.
 **/
class OAuthSignatureHMACSHA1 extends OAuthSignatureMethod
{
	public function getName()
	{
		return 'HMAC-SHA1';
	}

	/**
	 * @author Marc Worrell <marcw@pobox.com>
	 * @source http://code.google.com/p/oauth-php/source/browse/trunk/library/signature_method/OAuthSignatureMethod_HMAC_SHA1.php
	 **/
	public function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL)
	{
		$base_string = $req->getSignatureBaseString();

		$key_parts = array(
			$consumer->getSecret(),
			is_object($token) ? $token->getSecret() : ''
		);

		$key_parts = OAuthShared::urlEncode($key_parts);
		$key = implode('&', $key_parts);

		if(function_exists('hash_hmac'))
		{
			$hmac = hash_hmac('sha1', $base_string, $key, true);
		}
		else
		{
			// Fallback for PHP setups that do not have the hash extension.
			// The hash extension has been enabled by default since PHP 5.1.2,
			// but you never know.
			$blocksize = 64;

			if(strlen($key) > $blocksize)
			{
				$key = pack('H*', sha1($key));
			}

			$key = str_pad($key, $blocksize, chr(0x00));
			$ipad = str_repeat(chr(0x36), $blocksize);
			$opad = str_repeat(chr(0x5c), $blocksize);

			$hmac = pack('H*', sha1(($key ^ $opad) . pack('H*', sha1(($key ^ $ipad) . $base_string))));
		}

		// the result has to be base64 encoded.
		return base64_encode($hmac);
	}
}


/**
 * Implements a non-standard signature method called SALTED-MD5.
 * Don't use this one.
 **/
class OAuthSignatureSaltedMD5 extends OAuthSignatureMethod
{
	public function getName()
	{
		return 'SALTED-MD5';
	}

	public function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL)
	{
		$raw = $consumer->getSecret() . "\r\n" .
			$req->getSignatureBaseString() . "\r\n" .
			(is_object($token) ? $token->getSecret() : '');

		return strtolower(md5($raw));
	}
}


/**
 * Implements a non-standard signature method called HMAC-SHA256.
 * It follows the specs for HMAC-SHA1, but uses SHA256 instead of SHA1.
 * Definitely requires a PHP with the hash extension enabled.
 **/
class OAuthSignatureHMACSHA256 extends OAuthSignatureMethod
{
	public function getName()
	{
		return 'HMAC-SHA256';
	}

	public function buildSignature(OAuthRequest $req, OAuthConsumer $consumer, OAuthToken $token = NULL)
	{
		$base_string = $req->getSignatureBaseString();

		$key_parts = array(
			$consumer->getSecret(),
			is_object($token) ? $token->getSecret() : ''
		);

		$key_parts = OAuthShared::urlEncode($key_parts);
		$key = implode('&', $key_parts);

		return base64_encode(hash_hmac('sha256', $base_string, $key, true));
	}
}

