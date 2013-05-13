<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */


/**
 * The base class that all signature method classes have to be derived from.
 **/
abstract class OAuth2SignatureMethod
{
	/**
	 * Must return the name of the method, e.g. 'hmac-sha256'
	 * @return string
	 **/
	abstract public function getName();

}


/**
 * Implements
 * 
 * Requires a PHP with the hash extension enabled.
 **/
class OAuth2SignatureHmacSha256 extends OAuth2SignatureMethod
{
	public function getName()
	{
		return 'hmac-sha256';
	}

}

