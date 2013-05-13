<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */


class OAuth2Request
{
	protected $http_method;
	protected $request_url;

	protected $params_get = array();
	protected $params_post = array();
	protected $params_header = array();

	/**
	 * Do not allow this class to be instantiated directly
	 * You will have to use one of OAuth2ServerRequest/OAuth2ClientRequest classes.
	 **/
	protected function __construct()
	{
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
	public function getRequestUrl()
	{
		return $this->request_url;
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
