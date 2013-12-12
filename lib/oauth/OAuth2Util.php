<?php
/*
 * php-proauth (c) Ingmar "KiNgMaR" Runge 2009-2010
 * You are free to use this code under the terms of The MIT License.
 * You should have received a copy of The MIT License in LICENSE.txt with this file.
 */

namespace proauth;

require_once _OAUTH2_LIB_DIR . 'OAuthXShared.php';


class OAuth2Exception extends \Exception
{
	protected $error_idf;

	public function __construct($error_msg, $error_idf = '')
	{
		parent::__construct($error_msg);

		$this->error_idf = $error_idf;
	}

	public function getOAuthErrorId()
	{
		return $this->idf;
	}
}


class OAuth2AccessToken
{
	protected $access_token;
	protected $expires_at;
	protected $refresh_token;
	protected $token_secret;

	public function __construct($access_token, $expires_at = 0,
		$refresh_token = '', $access_token_secret = '')
	{
		$this->access_token = (string)$access_token;
		$this->expires_at = (int)$expires_at;
		$this->refresh_token = (string)$refresh_token;
		$this->token_secret = (string)$access_token_secret;
	}

	public function getToken() { return $this->access_token; }
	public function hasSecret() { return !empty($this->token_secret); }
	public function getSecret() { return $this->token_secret; }
	public function hasRefreshToken() { return !empty($this->refresh_token); }
	public function getRefreshToken() { return $this->refresh_token; }
	public function willExpire() { return ($this->expires_at > 0); }
	public function hasExpired() { return ($this->expires_at > 0 && $this->expires_at <= time()); }
	public function getExpiryTime() { return $this->expires_at; }

	/**
	 * Serializes this access token to a JSON string. Prefer this over
	 * serialize($token) when saving to a database etc.
	 * DO NOT save this in a cookie or in any other place where 3rd parties could
	 * read or even modify the data. DO NOT transfer it over the network, especially not via HTTP/AJAX.
	 * @return string
	 **/
	public function toJson()
	{
		$data = new stdClass();
		$data->v = 1;

		$data->token_s = $this->access_token;
		if(!empty($this->token_secret)) $data->secret_s = $this->token_secret;
		if($this->expires_at > 0) $data->expires_u = $this->expires_at;
		if(!empty($this->refresh_token)) $data->refr_token_s = $this->refresh_token;

		return json_encode($data);
	}

	/**
	 * Deserializes an access token that has been serialized using toJson().
	 * @see toJson
	 * @return false or instance of OAuth2AccessToken
	 **/
	public static function fromJson($data)
	{
		if(is_string($data))
		{
			$data = @json_decode($data);
		}

		if(is_object($data) && !empty($data->token_s))
		{
			return new self($data->token_s,
				(isset($data->expires_u) ? $data->expires_u : 0),
				(isset($data->refr_token_s) ? $data->refr_token_s : ''),
				(isset($data->token_secret) ? $data->token_secret : ''));
		}

		return false;
	}
}

