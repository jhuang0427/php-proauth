<?php

namespace proauth;

abstract class OAuthServerBackend
{
	const RESULT_ERROR = -1;
	const RESULT_OK = 1;
	const RESULT_DUPE = 2;

	const RESULT_RATE_LIMITED = 3;
	const RESULT_NOT_FOUND = 4;
	const RESULT_DISABLED = 5;

	const RESULT_DUPE_NONCE = 6;
	const RESULT_BAD_TIMESTAMP = 7;
	const RESULT_BAD_TOKEN = 8;
	const RESULT_OPERATION_NOT_PERMITTED = 9;

	/**
	 * @param string consumer_key
	 * @return mixed Return an OAuthConsumer instance, or one of: RESULT_RATE_LIMITED, RESULT_DISABLED, RESULT_NOT_FOUND
	 **/
	abstract public function getConsumerByKey($consumer_key);

	/**
	 * @return int One of: RESULT_OK, RESULT_DUPE_NONCE, RESULT_BAD_TIMESTAMP, RESULT_BAD_TOKEN
	 **/
	abstract public function checkNonceAndTimeStamp($nonce, $timestamp, OAuthConsumer $consumer, OAuthToken $token = NULL);

	/**
	 * Creates a new temporary token/key pair, associated with $consumer and optionally $callback_url.
	 * @return int One of: RESULT_DUPE (the token string is already used), RESULT_OK, RESULT_ERROR
	 **/
	abstract public function addTempToken(OAuthConsumer $consumer, OAuthToken $new_token, $callback_url);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function checkTempToken($token_str, $user_idf, $callback_url, &$consumer);

	/**
	 * If authorizing the temp token succeeded, the backend can set $redirect = true to redirect
	 * to the callback URL or display the verifier to the user using other means (with $redirect = false).
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function authorizeTempToken($token_str, $user_idf, $verifier, &$redirect);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function checkAuthedTempToken(OAuthConsumer $consumer, $token_str, &$token_secret);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function deleteTempToken($token_str, $user_idf);

	/**
	 * @return string
	 **/
	abstract public function getTempTokenCallback($token_str, $user_idf);

	/**
	 * @return string
	 **/
	abstract public function generateVerifier($callback_url);

	/**
	 * @return int One of: RESULT_DUPE (the token string is already used), RESULT_OK
	 **/
	abstract public function exchangeTempToken(OAuthConsumer $consumer, OAuthToken $temp_token, OAuthToken $new_token);

	/**
	 * @return int Return RESULT_OK, RESULT_RATE_LIMITED or RESULT_ERROR.
	 **/
	abstract public function getAccessTokenInfo(OAuthConsumer $consumer, $token_str, &$token_secret, &$user_data);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function checkVerifier($token_str, $verifier);

	/**
	 * @return int Return RESULT_OK or RESULT_ERROR.
	 **/
	abstract public function validateCallbackURL($token_str, $url);
}

