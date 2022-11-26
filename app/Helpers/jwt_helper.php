<?php

use Config\services;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\UserModel;

//*	****************************************************************************
//*	Extrae token del bearer token
//*	****************************************************************************
function getJwtRequest( $authorizationHeader)
{
	//*	Validar si existe bearer token
	if(is_null($authorizationHeader))
	{
		throw new \Exception('Error de autorización');
	}
	//*	Retornar solo token
	return explode(' ', $authorizationHeader)[1];
}
//*	****************************************************************************
//*	Crear token con Jwt
//*	****************************************************************************
function getSignedJwtUser(string $id)
{
	$time		=	time();
	$jwtTime	=	Services::getJwtTime();
	$jwtExpire	=	$time + $jwtTime;
	//*	Objeto de firma
	$payload = [
		'id'	=>	$id,
		'iat'	=>	$time,
		'exp'	=>	$jwtExpire,
	];
	//*	Crear token
	$token = JWT::encode($payload, Services::getJwtKey(), 'HS256');
	return $token;
}
//*	****************************************************************************
//*	Decodificar Token
//*	****************************************************************************
function decodeJwtRequest( string $token)
{
	//*	Obtener clave privada de Jwt
	$key = Services::getJwtKey();
	//*	Decodificar token
	$dataToken = JWT::decode($token, new Key($key, 'HS256'));
	//*	Recuperar información de usuario
	$userModel = new UserModel();
	$user = $userModel->find($dataToken->id);
	if(!$user)
	{
		throw new \Exception('Error de autorización');
	}
	return $user;
}