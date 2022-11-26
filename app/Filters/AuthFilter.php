<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\API\ResponseTrait;
use Config\Services;

class AuthFilter implements FilterInterface
{
	use ResponseTrait;
	public function before(RequestInterface $request
		, $arguments = null)
	{
		//*	Obtener datos autentificación
		$authenticationHeader = $request->getServer('HTTP_AUTHORIZATION');
		try {
			//*	*****************************************************
			//*	Jwt
			//*	*****************************************************
			helper('jwt');
			$token = getJwtRequest($authenticationHeader);
			$dataToken = decodeJwtRequest($token);
			//*	*****************************************************
			//*	Embeber información de usuario en la solicitud
			//*	*****************************************************
			$request->user = $dataToken;
			$request->token = $token;
			return $request;
		} catch (\Exception $e) {
			return Services::response()
				->setJSON([['general' => $e->getMessage()]])
				->setStatusCode(ResponseInterface::HTTP_UNAUTHORIZED);
		}
	}

	public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
	{}
}
