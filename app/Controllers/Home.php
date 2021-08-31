<?php

namespace App\Controllers;

use \Firebase\JWT\JWT;
use App\Controllers\AuthController;
use codeigniter\RESTful\ResourceController;


header("Access-Control-Allow-Origin: * ");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");


class Home extends ResourceController
{
	public function __construct()
	{
		// inisialisasi class Auth dengan $this->protect
		$this->protect = new AuthController();
	}
	public function index()
	{
		$secret_key = $this->protect->privateKey();
		$token = null;
		$authHeader = $this->request->getServer('HTTP_AUTHORIZATION');
		$arr = explode(' ', $authHeader);
		$token = $arr[0];

		if ($token) {
			try {
				$decoded = JWT::decode($token, $secret_key, array('HS256'));
				// Access is granted. Add code of the operation here 
				if ($decoded) {
					// response true
					$output = [
						'message' => 'Access granted'
					];
					return $this->respond($output, 200);
				}
			} catch (\Exception $e) {
				$output = [
					'message' => 'Access denied',
					"error" => $e->getMessage()
				];

				return $this->respond($output, 401);
			}
		}
	}
}
