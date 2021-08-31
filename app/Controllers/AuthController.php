<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use App\Models\AuthModel;
use \Firebase\JWT\JWT;


class AuthController extends ResourceController
{
	function __construct()
	{
		$this->auth = new AuthModel();
	}
	public function privateKey()
	{
		$privateKey = <<<EOD
            -----BEGIN RSA PRIVATE KEY-----
            MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
            vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
            5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
            AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
            bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
            Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
            cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
            5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
            ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
            k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
            qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
            eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
            B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
            -----END RSA PRIVATE KEY-----
            EOD;
		return $privateKey;
	}
	public function register()
	{
		$firstname  = $this->request->getPost('first_name');
		$lastname   = $this->request->getPost('last_name');
		$email      = $this->request->getPost('email');
		$password   = $this->request->getPost('password');

		$password_hash = password_hash($password, PASSWORD_BCRYPT);

		$data = json_decode(file_get_contents("php://input"));

		$dataRegister = [
			'first_name' => $firstname,
			'last_name' => $lastname,
			'email' => $email,
			'password' => $password_hash
		];

		$register = $this->auth->register($dataRegister);

		if ($register == true) {
			$output = [
				'status' => 200,
				'message' => 'Berhasil register'
			];
			return $this->respond($output, 200);
		} else {
			$output = [
				'status' => 400,
				'message' => 'Gagal register'
			];
			return $this->respond($output, 400);
		}
	}
	public function login()
	{
		$email      = $this->request->getPost('email');
		$password   = $this->request->getPost('password');

		$cek_login = $this->auth->cek_login($email);

		// var_dump($cek_login['password']);

		if (password_verify($password, $cek_login['password'])) {
			$secret_key = $this->privateKey();
			$issuer_claim = "THE_CLAIM"; // this can be the servername. Example: https://domain.com
			$audience_claim = "THE_AUDIENCE";
			$issuedat_claim = time(); // issued at
			$notbefore_claim = $issuedat_claim + 10; //not before in seconds
			$expire_claim = $issuedat_claim + 3600; // expire time in seconds
			$token = array(
				"iss" => $issuer_claim,
				"aud" => $audience_claim,
				"iat" => $issuedat_claim,
				"nbf" => $notbefore_claim,
				"exp" => $expire_claim,
				"data" => array(
					"id" => $cek_login['id'],
					"firstname" => $cek_login['first_name'],
					"lastname" => $cek_login['last_name'],
					"email" => $cek_login['email']
				)
			);

			$token = JWT::encode($token, $secret_key);

			$output = [
				'status' => 200,
				'message' => 'Berhasil login',
				"token" => $token,
				"email" => $email,
				"expireAt" => $expire_claim
			];
			return $this->respond($output, 200);
		} else {
			$output = [
				'status' => 401,
				'message' => 'Login failed',
				"password" => $password
			];
			return $this->respond($output, 401);
		}
	}
	public function showAll()
	{
		$data = $this->auth->findAll();
		return $this->respond($data, 200);
	}
	public function show($id = null)
	{
		$data =  $this->auth->getWhere(['id' => $id])->getResult();
		if ($data) {
			return $this->respond($data);
		} else {
			return $this->failNotFound();
		}
	}
	public function update($id = null)
	{

		$json = $this->request->getJSON();
		if ($json) {
			$data = [
				'first_name' => $json->first_name,
				'last_name' => $json->last_name,
				'email' => $json->email,
				'password' => $json->email,
			];
		} else {
			$input = $this->request->getRawInput();
			$data = [
				'first_name' => $input['first_name'],
				'last_name' => $input['last_name'],
				'email' => $input['email'],
				'password' => $input['password']
			];
		}
		// Insert to Database
		$this->auth->update($id, $data);
		$response = [
			'status'   => 200,
			'error'    => null,
			'messages' => [
				'success' => 'Data Updated'
			]
		];
		return $this->respond($response);
	}
	public function delete($id = null)
	{
		$data = $this->auth->find($id);
		if ($data) {
			$this->auth->delete($id);
			$response = [
				'status'   => 200,
				'error'    => null,
				'messages' => [
					'success' => 'Data Deleted'
				]
			];

			return $this->respondDeleted($response);
		} else {
			return $this->failNotFound('No Data Found with id ' . $id);
		}
	}
}
