<?php
header("Content-Type: application/json");

class Api {
    private $publicKey;
    private $privateKey;

    public function __construct() {
        $this->publicKey = file_get_contents("keys/publicKey");
        $this->privateKey = file_get_contents("keys/privateKey");
    }

    public function handleRequest() {
        error_log("Handling request..."); 
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $headers = getallheaders();
        $body = file_get_contents('php://input');

        $response = [
            'method' => $method,
            'path' => $path,
            'headers' => $headers,
            'body' => json_decode($body, true),
        ];

        switch ($method) {
            case 'POST':
                switch ($path) {
                    case '/verify':
                        $response['message'] = $this->verify($body, $headers);
                        break;
                    case '/create':
                        $response['message'] = $this->create();
                        break;
                    default:
                        http_response_code(404);
                        $response['message'] = 'Not Found';
                        break;
                }
                break;
            default:
                http_response_code(405);
                $response['message'] = 'Method Not Allowed';
                break;
        }

        echo json_encode($response);
    }

    private function verify($body, $headers) {
        $encoded_body = hash("sha256", $body);
        $decodedSignature = base64_decode($headers['X-Auth-Signature']);

        $result = openssl_verify($body, $decodedSignature, $this->publicKey, OPENSSL_ALGO_SHA256);
        return $result;
    }

    function create() {
        $payload = [
            'a' => 'b'
        ];

        $data = json_encode($payload);

        $key = openssl_pkey_get_private($this->privateKey);
        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);
        $base64 = base64_encode($signature);

        return $base64;
    }
}

$api = new Api();
$api->handleRequest();
?>