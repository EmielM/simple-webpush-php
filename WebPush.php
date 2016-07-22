<?php

class WebPush {

	static $curve = [
		'a' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC', // equivalent to -3
		'b' => '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
		'p' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
	];

	// Generate your own key like this: 
	// openssl ecparam -name prime256v1 -genkey > webpush.pem
	// openssl ec -in webpush.pem -param_out -param_enc explicit -text
	static $serverPub = '
		04:aa:fc:72:69:4b:19:7f:f7:74:43:36:7f:be:98:
		4d:73:9f:a8:5d:d4:28:67:32:8b:8d:9f:85:02:c9:
		55:57:a3:6e:57:9c:cd:ef:b3:b5:31:4a:a1:5a:a7:
		b3:4d:43:dd:5d:14:2f:4b:63:1e:df:d4:cd:8b:d7:
		53:46:2b:d3:91
	';
	static $serverPriv = '
		00:a6:50:81:de:8b:d3:ce:1d:0c:da:3f:0c:a0:5f:
		b0:3e:89:be:ac:32:f3:ba:60:fa:c7:fb:75:b1:53:
		af:65:cd
	';

	// Obtain your key in google api console if you want to send to chrome
	static $gcmKey = 'WQRFasasSdv-8EASqwifhus7kjhs_kjASwihusU';

	// $sub example: [
	//   'endpoint' => 'https://android.googleapis.com/...',
	//   'keys' => ['p256dh' => 'xxxx', 'auth' => 'xxxx']
	// ]
	// $payload a string that will be passed to the service worker push event handler

	static function send($sub, $payload)
	{
		$d = bin2hex(base64_decode(strtr($sub['keys']['p256dh'], '-_', '+/')));
		assert(substr($d,0,2) == '04');
		$clientPub = [
			'x' => substr($d, 2, strlen($d) / 2 - 1),
			'y' => substr($d, strlen($d) / 2 + 1)
		];

		$serverPub = preg_replace('/[\s:]/', '', self::$serverPub);
		$serverPriv = preg_replace('/[\s:]/', '', self::$serverPriv);

		$curve = self::$curve;

		assert(substr($serverPub,0,2) == '04');

		$point = self::mul(
			['a' => gmp_init($curve['a'],16), 'b' => gmp_init($curve['b'], 16), 'p' => gmp_init($curve['p'], 16)],
			['x' => gmp_init($clientPub['x'],16), 'y' => gmp_init($clientPub['y'],16)],
			gmp_init($serverPriv, 16)
		);

		$sharedSecret = gmp_strval($point['x'], 16);
		if (strlen($sharedSecret)%2) $sharedSecret = '0'.$sharedSecret; // pad because hex2bin works byte-aligned

		$salt = openssl_random_pseudo_bytes(16);

		$d = base64_decode(strtr($sub['keys']['auth'], '-_', '+/'));

		$ikm = self::hkdf($d, hex2bin($sharedSecret), 'Content-Encoding: auth'.chr(0), 32);

		$clientPubBin = hex2bin('04' . $clientPub['x'] . $clientPub['y']);
		$serverPubBin = hex2bin($serverPub);
		assert(strlen($clientPubBin) == 65 && strlen($serverPubBin) == 65);

		$context = chr(0).chr(0).'A'.$clientPubBin.chr(0).'A'.$serverPubBin;

		$key = self::hkdf($salt, $ikm, 'Content-Encoding: aesgcm'.chr(0).'P-256'.$context, 16);
		$nonce = self::hkdf($salt, $ikm, 'Content-Encoding: nonce'.chr(0).'P-256'.$context, 12);

		$payload = chr(0).chr(0).$payload;

		$tag = null;

		// when upgraded to php7.1 use:
		// $encrypted = openssl_encrypt($payload, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
		list($encrypted, $tag) = AESGCM::encrypt($key, $nonce, $payload, "");

		$body = $encrypted.$tag;

		$salt = rtrim(strtr(base64_encode($salt), '+/', '-_'), '=');
		$dh = rtrim(strtr(base64_encode($serverPubBin), '+/', '-_'), '=');

		$headers = [
			'Content-Length' => strlen($body),
			'Content-Type' => 'application/octet-stream',
			'Content-Encoding' => 'aesgcm',
			'Encryption' => 'keyid="p256dh";salt="'.$salt.'"',
			'Crypto-Key' => 'keyid="p256dh";dh="'.$dh.'"',
			'TTL' => '2419200'
		];

		$url = $sub['endpoint'];
		if (substr($url,0,39) == 'https://android.googleapis.com/gcm/send') {
			$headers['Authorization'] = 'key='.self::$gcmKey;
			$url = 'https://gcm-http.googleapis.com/gcm'.substr($url,39); // apparently temporarily, other endpoint doesn't always support webpush
		}

		$c = curl_init();
		curl_setopt_array($c, [
			CURLOPT_POST => true,
			CURLOPT_URL => $url,
			CURLOPT_POSTFIELDS => $body,
			CURLOPT_HTTPHEADER => $x = array_map(
				function($k,$v) { return $k.': '.$v; },
				array_keys($headers), array_values($headers)
			),
			CURLOPT_RETURNTRANSFER => true,
		]);
		curl_exec($c);

		return curl_getinfo($c, CURLINFO_HTTP_CODE) == 201;
	}

    static function hkdf($salt, $ikm, $info, $length){
		// hmac-based extract-and-expand key derivation
		$prk = hash_hmac('sha256', $ikm, $salt, true);
		return substr(hash_hmac('sha256', $info.chr(1), $prk, true), 0, $length);
    }

	// Simple elliptic curve multiplication, because always roll your own crypto.
	// Don't use for anything serious, but probably usable for simple WebPush payload DH key generation
	// Based on https://github.com/phpecc/phpecc, which is rather extensive.
	// Limited to Elliptic curve point multiplication, using gmp for bignum handling
	
	static function add($curve, $p1, $p2) {

		if ($p1=='infinity') return $p2;
		if ($p2=='infinity') return $p1;

		if (gmp_cmp($p1['x'], $p2['x']) == 0) {
			if (gmp_cmp($p1['y'], $p2['y']) == 0) {
				return self::double($curve, $p1);
			} else {
				// what does this mean? different y for same x
				return ['x' => 0, 'y' => 0];
			}
		}

		$slope = self::modDiv(gmp_sub($p2['y'], $p1['y']), gmp_sub($p2['x'], $p1['x']), $curve['p']);
		$x = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $p1['x']), $p2['x']), $curve['p']);
		$y = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($p1['x'], $x)), $p1['y']), $curve['p']);

		return ['x' => $x, 'y' => $y];
	}

	static function modDiv($n,$d,$p) {
		return gmp_mod(gmp_mul($n, gmp_invert($d,$p)), $p);
	}

	static function double($curve, $p1) {

		if ($p1=='infinity') return 'infinity';

		$threeX2 = gmp_mul(3, gmp_pow($p1['x'], 2));

		$tangent = self::modDiv(gmp_add($threeX2, $curve['a']), gmp_mul(2, $p1['y']), $curve['p']);

		$x = gmp_mod( gmp_sub(gmp_pow($tangent, 2), gmp_mul(2, $p1['x'])), $curve['p']);
		$y = gmp_mod( gmp_sub(gmp_mul($tangent, gmp_sub($p1['x'], $x)), $p1['y']), $curve['p']);

		return ['x' => $x, 'y' => $y];
	}

	static function mul($curve, $p1, $n) {

		if ($p1 == 'infinity' || gmp_cmp($n,0)==0) {
			return 'infinity';
		}

		$q = 'infinity';
		$b = gmp_strval($n, 2);
		for ($i = 0; $i < strlen($b); $i++) {
			$q = self::double($curve, $q);
			if ($b[$i]) {
				$q = self::add($curve,$q,$p1);
			}
		}

		return $q;
	}
}

