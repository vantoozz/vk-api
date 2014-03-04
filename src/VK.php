<?php

class VK
{

    private $app_id;
    private $secret;
    private $verion;
    private $access_token = null;

    public function __construct($app_id, $secret, $version = '3.0')
    {
        $this->app_id = $app_id;
        $this->secret = $secret;
        $this->version = $version;
    }

    public function app_id()
    {
        return $this->app_id;
    }

    public function calculateAuthKey($viewer_id)
    {
        return md5($this->app_id . '_' . $viewer_id . '_' . $this->secret);
    }

    public function api5($method, $params)
    {
        if (!$this->access_token) {
            $this->access_token = $this->getServerAccessToken();
        }

        $params['v'] = $this->version;
        $params['client_secret'] = $this->secret;
        $params['access_token'] = $this->access_token;

        $response = file_get_contents('https://api.vk.com/method/' . $method . '?' . http_build_query($params));

        if (!$response = json_decode($response)) {
            throw new VKException('VK API error');
        }

        return $response;;
    }

    public function api($method, $params)
    {

        $params['api_id'] = $this->app_id;
        $params['method'] = $method;
        $params['v'] = $this->version;
        $params['format'] = 'json';
        $params['random'] = rand(1, 9999);
        $params['timestamp'] = time();
        $params['sig'] = $this->sign($params);

        $response = file_get_contents('https://api.vk.com/api.php?' . http_build_query($params));

        if (!$response = json_decode($response)) {
            throw new VKException('VK API error');
        }
        return $response->response;
    }

    public function getServerAccessToken()
    {

        $params = array(
            'client_id' => $this->app_id,
            'client_secret' => $this->secret,
            'v' => $this->verion,
            'grant_type' => 'client_credentials',
        );

        $response = file_get_contents('https://oauth.vk.com/access_token?' . http_build_query($params));

        if (!$response = json_decode($response)) {
            throw new VKException('VK API error');
        }

        if (!isset($response->access_token)) {
            throw new VKException('VK API error');
        }
        return $response->access_token;
    }

    public function parseCookie()
    {
        $session = array();
        $member = false;
        if (!isset($_COOKIE['vk_app_' . $this->app_id])) {
            return false;
        }
        $valid_keys = array('expire', 'mid', 'secret', 'sid', 'sig');
        $app_cookie = $_COOKIE['vk_app_' . $this->app_id];
        if ($app_cookie) {
            $session_data = explode('&', $app_cookie, 10);
            foreach ($session_data as $pair) {
                list($key, $value) = explode('=', $pair, 2);
                if (empty($key) || empty($value) || !in_array($key, $valid_keys)) {
                    continue;
                }
                $session[$key] = $value;
            }
            foreach ($valid_keys as $key) {
                if (!isset($session[$key])) {
                    return $member;
                }
            }
            ksort($session);

            $sign = '';
            foreach ($session as $key => $value) {
                if ($key != 'sig') {
                    $sign .= ($key . '=' . $value);
                }
            }
            $sign .= $this->secret;
            $sign = md5($sign);
            if ($session['sig'] == $sign && $session['expire'] > time()) {
                $member = array(
                    'id' => intval($session['mid']),
                    'secret' => $session['secret'],
                    'sid' => $session['sid']
                );
            }
        }
        return $member;
    }

    public function cookie()
    {
        if (!isset($_COOKIE['vk_app_' . $this->app_id])) {
            throw new VKException('No VK cookie');
        }
        $data = array();
        $cookie = $_COOKIE['vk_app_' . $this->app_id];
        $cookie = explode('&', $cookie);
        foreach ($cookie as $value) {
            $value = explode('=', $value);
            $data[$value[0]] = $value[1];
        }
        return $data;
    }

    private function sign($params)
    {
        $sign = '';
        ksort($params);
        foreach ($params as $key => $value) {
            $sign .= $key . '=' . $value;
        }
        $sign .= $this->secret;
        return md5($sign);
    }

}
