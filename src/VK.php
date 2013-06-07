<?php

class VK{
	
	private $app_id;
	private $secret;
	
	public function __construct($app_id, $secret){
		 $this->app_id=$app_id;
		 $this->secret=$secret;
	}
	
	public function app_id(){
		return $this->app_id;
	}
	
	public function calculateAuthKey($viewer_id){
		return md5($this->app_id.'_'.$viewer_id.'_'.$this->secret);
	}
	
	public function api($method, $params){
		$params['api_id'] = $this->app_id;
		$params['method'] = $method;
		$params['v'] = '3.0';
		$params['format'] = 'json';
		$params['random'] = rand(1, 9999);
		$params['timestamp'] = time();
		$params['sig']=$this->sign($params);
		
		$response=file_get_contents('http://api.vk.com/api.php?'.http_build_query($params));
		if(!$response=json_decode($response)){
			throw new VKException('VK API error');
		}
		return $response->response;
	}
	
	public function cookie(){
		if(!isset($_COOKIE['vk_app_'.$this->app_id])){
			throw new VKException('No VK cookie');
		}
		$data=array();
		$cookie=$_COOKIE['vk_app_'.$this->app_id];
		$cookie=explode('&', $cookie);
		foreach ($cookie as $value) {
			$value=explode('=', $value);
			$data[$value[0]]=$value[1];
		}
		return $data;
	}
	
	private function sign($params){
		$sign='';
		ksort($params);	
		foreach($params as $key=>$value){
			$sign.=$key.'='.$value;
		}
		$sign.=$this->secret;
		return md5($sign);
	}
	
}