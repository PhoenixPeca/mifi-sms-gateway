<?php
$host = $_GET['host'];

$time = time().rand(pow(10, 3-1), pow(10, 3)-1);
$GnCount = 1;
function doLogin($username1, $passwd1) {
	global $host, $time, $GnCount, $nonce, $AuthQop, $Authrealm, $username, $passwd;

	$url = "http://".$host."/login.cgi?_=".$time;
	//$loginParam = trim(str_replace('WWW-Authenticate:' , '', @get_headers($url)[1]));
	$loginParam = 'Digest realm="Highwmg", nonce="14555168", qop="auth"';
	$GnCount++;

	if(!empty($loginParam)) {
		$loginParamArray = explode(' ',$loginParam);
		if($loginParamArray[0] == "Digest") {
			$Authrealm = trim(substr($loginParamArray[1], strpos($loginParamArray[1], "=") + 1), '", ');
            $nonce = trim(substr($loginParamArray[2], strpos($loginParamArray[2], "=") + 1), '", ');
            $AuthQop = trim(substr($loginParamArray[3], strpos($loginParamArray[3], "=") + 1), '", ');
			
			$username = $username1;
            $passwd = $passwd1;
			
			$HA1 = md5($username.":".$Authrealm.":".$passwd);
			$HA2 = md5("GET".":"."/cgi/protected.cgi");
			
			
			$rand = floor(rand(0, 100001));
			$date = $time;
			$salt = $rand.$date;
			$tmp = md5($salt);
			$AuthCnonce = substr($tmp, 0, 16);
			
			$DigestRes = md5($HA1.":".$nonce.":"."00000001".":".$AuthCnonce.":".$AuthQop.":".$HA2);
			
			$url = "http://".$host."/login.cgi";
			$url = $url."?Action=Digest&username=".$username."&realm=".$Authrealm."&nonce=".$nonce."&response=".$DigestRes."&qop=".$AuthQop."&cnonce=".$AuthCnonce."&temp=marvell&_=".$time;
			
			$credsin['username'] = $username;
			$credsin['Authrealm'] = $Authrealm;
			$credsin['passwd'] = $passwd;
			$credsin['nonce'] = $nonce;
			$credsin['AuthQop'] = $AuthQop;

			$header = getAuthHeader('GET',$credsin);

			$opts = array(
			  'http' => array(
				'method' => "GET",
				'header' => "Authorization: ".$header."\r\n"
			  )
			);
			$context = stream_context_create($opts);
			$outHeaders = @get_headers($url, false, $context);

			if(strpos($outHeaders[0], '200 OK') !== false) {
				return true;
			} else {
				return false;
			}
		}
	}
}

function getAuthHeader($requestType, $credsin) {
	global $GnCount;
	$username = $credsin['username'];
	$Authrealm = $credsin['Authrealm'];
	$passwd = $credsin['passwd'];
	$nonce = $credsin['nonce'];
	$AuthQop = $credsin['AuthQop'];
	
	$HA1 = md5($username.":".$Authrealm.":".$passwd);
	$HA2 = md5($requestType.":"."/cgi/xml_action.cgi");

	$rand = floor(rand(0, 100001));
	$date = time();
	$salt = $rand.$date;
	$tmp = md5($salt);
    $AuthCnonce_f = substr($tmp,0,16);	
	
    $strhex = dechex(strval($GnCount));
    $temp = sprintf("%08s", $strhex);
    $Authcount = strtoupper(substr($temp, strlen($temp)-8));
    $DigestRes = md5($HA1.":".$nonce.":".$Authcount.":".$AuthCnonce_f.":".$AuthQop.":".$HA2);

    $strAuthHeader = "Digest "."username=\"".$username."\", realm=\"".$Authrealm."\", nonce=\"".$nonce."\", uri=\""."/cgi/xml_action.cgi"."\", response=\"".$DigestRes."\", qop=".$AuthQop.", nc=".$Authcount.", cnonce=\"".$AuthCnonce_f."\"";
    return $strAuthHeader;
}

function message_compose($number, $string) {
	$number = intval($number);
	if(empty($string) || empty($number)) {
		die('002 EMPTY_MESSAGE_ARGUMENTS');
	}
	if(strlen($string) >= 764) {
		die('003 MESSAGE_TOO_LONG');
	}
	$encoded_msg = substr(unpack('H*', iconv("UTF-8", "UTF-16", $string))[1], 4);
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
	<RGW>
	   <message>
		  <flag>
			 <message_flag>SEND_SMS</message_flag>
			 <sms_cmd>4</sms_cmd>
		  </flag>
		  <send_save_message>
			 <contacts>$number</contacts>
			 <content>$encoded_msg</content>
			 <encode_type>GSM7_default</encode_type>
			 <sms_time>".date('y,n,j,g,').intval(date('i')).','.intval(date('s')).','.date('O')."</sms_time>
		  </send_save_message>
	   </message>
	</RGW>";
}

function doRequestGET($file) {
	global $host, $time, $GnCount, $nonce, $AuthQop, $Authrealm, $username, $passwd;
	$url = "http://".$host."/xml_action.cgi?method=get&module=duster&file=".$file;
	$GnCount++;

	$credsin['username'] = $username;
	$credsin['Authrealm'] = $Authrealm;
	$credsin['passwd'] = $passwd;
	$credsin['nonce'] = $nonce;
	$credsin['AuthQop'] = $AuthQop;

	$header = getAuthHeader('GET',$credsin);
	$opts = array(
	  'http' => array(
		'method' => "GET",
		'header' => "Authorization: ".$header."\r\n"
	  )
	);
	$context = stream_context_create($opts);
	$outHeaders = @file_get_contents($url, false, $context);
	return $outHeaders;
}

function doRequestSET($file, $content) {
	global $host, $time, $GnCount, $nonce, $AuthQop, $Authrealm, $username, $passwd;
	$url = "http://".$host."/xml_action.cgi?method=set&module=duster&file=".$file;
	$GnCount++;	

	$credsin['username'] = $username;
	$credsin['Authrealm'] = $Authrealm;
	$credsin['passwd'] = $passwd;
	$credsin['nonce'] = $nonce;
	$credsin['AuthQop'] = $AuthQop;
	
	$header = getAuthHeader('POST', $credsin);
	$opts = array(
	  'http' => array(
		'method' => "POST",
		'header' => "Authorization: ".$header."\r\n" .
					"Content-Type: application/x-www-form-urlencoded\r\n" .
					"X-Requested-With: XMLHttpRequest\r\n",
		'content' => $content
	  )
	);
	$context = stream_context_create($opts);
	$outHeaders = @file_get_contents($url, false, $context);
	return $outHeaders;
}


if(doLogin($_GET['authuser'], $_GET['authpass'])) {
	if(doRequestSET('message', message_compose($_GET['num'], $_GET['msg']))) {
		echo "200 MESSAGE_SENT";
	} else {
		echo "001 ACTION_FAILED";
	}
} else {
	echo "401 UNAUTHORIZED_ACCESS";
}
