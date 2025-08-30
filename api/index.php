<?php
error_reporting(0);
ini_set('display_errors', false);
ini_set('display_startup_errors', false);
date_default_timezone_set('Asia/Jakarta');

function get_client_ip()
{
    $ipaddress = '';
    if (isset($_SERVER['HTTP_CLIENT_IP']))
        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if (isset($_SERVER['HTTP_X_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    else if (isset($_SERVER['HTTP_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    else if (isset($_SERVER['HTTP_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_FORWARDED'];
    else if (isset($_SERVER['REMOTE_ADDR']))
        $ipaddress = $_SERVER['REMOTE_ADDR'];
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}

// Usage example
$client_ip = get_client_ip();

//check if the client IP is a valid IP address
if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    $client_ip = 'Invalid IP address: ' . $client_ip;
}


header("Content-Type: text/plain");

// if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
//     $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
// } elseif (isset($_SERVER['HTTP_X_REAL_IP'])) {
//     $ip_address = $_SERVER['HTTP_X_REAL_IP'];
// } else {
//     $ip_address = $_SERVER['REMOTE_ADDR'];
// }
// echo 'ip_address: ' . $ip_address . PHP_EOL;


echo $client_ip;
