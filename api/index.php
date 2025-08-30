<?php
error_reporting(0);
ini_set('display_errors', false);
ini_set('display_startup_errors', false);
date_default_timezone_set('Asia/Jakarta');

class VisitorIP
{
    private $authorized_proxies = [];
    function __construct($proxies = '')
    {
        if (is_string($proxies) && !empty(trim($proxies))) {
            $this->authorized_proxies = array_map('trim', explode(',', $proxies));
        } else if (is_array($proxies) && !empty($proxies)) {
            foreach ($proxies as $p) {
                if (is_string($p)) {
                    $p = trim($p);
                    if (static::get_ip_version($p)) {
                        $this->authorized_proxies[] = $p;
                    }
                }
            }
        } else {
            $this->authorized_proxies = !!$proxies;
        }
    }
    private function get_proxies()
    {
        return $this->authorized_proxies;
    }
    private static function get_ip_version(string $ip)
    {
        $ip = explode('/', $ip)[0];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 4;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 6;
        }
        return 0;
    }
    private static function ip_compare($ip, $other)
    {
        $ip_ver = static::get_ip_version($ip);
        if ($ip_ver != static::get_ip_version($other)) {
            return false;
        }
        switch ($ip_ver) {
            case 4:
                return $ip == $other;
            case 6:
                return inet_pton($ip) == inet_pton($other);
            default:
                return false;
        }
    }
    private static function inet_to_bits($inet)
    {
        $splitted = str_split($inet);
        $binaryip = '';
        foreach ($splitted as $char) {
            $binaryip .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        return $binaryip;
    }
    private static function ip_in_range(string $ip, string $range)
    {
        try {
            $ip_ver = static::get_ip_version($ip);
            if ($ip_ver != static::get_ip_version($range)) {
                return false;
            }
            switch ($ip_ver) {
                case 4:
                    list($subnet, $bits) = explode('/', $range);
                    if ($bits === null) {
                        $bits = 32;
                    }
                    $ip = ip2long($ip);
                    $subnet = ip2long($subnet);
                    $mask = -1 << (32 - $bits);
                    $subnet &= $mask;
                    return ($ip & $mask) == $subnet;
                case 6:
                    $ip = inet_pton($ip);
                    $binaryip = static::inet_to_bits($ip);

                    list($net, $maskbits) = explode('/', $range);
                    $net = inet_pton($net);
                    $binarynet = static::inet_to_bits($net);

                    $ip_net_bits = substr($binaryip, 0, $maskbits);
                    $net_bits = substr($binarynet, 0, $maskbits);
                    return $ip_net_bits == $net_bits;
                default:
                    return false;
            }
        } catch (Exception $e) {
            return false;
        }
    }
    public function get_client_ip()
    {
        $ip = '';
        $authorized_proxy = false;
        if (is_bool($this->authorized_proxies)) {
            $authorized_proxy = $this->authorized_proxies;
        } else if (!empty($this->authorized_proxies)) {
            foreach ($this->authorized_proxies as $p) {
                if (strpos($p, '/') !== false) {
                    if (static::ip_in_range($_SERVER['REMOTE_ADDR'], $p)) {
                        $authorized_proxy = true;
                        break;
                    }
                } else if (static::ip_compare($_SERVER['REMOTE_ADDR'], $p)) {
                    $authorized_proxy = true;
                    break;
                }
            }
        }
        if ($authorized_proxy) {
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $fwd_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                $ip = trim(end($fwd_ips));
            } else if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                $ip = $_SERVER['HTTP_CLIENT_IP'];
            }
        }
        if (!$ip) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
}

// Usage example
$visitorIP = new VisitorIP('');
$client_ip = $visitorIP->get_client_ip();

//check if the client IP is a valid IP address
if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    $client_ip = 'Invalid IP address: ' . $client_ip;
}
header("Content-Type: text/plain");
echo 'sasasasas' . PHP_EOL;

    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } elseif (isset($_SERVER['HTTP_X_REAL_IP'])) {
        $ip_address = $_SERVER['HTTP_X_REAL_IP'];
    } else {
        $ip_address = $_SERVER['REMOTE_ADDR'];
    }
echo 'ip_address: ' . $ip_address . PHP_EOL;


echo $client_ip;