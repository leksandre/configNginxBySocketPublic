<?php
/**
 * Created by PhpStorm.
 * User:
 * Date: 12/01/2020
 * Time: 19:56
 */

require_once(ROOTPATH . '/../app/extensions/components/AuthMiddleware.php');
require_once(ROOTPATH . '/../app/extensions/components/ValidationHelper.php');
require_once(ROOTPATH . '/../app/extensions/components/Request.php');

require_once 'vendor/autoload.php';

use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints as Assert;

class Restapi8nginxController extends ApiController {

    /*
        * instance of class for logs messaging
    */
    public $RabbitMessaging;

    /*
        * default portal
    */
    public $tenantPortal;
    /*
        * default shortner
    */
    public $server_short;
    /**
     * Create and initialize the controller
     */

    //    public function __construct()
    //    {
    //    }

    /**
     * find and return regex template string by name
     *
     * @param string $assertName
     * @param array $options
     *
     * @return Assert\Regex
     */
    public function getDefaultRegexAssert($assertName, $options = null)
    {
        return ValidationHelper::getDefaultRegexAssert($assertName, $options);
    }

    /**
     * Action for create new config file for domain
     */
    public function actionCreateConfig()
    {
        $this->tenantPortal = '';
        $this->server_short = '';
        $this->RabbitMessaging = new OrganizerRabbitSimple();
        try {
            $data = $this->checkAuth();
            $body = Request::rawParams('application/json');
            $res = $this->createNewConfig(Yii::app()->db, $body, $data);
        } catch (Error $error) {
            $res = $this->catchAnyThrowable($error, 400, $error->getMessage(), $error->getMessage(), false);
        }
        $this->sendResponse($res['code'], $res['body']);
    }

    /**
     * The function for creating new config file for nginx
     *
     * @param EDbConnection $connection
     * @param array $params
     * @param $authData
     *
     * @return array
     */
    public function createNewConfig(EDbConnection $connection, array $params, $authData) : array
    {
        $fields = $params; //['fields']; //        $files = $params['files'];
        if (!isset($authData['user']['id'])) { //isset($authData['object']['id']) or

            return [
                'code' => '500',
                'body' => 'only bc user could maked this operation',
            ];
        }
        if (stripos($fields['domain'] ?? '', '/') > 0) {
            $arr = explode('/', $fields['domain']);
            if (isset($arr[0]) and isset($arr[1])) {
                $fields['domain'] = $arr[0];
            }
        }
        //dd($authData);
        $constraint = new Assert\Collection(
            [

                'domain' => [
                    new Assert\Regex(
                        [
                            'pattern' => '/^[^\.]{1,63}(\.[^\.]{1,63})*$/u',
                            'message' => ' wrong subdomain lenght ',
                        ]),
                    new Assert\Regex(
                        [
                            //'pattern' => '/[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z0-9\&\.\/\?\:@\-_=#])*/u',
                            'pattern' => '/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/iu',
                            'message' => ' wrong domain name ',
                        ]),
                    new Assert\Length(
                        [
                            'max' => 253,
                            'min' => 1,
                        ]),

                ],
                'isCustom' => [
                    new Assert\Optional([
                        new Assert\Choice([
                            'choices' => [0, 1, '0', '1']
                        ])
                    ])
                ],
                'appId' => [
                    new Assert\Optional([
                        new Assert\GreaterThanOrEqual(1),
                    ])
                ],
            ]);

        $errors = $this->globalValidator($fields, $constraint);
        if (is_array($errors)) {
            return $errors;
        }

        $isCustom = $fields['isCustom'] ?? 0;
        $appId = $fields['appId'] ?? 0;

        if ((intval($isCustom) == 0)) {
            if (substr_count($fields['domain'], '.') !== 1) {
                return [
                    'code' => '400',
                    'body' => 'You can only wrap a 2nd level domain into a branded app. So for example, you can wrap "mysite.com", but not "nnn.mysite.com". If you need to add PWA capabilities to such a third level domain - use PWA JS Capsule option.',
                ];
            }
        }

        if ((intval($isCustom) > 0)) {
            if (substr_count($fields['domain'], '.') !== 2) {
                return [
                    'code' => '400',
                    'body' => 'could use only domain of 3 level, for example anyone.yourdomain.com',
                ];
            }

            if ((intval($appId) > 0)) {
                $result = Yii::app()->db->createCommand()
                    ->select('id')
                    ->from('applications')
                    ->where('"id" <> :id and concat("Params"->>\'clientsubdomain\',\'.\',"Params"->>\'clientsiteurlforbrand\') = :domain ', [
                        ':id' => intval($appId),
                        ':domain' => $fields['domain'],
                    ])
                    ->queryAll(true);
                if(is_array($result) && isset($result[0]) && isset($result[0]['id'])){
                    return [
                        'code' => '400',
                        'body' => 'domain '.$fields['domain'].' already used in application '.$result[0]['id'],
                    ];
                }
            }
        }

        $res = $this->createConfig(strtolower($fields['domain']), (intval($isCustom)));

        $time = date('Y-m-d H:i:s');
        $level = 'NOTICE';
        if ($res['code'] !== '200') {
            $level = 'ERROR';
        }
        $this->RabbitMessaging->addItInRabbitQueueForLogs(
            json_encode(
                [
                    // standart params
                    "message" => $time . " [nginxController] [$level] createNewConfig",
                    "level" => $level,
                    "category" => 'nginxController_createNewConfig',
                    "time" => $time,
                    // new extended params
                    "hostname" => isset(Yii::app()->params['client_portal']) ? Yii::app()->params['client_portal'] :
                        $this->tenantPortal,
                    "server" => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : $this->server_short,
                    "host" => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $this->tenantPortal,
                    "ip_addr" => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
                    "service" => 'nginxController',
                    "mbst_server" => getenv('MBST_SERVER', true) ? : getenv('MBST_SERVER'),
                    // params for nginxController
                    'res body' => $res['body'] ?? '',
                ], true));

        return $res;

    }

    /**
     * The function for make curl request
     *
     * @param $clientDomain
     *
     * @return array
     */
    public function validateurl($url) : array
    {
        //        $url = 'https://insales-admin.comx.su/api/v8/nginx/validate';
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        $err = curl_error($ch);
        //        dump($response);
        //        dump($err);
        //        dd(1);
        $retcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
        curl_close($ch);

        //        dd($retcode, $body);
        Yii::log(
            json_encode(
                [
                    'response validate url',
                    [
                        $retcode,
                        $body,
                    ],
                ]), 'error');

        $time = date('Y-m-d H:i:s');
        $this->RabbitMessaging->addItInRabbitQueueForLogs(
            json_encode(
                [
                    // standart params
                    "message" => $time . " [nginxController] [NOTICE] validate url",
                    "level" => 'NOTICE',
                    "category" => 'nginxController_validate_url',
                    "time" => $time,
                    // new extended params
                    "hostname" => isset(Yii::app()->params['client_portal']) ? Yii::app()->params['client_portal'] :
                        $this->tenantPortal,
                    "server" => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : $this->server_short,
                    "host" => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $this->tenantPortal,
                    "ip_addr" => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
                    "service" => 'nginxController',
                    "mbst_server" => getenv('MBST_SERVER', true) ? : getenv('MBST_SERVER'),
                    // params for nginxController
                    'retcode' => json_encode($retcode),
                    'body' => json_encode($body),
                    'header' => json_encode($header),
                    'curl_error' => json_encode($err),
                    'curl_response' => json_encode($response),
                ], true));

        return [
            $retcode,
            $body,
        ];
    }

    /**
     * The function for get and validate ip addres
     *
     * @param $clientDomain
     *
     * @return array
     */
    public function validateip($url, $clearadmin = false)
    {

        $server = $_SERVER['SERVER_NAME'] ?? '';

        $ip2 = gethostbyname($url);

        $ip = gethostbyname($server ?? "");


        if ($clearadmin) {
            $server = str_ireplace('-admin.', '.', $server);
        }

        $result = dns_get_record($url);
        $result2 = dns_get_record($server);

        $foundCname = false;

        foreach ($result as $guest) {
            foreach ($result2 as $master) {
                if ($guest['target'] == $master['host']) {
                    if ($guest['type'] == "CNAME") {
                        $foundCname = true;
                    }
                }
            }
        }

        //        dd($ip, $ip2, $_SERVER['SERVER_NAME'], $url);
        $time = date('Y-m-d H:i:s');
        $level = 'NOTICE';
        if (!$foundCname) {
            //dd("$ip == $ip2");
            if ($ip == $ip2) {
                $foundCname = true;
            }
        }

        if (!$foundCname) {
            Yii::log(
                json_encode(
                    [
                        'wrong cname',
                        'client',
                        $result,
                        $url,
                        $ip2,
                        '---',
                        'server',
                        $result2,
                        $_SERVER['SERVER_NAME'] ?? '',
                        $ip,

                    ]), 'error');
            $level = 'ERROR';
        }

        $this->RabbitMessaging->addItInRabbitQueueForLogs(
            json_encode(
                [
                    // standart params
                    "message" => $time . " [nginxController] [$level] validateip",
                    "level" => $level,
                    "category" => 'nginxController_validateip',
                    "time" => $time,
                    // new extended params
                    "hostname" => isset(Yii::app()->params['client_portal']) ? Yii::app()->params['client_portal'] :
                        $this->tenantPortal,
                    "server" => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : $this->server_short,
                    "host" => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $this->tenantPortal,
                    "ip_addr" => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
                    "service" => 'nginxController',
                    "mbst_server" => getenv('MBST_SERVER', true) ? : getenv('MBST_SERVER'),
                    // params for nginxController
                    'mark' => 'nginxController_validateip',
                    'ipguest' => $ip2,
                    'dnsguest' => $result,
                    'ipserver' => $ip,
                    'dnsserver' => $result2,
                    'SERVER_NAME_ip2' => $_SERVER['SERVER_NAME'] ?? '',
                    'url_ip' => $url,
                ], true));

        return $foundCname;
    }

    /**
     * The function for make curl request for modify config
     *
     * @param $url
     *
     * @return none
     */
    public function modifyConfig($url, $isCustom = 0)
    {

        // $postUrl = gethostbyname($_SERVER['SERVER_NAME']);
        // $postUrl = "127.0.0.1";
        $postUrl = str_ireplace('https://tenant.', 'docker.', Yii::app()->params['currentServerParams']['url']);
        // dd($postUrl);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $postUrl);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10000);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        // curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        curl_setopt($ch, CURLOPT_PORT, 9090);
        // curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POST, 1);

        $additional = '';
        if ($isCustom==0){
            $additional = (Yii::app()->params['client_portal'] ?? '') . '.';
        }

        curl_setopt(
            $ch, CURLOPT_POSTFIELDS, "process_config_" . $additional . $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/plain']);

        $response = curl_exec($ch);
        $err = curl_error($ch);
        //if ($err) {
        //   dump($err);
        //}
        //$retcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        //        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        curl_close($ch);
        $level = "NOTICE";
        if (strval($response) != 'Success') {
            //dd('err', $response);
            $level = "ERROR";
        }
        $time = date('Y-m-d H:i:s');
        $this->RabbitMessaging->addItInRabbitQueueForLogs(
            json_encode(
                [
                    // standart params
                    "message" => $time . " [nginxController] [$level] modifyConfig",
                    "level" => $level,
                    "category" => 'nginxController_modifyConfig',
                    "time" => $time,
                    // new extended params
                    "hostname" => isset(Yii::app()->params['client_portal']) ? Yii::app()->params['client_portal'] :
                        $this->tenantPortal,
                    "server" => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : $this->server_short,
                    "host" => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $this->tenantPortal,
                    "ip_addr" => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
                    "service" => 'nginxController',
                    "mbst_server" => getenv('MBST_SERVER', true) ? : getenv('MBST_SERVER'),
                    // params for nginxController
                    'response' => json_encode($response),
                    'body' => json_encode($body),
                    'SERVER_NAME' => $_SERVER['SERVER_NAME'] ?? '',
                    'url' => json_encode($url),
                    'curl_err' => json_encode($err),
                    'postUrl' => json_encode($postUrl),
                ], true));
        // print($response);
        // $result = json_decode($response, true) ?? [];
        // dd($response, $header, $body, $postUrl);
    }

    /**
     * The function for creating new config file for nginx
     *
     * @param $clientDomain
     *
     * @return array
     */
    public function createConfig($clientDomain, $isCustom = 0) : array //docker container exec mbst_nginx nginx -s reload
    {

        if ($isCustom > 0) {
            $file = '/usr/local/etc/cnamedomain/conf_template2custom';
            $filename = str_ireplace('.', '_', $clientDomain);
            $arr = explode('.',$clientDomain);
            $newfile = '/usr/local/etc/cnamedomain/02_newmucustom_' . $filename . '.conf';

            $cname1 = $arr[0] . '-admin.' . $arr[1] . '.' . $arr[2];
            $url1 = 'https://' . $cname1 . '/api/v8/nginx/validate';
            $cname2 = $arr[0] . '.' . $arr[1] . '.' . $arr[2];
            $url2 = 'https://' . $cname2 . '/';
        } else {
            $file = '/usr/local/etc/cnamedomain/conf_template';
            $filename = (Yii::app()->params['client_portal'] ?? '') . '_' . str_ireplace('.', '_', $clientDomain);
            $newfile = '/usr/local/etc/cnamedomain/01_newmu_' . $filename . '.conf';

            $cname1 = (Yii::app()->params['client_portal'] ?? '') . '-admin.' . $clientDomain;
            $url1 = 'https://' . $cname1 . '/api/v8/nginx/validate';
            $cname2 = (Yii::app()->params['client_portal'] ?? '') . '.' . $clientDomain;
            $url2 = 'https://' . $cname2 . '/';
        }


        if (!$this->validateip($cname1)) {
            return [
                'code' => '500',
                //'body' => 'cname ' . $cname1 . ' is not registered',
                'body' => 'We can\'t verify that the domain name ['.$cname1.'] is registered. ' .
                    'Please make sure you created CNAME records and try again.',
            ];
        }
        if (!$this->validateip($cname2, true)) {
            return [
                'code' => '500',
                //'body' => 'cname ' . $cname2 . ' is not registered',
                'body' => 'We can\'t verify that the domain name ['.$cname2.'] is registered. ' .
                    'Please make sure you created CNAME records and try again '.$clientDomain,
            ];
        }

        if (file_exists($newfile)) {

        } else {

            if (!file_exists($file)) {
                return [
                    'code' => '400',
                    'body' => 'template file not exist',
                ];
            }

            if (!is_dir(dirname($newfile))) {
                mkdir(dirname($newfile), 0777, true);
            }

            if (!is_dir(dirname($newfile))) {
                return [
                    'code' => '400',
                    'body' => 'could not create the directory',
                ];
            }

            if (!@copy($file, $newfile)) {
                $errors = error_get_last();
                //            echo "COPY ERROR: " . $errors['type'];
                //            echo "<br />\n" . $errors['message'];

                return [
                    'code' => '500',
                    'body' => 'could not copy config file',
                    'error' => $errors,
                ];

            } else {
                //            echo "File copied from remote!";
            }

            if (!file_exists($newfile)) {
                return [
                    'code' => '400',
                    'body' => 'config file by some undetermined reason was not created',
                ];
            }

            if ($isCustom > 0) {
                $content = file_get_contents($newfile);
                $level2 = str_ireplace('https://', '', Yii::app()->params['host']);
                $level1 = str_ireplace('-admin.', '.', $level2);
                $content = str_replace('domen1level', $level1, $content);
                $content = str_replace('domen2level', $level2, $content);
                file_put_contents($newfile, $content);
            }

            $this->modifyConfig($clientDomain, $isCustom);
            sleep(7);
        }

        //$shell1 = shell_exec('docker container exec mbst_nginx nginx -s reload');
        //$shell1 = shell_exec('docker container restart mbst_nginx');

        //  [//do not uncomment
        //      $code1,
        //      $body1,
        //  ] = $this->validateurl($url2);
        //  if (($code1 != '200') or $body1 != '{"code":"a5f5d1929b56b3a699339a2984fbe22c"}') {
        //      return [
        //          'code' => '500',
        //          'body' => 'host ' . $cname2 . ' is not configured',
        //      ];
        //  }

        [
            $code1,
            $body1,
        ] = $this->validateurl($url1);
        if (($code1 != '200') or $body1 != '{"code":"a5f5d1929b56b3a699339a2984fbe22c"}') {
            return [
                'code' => '500',
                'body' => 'host ' . $cname1 . ' is not configured',
            ];
        }

        return [
            'code' => '200',
            'body' => 'config created',
            //            'r' => $shell1,
        ];

    }

    /**
     * Action for response valid code
     */
    public function actionValidateCname()
    {
        $this->sendResponse(200, ['code' => 'a5f5d1929b56b3a699339a2984fbe22c']);
    }

}
