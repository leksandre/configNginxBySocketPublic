# configNginxBySocketPublic
 # php like

        // $postUrl = gethostbyname($_SERVER['SERVER_NAME']);
        // $postUrl = "127.0.0.1";
        $postUrl = str_ireplace('https://tenant.', 'docker.', Yii::app()->params['currentServerParams']['url']);
        // $postUrl = "docker.mobsted.ru";
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
