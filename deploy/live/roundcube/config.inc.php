<?php
// SH-10 optional webmail: use the signed-in person's SASL credentials, never
// unauthenticated port 25 as in the dev stack. Verify the mailhost certificate.
$config['product_name'] = 'amx';
$config['smtp_host'] = 'tls://mailhost:587';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$ssl = ['verify_peer' => true, 'verify_peer_name' => true,
        'peer_name' => getenv('AMX_MX_HOST')];
if (is_readable('/tls/ca.pem')) {
    $ssl['cafile'] = '/tls/ca.pem';
}
$config['smtp_conn_options'] = ['ssl' => $ssl];
$config['imap_host'] = 'ssl://mailhost:993';
$config['imap_conn_options'] = ['ssl' => $ssl];
$config['enable_installer'] = false;
