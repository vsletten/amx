<?php
$config['db_dsnw'] = 'sqlite:////var/roundcube/db/sqlite.db?mode=0646';
$config['imap_host'] = [
    'mailhost-nw:143' => 'northwind.test',
    'mailhost-ct:143' => 'contoso.test',
    'mailhost-pm:143' => 'plainmail.test',
];
$config['smtp_host'] = '%h:25';
$config['support_url'] = '';
$config['product_name'] = 'amx prototype';
$config['des_key'] = 'amx-dev-only-key-3006!!';
// amx_folder_drawer (dev stack): folders slide out beside the message list at 769-1200 px.
$config['plugins'] = ['archive', 'amx_folder_drawer'];
$config['skin'] = 'elastic';
$config['enable_installer'] = false;
$config['login_autocomplete'] = 2;
