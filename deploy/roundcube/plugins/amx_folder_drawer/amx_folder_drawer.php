<?php
// SPDX-License-Identifier: Apache-2.0

/**
 * amx dev stack: the folder list as a drawer that pushes the message list aside.
 *
 * In Elastic's "normal" width band (769-1200 px) the folder list and the message list replace
 * each other, so a person cannot drag a held message from Outbox/Held onto Outbox/Approved.
 * This plugin keeps both visible there: the Folders button slides the folder list open beside
 * the message list and it stays open while folders are browsed. Wider screens already show both
 * (Elastic's three-column layout) and are left alone.
 */
class amx_folder_drawer extends rcube_plugin
{
    public $task = 'mail';

    public function init()
    {
        $this->include_stylesheet('amx_folder_drawer.css');
        $this->include_script('amx_folder_drawer.js');
    }
}
