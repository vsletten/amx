// SPDX-License-Identifier: Apache-2.0
/**
 * amx dev stack: in Elastic's "normal" band the Folders button toggles a drawer that pushes the
 * message list aside (see amx_folder_drawer.css). Elastic still runs its own show_sidebar /
 * show_list logic; the CSS keeps both panels visible whatever classes Elastic sets, so this
 * script tracks the open state and whether the band applies, and re-enables dragging messages
 * onto folders for mouse users in windows 1024 px or narrower.
 */
(function ($) {
    var storageKey = 'amx.folderDrawer';
    var open = true;

    try {
        open = window.localStorage.getItem(storageKey) !== 'closed';
    } catch (error) {
        // Private windows may refuse storage; default to open.
    }

    function inNormalBand() {
        return Boolean(
            window.UI && UI.get_screen_mode && UI.get_screen_mode() === 'normal'
                && $('#layout-sidebar').length && $('#layout-list').length
        );
    }

    function apply() {
        var html = $(document.documentElement);
        var active = inNormalBand();
        html.toggleClass('amx-drawer', active).toggleClass('amx-drawer-open', active && open);
    }

    function restoreMouseDragging() {
        // Elastic treats any window 1024 px wide or narrower as a touch device and turns off
        // dragging messages onto folders (roundcube/elastic#45: dragging blocks touch scrolling).
        // With a mouse, turn it back on so held mail can be dragged to Outbox/Approved.
        var list = window.rcmail && rcmail.message_list;
        var mouse = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
        if (mouse && list && rcmail.gui_objects.folderlist && list.draggable === false) {
            list.draggable = true;
            list.dblclick_time = rcmail.dblclick_time;
        }
    }

    function later() {
        window.setTimeout(apply, 0);
    }

    function remember() {
        try {
            window.localStorage.setItem(storageKey, open ? 'open' : 'closed');
        } catch (error) {
            // Not remembered; the drawer still works for this page.
        }
    }

    $(function () {
        $('#layout-list a.back-sidebar-button.folders').on('click', function () {
            if (inNormalBand()) {
                open = !open;
                remember();
            }
            later();
        });
        if (window.rcmail) {
            rcmail.addEventListener('skin-resize', later);
            rcmail.addEventListener('listupdate', later);
            // Registered after Elastic's own init handler, so this runs after it disables drag.
            rcmail.addEventListener('init', function () {
                restoreMouseDragging();
                later();
            });
        }
        later();
    });
})(jQuery);
