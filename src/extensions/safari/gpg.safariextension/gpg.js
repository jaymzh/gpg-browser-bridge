/*
 * Copyright 2010, Google Inc.
 *
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"  basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the GPG Browser Bridge.
 *
 * The Initial Developer of the Original Code is Google Inc.
 *
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Phil Ames <philames@google.com>
 *
 * ***** END LICENSE BLOCK *****
 */

/**
 * @fileoverview Code responsible for processing messages from a Chrome content
 *     script and passing it to the common GPG handler.
 * @author philames@google.com (Phil Ames)
 */

  var gpg = null;
  var gpgPrefs = null;
  /*
   * This function is called by the code in gpg_script.js when a page
   * dispatches a gpgEvent.  The request contains all pertinent
   * information such as what method is being invoked and the arguments
   * to said method.
   */
  function gpgListener(message) {
    if (message.name != 'gpgMessage') {
      return;
    }
    request = JSON.parse(message.message);
    response = {
      'isError': true,
      'targetOrigin': request.targetOrigin,
      'txid': request.txid
    };
    response.targetOrigin = request.targetOrigin;
    response.txid = request.txid;
    tab = safari.application.activeBrowserWindow.activeTab;

    try {
      response = processGpgEvent(request, gpgPrefs);
    } catch (e) {
      response.errorStr = 'Unexpected JS exception: ' + e.message;
    }

    tab.page.dispatchMessage('gpgMessage', JSON.stringify(response));
  }

  function init() {
    try {
      gpg = document.getElementById('gpg').Gnupg();
    } catch (e) {
      gpg = null;
    }

    gpgPrefs = getPreferenceService();

    if (gpg == null) {
      alert('GPG Plugin could not be instantiated!');
    } else if (!configurePlugin()) {
      alert('GPG Plugin could not be configured!');
    }

    // set up a listener for events from the content script
    safari.application.addEventListener('message', gpgListener, false);

    // set up a preference change listener
    safari.extension.settings.addEventListener('change', prefChange, false);
  }
