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
 * Software distributed under the License is distributed on an "AS IS" basis,
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
 * @param {Object} request A JSON object containing the method and arguments
 *     for the NPAPI object invocation
 * @param {Object} sender An object containing information about the script
 *     context that sent the request.
 * @param {function} sendResponse A callback function for receiving the results
 *     of the invocation of the NPAPI methods.
 */
function gpgListener(request, sender, sendResponse) {
  response = {
    'isError': true,
    'targetOrigin': request.targetOrigin,
    'response.txid': request.txid
  };

  if (gpgPrefs.getPreference('gpg_last_configured') <
      gpgPrefs.getPreference('gpg_last_updated')) {
    if (!configurePlugin()) {
      response.errorStr = 'Error configuring plugin';
      sendResponse(JSON.stringify(response));
      return;
    }
  }

  try {
    response = processGpgEvent(request, gpgPrefs);
  } catch (e) {
    response.errorStr = 'Unexpected JS exception: ' + e.message;
  }

  sendResponse(JSON.stringify(response));
}


/*
 * This function is invoked by the body onLoad handler in background.html.  It
 * instantiates the NPAPI plugin, the preference service for the extension, and
 * registers the appropriate event listeners for messages that will be sent by
 * content scripts injected on pages.
 */
function init() {
  try {
    gpg = document.getElementById('gpg').Gnupg();
  } catch (e) {
    alert('GPG Plugin could not be instantiated! (No NPAPI plugin?)');
    return;
  }

  gpgPrefs = getPreferenceService();

  if (!configurePlugin()) {
    alert('GPG Plugin could not be configured!');
  }

  // Set up a listener for events from the content script.
  chrome.extension.onRequest.addListener(gpgListener);
}
