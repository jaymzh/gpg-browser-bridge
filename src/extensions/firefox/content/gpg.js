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
 * @fileoverview Code responsible for processing a GPG event and passing to the
 *     common GPG handler.
 * @author philames@google.com (Phil Ames)
 */

var gpg = null;
var gpgPrefs = null;


function gpgListener(e) {
  if (content.wrappedJSObject.location.protocol == 'file:') {
    alert('file:// origins do not support message passing');
  }

  targetOrigin = content.wrappedJSObject.location.protocol + '//' +
    content.wrappedJSObject.location.host;

  if (content.wrappedJSObject.location.port != '') {
    targetOrigin += ':' + content.wrappedJSObject.location.port;
  }

  response = { 'isError': true };
  txid = e.target.getAttribute('txid');
  method = e.target.getAttribute('method');
  if (txid == null) {
    response.errorStr = 'No txid specified';
    content.postMessage(JSON.stringify(response), targetOrigin);
    return;
  }
  else if (method == null) {
    response.errorStr = 'No method specified';
    content.postMessage(JSON.stringify(response), targetOrigin);
    return;
  }

  msg = {
    method: e.target.getAttribute('method'),
    targetOrigin: targetOrigin,
    txid: e.target.getAttribute('txid'),
    rawtext: e.target.getAttribute('rawtext'),
    hidden_keyids: e.target.getAttribute('hidden_keyids'),
    always_trust: e.target.getAttribute('always_trust'),
    sign: e.target.getAttribute('sign'),
    cipherText: e.target.getAttribute('cipherText'),
    keyid: e.target.getAttribute('keyid'),
    signedtext: e.target.getAttribute('signedtext'),
    signature: e.target.getAttribute('signature'),
    clearsignedtext: e.target.getAttribute('clearsignedtext'),
    keyserver: e.target.getAttribute('keyserver'),
    uid: e.target.getAttribute('uid'),
    level: e.target.getAttribute('level'),
    key: e.target.getAttribute('key'),
    keyids: e.target.getAttribute('keyids')
  };

  try {
    response = processGpgEvent(msg, gpgPrefs);
  } catch (e) {
    response.errorStr = 'Unexpected JS exception: ' + e.message;
  }
  content.postMessage(JSON.stringify(response), targetOrigin);
}

var gpgPlugin = {
  init: function(e) {
    // See gpg_prefs.js for the definition of this function.
    gpgPrefs = getPreferenceService();

    // Hook page load events with the initTab method.
    if (gBrowser != null) {
      gBrowser.addEventListener('load', this.gpgPlugin.initTab, true);
    }

    // Instantiate the GPG Plugin.
    try {
      gpg = document.getElementById('gpg').Gnupg();
    } catch (e) {
      alert('GPG Plugin could not be instantiated! (No NPAPI plugin?)');
      return;
    }

    if (!configurePlugin(gpg, gpgPrefs)) {
      alert('GPG Plugin could not be configured!');
    }

    // The preferenceObserver is declared in gpg_prefs.js.
    preferenceObserver.startup(gpgPrefs);
  },
  initTab: function(e) {
    if (typeof e.originalTarget == typeof HTMLDocument) {
      e.originalTarget.addEventListener('gpgEvent', gpgListener, false,
                                        true);
    }
  }
};

window.addEventListener('load', gpgPlugin.init, false);
