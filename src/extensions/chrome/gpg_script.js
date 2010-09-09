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
 * @fileoverview Content script responsible for passing messages between web
 *     pages and background.html.
 * @author philames@google.com (Phil Ames)
 */

/*
 * This function is invoked by the code on background.html and passes the JSON
 * response back to the calling page.  It is passed as a parameter to
 * chrome.extension.sendRequest (in this file) to allow communication from
 * background.html to this content script.
 * @param {String} e A string JSON representation of the result of the call to
 *     the NPAPI plugin.
 */
function gpgCallback(e) {
  response = JSON.parse(e);
  window.postMessage(e, response.targetOrigin);
}


/*
 * This method initially catches the event from the page and passes it on to the
 * code in background.html
 * @param {Object} e The event dispatched from a page where the listener is
 *     registered.
 */
function gpgListener(e) {
  targetOrigin = window.location.protocol + '//' + window.location.host;
  if (window.location.port) {
    targetOrigin += ':' + window.location.port;
  }

  response = { 'isError': true };
  response.targetOrigin = targetOrigin;
  if (e.target.getAttribute('txid') == null) {
    response.errorStr = 'No txid specified';
    window.postMessage(JSON.stringify(response), targetOrigin);
    return;
  } else if (e.target.getAttribute('method') == null) {
    response.errorStr = 'No method specified';
    window.postMessage(JSON.stringify(response), targetOrigin);
    return;
  }

  var msg = {
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

  chrome.extension.sendRequest(msg, gpgCallback);
}


window.addEventListener('gpgEvent', gpgListener, false);
