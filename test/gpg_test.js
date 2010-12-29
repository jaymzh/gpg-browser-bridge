// Copyright 2010 Google Inc. All Rights Reserved.

/**
 * @fileoverview Supporting JavaScript functions for testing GPG plugin
 *     functionality.
 * @author philames@google.com (Phil Ames)
 */

/*
 * This function creates a GpgElement node from the current document attribute
 * and returns something suitable for attaching to the page.
 * @param {string} method The method to call on the NPAPI plugin.
 * @param {string} txid A transaction ID to identify the result of the method
 *     call.
 * @param {object} parameters The parameters to pass to the NPAPI plugin for
 *     this method call.
 * @return An object that should be attached with appendChild().
 */
function createGpgElement(method, txid, parameters) {
  var element = document.createElement('gpgElement');
  var validParameters = [
      'rawtext', 'hidden_keyids', 'always_trust', 'sign',
      'cipherText', 'keyid', 'signedtext', 'signature', 'clearsignedtext',
      'keyserver', 'uid', 'level', 'key', 'keyids'];

  element.setAttribute('method', method);
  element.setAttribute('txid', txid);

  for (var x in parameters) {
    var idx = validParameters.indexOf(x);
    if (idx >= 0) {
      element.setAttribute(validParameters[idx], parameters[x]);
    }
  }
  return element;
}

function dispatchEventToElement(element) {
  var ev = document.createEvent('Events');
  ev.initEvent('gpgEvent', true, false);
  element.dispatchEvent(ev);
}

function receiveMessage(message) {
  response = JSON.parse(message.data);
  if (response.isError) {
    document.getElementById('misc').innerHTML = '<pre>' + response.errorStr +
    '</pre>';
    return;
  }

  switch (response.txid) {
    case '1': // encrypt
      document.getElementById('ciphertext').value = response.cipherText;
      break;
    case '2': // decrypt
      document.getElementById('plaintext').value = response.data;
      break;
    case '3': // sign
      document.getElementById('vsignedtext').value = response.retstring;
      break;
    case '4': // clearsign
      document.getElementById('vsignedtext').value = response.retstring;
      break;
    case '5': // verify
      document.getElementById('misc').innerHTML = response.signer + '(' +
          response.trustLevel + ')';
      break;
    case '6': // clearverify
      document.getElementById('misc').innerHTML = response.signer + '(' +
          response.trustLevel + ')';
      break;
    case '7': // getkey
      document.getElementById('misc').innerHTML = response.retbool;
      break;
    case '8': // getuids
      str = '';
      for (var i = 0; i < response.uids.length; i++) {
        str += response.uids[i];
        if (i + 1 != response.uids.length)
         str += ', ';
      }
      document.getElementById('misc').innerHTML = str;
      break;
    case '9': // getversion
      document.getElementById('misc').innerHTML = response.retstring;
      break;
    case '10': // gettrust
      document.getElementById('misc').innerHTML = response.retstring;
      break;
    case '11': // getfingerprint
      document.getElementById('misc').innerHTML = response.retstring;
      break;
    case '12': // getfingerprint
      document.getElementById('misc').innerHTML = response.retbool;
      break;
    default:
      alert('Unknown txid.');
      break;
  }
}

var gpg;

function pageInit() {
  window.addEventListener('message', receiveMessage, false);
    document.getElementById('plaintext').value = 'Some text.\n';
    document.getElementById('rawtext').value = 'Some text.\n';
    document.getElementById('vsignedtext').value =
    '-----BEGIN PGP SIGNATURE-----\n' +
    'Version: GnuPG v1.4.6 (GNU/Linux)\n' +
    '\n' +
    'iEYEARECAAYFAkw7IncACgkQLBV88STLCDmvIQCdF6HGtdkmd1OAEokY+X6qfCNI\n' +
    '5N4An28x5ftN0miHuy3pvXMoc+RZ0g5O\n' +
    '=2S4h\n' +
    '-----END PGP SIGNATURE-----\n';

    document.getElementById('ciphertext').value =
    '-----BEGIN PGP MESSAGE-----\n' +
    'Version: GnuPG v1.4.10 (GNU/Linux)\n' +
    '\n' +
    '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\n' +
    'HflAFGua+ODo6Z60I8ssotYK60VJVg8Idg==\n' +
    '=fg6e\n' +
    '-----END PGP MESSAGE-----\n';
    document.getElementById('keyid').value = '24CB0839';
}

function encryptText() {
  var request = {
    'rawtext': document.getElementById('plaintext').value,
    'keyids': document.getElementById('keyid').value,
    'hidden_keyids': '',
    'always_trust': document.getElementById('always_trust').checked,
    'sign': ''
  };

  var element = createGpgElement('encrypt', 1, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function decryptText() {
  var request = {
    'cipherText': document.getElementById('ciphertext').value
  };
  var element = createGpgElement('decrypt', 2, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function signText() {
  var request = {
    'rawtext': document.getElementById('rawtext').value,
    'keyid': document.getElementById('keyid').value
  };
  var element = createGpgElement('sign', 3, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function clearSignText() {
  var request = {
    'rawtext': document.getElementById('rawtext').value,
    'keyid': document.getElementById('keyid').value
  };
  var element = createGpgElement('clearsign', 4, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function verifyText() {
  var request = {
    'signedtext': document.getElementById('rawtext').value,
    'signature': document.getElementById('vsignedtext').value
  };
  var element = createGpgElement('verify', 5, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function clearVerifyText() {
  var request = {
    'clearsignedtext': document.getElementById('vsignedtext').value
  };
  var element = createGpgElement('verify_clear', 6, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function getKey() {
  var request = {
    'keyid': document.getElementById('keyid').value,
    'keyserver': document.getElementById('keyserver').value
  };
  var element = createGpgElement('get_key', 7, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function getUids() {
  var request = {
    'keyid': document.getElementById('keyid').value
  };
  var element = createGpgElement('get_uids', 8, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function getVersion() {
  var request = { };
  var element = createGpgElement('get_gnupg_version', 9, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function getTrust() {
  var request = {
    'keyid': document.getElementById('keyid').value
  };
  var element = createGpgElement('get_trust', 10, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function getFingerprint() {
  var request = {
    'keyid': document.getElementById('keyid').value
  };
  var element = createGpgElement('get_fingerprint', 11, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}

function signUid() {
  var request = {
    'keyid': document.getElementById('keyid').value,
    'uid': document.getElementById('uid').value,
    'level': document.getElementById('level').value
  };
  var element = createGpgElement('sign_uid', 12, request);
  document.documentElement.appendChild(element);
  dispatchEventToElement(element);
}
