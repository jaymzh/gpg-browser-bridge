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
    'Version: GnuPG v1.4.6 (GNU/Linux)\n' +
    '\n' +
    'hQQOA9eXSuvE3GNAEBAAhTwY76j5t1sew3Pd388r97+li9UReo82rtg44zsB98hp\n' +
    'lTjXl2yH8uRyuIeUBeKZo21Ryx1UbmNt884mmywdy4LCzV6ZXm8b5vCfHw0WHbm2\n' +
    'xfJKZpZOTTEPlXZs7B8r+/rwiV64zjyHfmBYQKnS1FpDe+SuMaaz9AS9uMCRJF8m\n' +
    'co+9UcvNAYFK05ZC2bW5c0wPETyMMxiJ3P0WmDCDUJa2DdtCHaVY0dlmJDhIz4QF\n' +
    'Ydn08U/1xV/klVyAq+fe99K8bnlQ7b3zdJ1FtI1jMF/xyVuCyAjJtbLL4YE/xZcA\n' +
    'ucysj6gyuJS18KIVx4Dwv0TPB3LX3G4oEKS8FKV5yPgc15REHoUlrGS7kf7fZauj\n' +
    'q598ucwSkm7V5DkbzrrPTaH048pyOKNpHdtbggHqe3Fj6s8Wwkiz3VbGrrOKN6xc\n' +
    'LwJxwvMGfbEXDlYS49mngkJmvhH1SRVl/CzNFf2hjihOjNa1xh718RHkPgb6Gqqu\n' +
    'MSh9xqzH0Dpdfh4WZgc5ZlEDhEcTf9AGnscwRNgbiKVnp9FFrJpi69jwoKrUz6Uy\n' +
    'T7IOnWe1IldK591UtTUJXqYiI8h4HpQ7kXwKf8585B7qjM/8d9WQsEWO7TN4o133\n' +
    'S/vej2PWXB4QPA6npwA25civ2QMTvIxFdlMiXcQ9cTMkTG5KEVA7W8vSt+Sw2KMP\n' +
    '/A3IZABC5j1+Q+W9HA8z14DoyXO9gkvQp4OepvsrNUYFdXMokY2AOdFNt+REXwkh\n' +
    'EeFjegtRx6OwahYm2uJCIcd8bPnXMUEwueu2XmxwBs42eacp2acAav37L6OwRTwe\n' +
    'j4qKCLqEuVRWj4dqOgZKFNYm/CXBf+lFmhcdtxEqVasRX/XlWVtmB0X+++6Y20eP\n' +
    'QUTDlcPm16Ff+992JZLvhP0nu2grHTN4ARMVS0wRK4CebF/F/ejnvQVpkMXgA5lt\n' +
    'O7uqwzlR5rIa5Nn6dkdZZ2GVoaATLnOzhhS01Iz9B+5rQtl/uCvyD3L/4wXbPH/f\n' +
    'an8Ck00aIxm/m/rOeey4R1HjPj/Ux8pA69ZyrSFa1VVG7/4O685rd94IcbGRLHX3\n' +
    'yyi5CeH4H0hk6o7NhyqwE1GUPec0UXFUtl1dfNGTFieLRgV7JzVgcSt+ytfJYMj7\n' +
    'a3ee7Q96XIZcDZpyOuM5FvQNlZj6UF/RvfB6SUqkqbAH669NLuJy5dxOifjfXh20\n' +
    'CewpO0F5PBWNU/TCawZAKoSzpSHdwmqm4N8870Rls+8rzvaEqiNSoIW/9a/hI15u\n' +
    'AU5UO0hTADMT3agXDDajj3WMKl/lCXmanZG6p3vx5zhtwuXEOv/rRrq//JtdyVNt\n' +
    'vpg8ue4owq5+eM0Np5+eb2elgyeagxhcVRxbUXvX6cSV0mMBlrQDKHlxLNd1XpTo\n' +
    '4er3rMyyVv4quRBZyJzzcN2qRwC9L82OaAWVNIMF+uVibnOlwmbti5MKRkH+whg5\n' +
    'QWc0wXMxSbxBVkLK0nzECvOlSXfnQ4sSJxE4hApVlnsuygcsb+0=\n' +
    '=CLh/\n' +
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
