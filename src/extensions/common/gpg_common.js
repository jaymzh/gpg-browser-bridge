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

/*
 * Determines whether a string looks like a GPG key id.
 * @param {string} key The hexadecimal key ID to check.
 * @return A boolean indicating whether this key is properly formatted.
 */
function validKeyId(key) {
  return /^[0-9A-Fa-f]{8}$/.test(key);
}


/*
 * Copies all attributes from one object to another.
 * @param {Object} to The destination object.
 * @param {Object} from The source object.
 */
function copy(from, to) {
  for (var x in from) {
    to[x] = from[x];
  }
}


/*
 * Examines all keys in the provided string and adds valid keys to the
 * returned array.
 * @param {string} keys A csv list of key IDs.
 * @return An array of all keys which were valid in the request.
 */
function parseCsvKeylist(keys) {
  var rv = [];
  if (!keys) {
    return rv;
  }
  var keyArray = keys.split(',');
  for (var i = 0; i < keyArray.length; i++) {
    if (validKeyId(keyArray[i])) {
      rv.push(keyArray[i]);
    }
  }
  return rv;
}


/*
 * Checks that the provided key is valid.  If invalid, it defaults to the
 * preferred key (if one is available).  Otherwise, a null value is returned.
 * @param {string} key The user provided key.
 * @param {array} preferredKeys An array of keys where the preferred key ID is
 *     the first element.
 * @return {string} The key to use (or null if no suitable key found).
 */
function checkProvidedKey(key, preferredKeys) {
  if (key && validKeyId(key)) {
    return key;
  }
  if (preferredKeys && preferredKeys.length != 0 &&
      validKeyId(preferredKeys[0])) {
        return preferredKeys[0];
      }
  return null;
}


/*
 * This function processes a variable list of arguments and verifies that all
 * are present.  If any are not present/defined, the errorStr attribute of the
 * response object will be set to the value of the error parameter.
 * @param {object} response The response object.
 * @param {string} error The error message to present if all values are not set.
 * @return {bool} True if all values are defined, false otherwise.
 */
function argumentsOk(response, error) {
  for (var i = 2; i < arguments.length; i++) {
    if(arguments[i] == null) {
      response.errorStr = error;
      return false;
    }
  }
  return true;
}

/*
 * This function processes a GpgEvent as dispatched from a web page and invokes
 * the appropriate methods on the NPAPI plugin.
 * @param {Object} request A JSON object containing the method and arguments to
 *     invoke.
 * @param {Object} preferences An interface to the browser preference system to
 *     retrieve any relevant preferences when performing the operation specified
 *     in the request.
 */
function processGpgEvent(request, preferences) {
  var response = { 'isError': true };
  response.targetOrigin = request.targetOrigin;
  response.txid = request.txid;

  /*
   * TODO(philames): insert a check to validate that this origin is authorized
   * to invoke the method (to prevent evil.com from arbitrarily signing text as
   * me if my passphrase is cached).
   */

  if (preferences.getPreference('gpg_last_configured') <
      preferences.getPreference('gpg_last_updated')) {
    /*
     * configurePlugin() will call the necessary methods
     * to update the NPAPI plugin for Chrome.  In Firefox,
     * the preferenceObserver handles the updates to
     * preferences and this comparison will always be
     * if (false < false), so this will never execute
     * in Firefox.
     */
    if (!configurePlugin(gpg, preferences)) {
      response.errorStr = 'Error configuring plugin';
      return response;
    }
  }

  keys = [];
  if (preferences.getPreference('gpg_key_id') != null &&
      validKeyId(preferences.getPreference('gpg_key_id'))) {
    keys.push(preferences.getPreference('gpg_key_id'));
  }

  switch (request.method) {
    case 'encrypt':
      var rawtext = request.rawtext;
      var targetKeys = request.keyids;
      var hiddenKeyids = request.hidden_keyids;
      var alwaysTrust = request.always_trust;
      var sign = request.sign;
      if (!sign) {
        sign = '';
      } else if (sign && !validKeyId(sign)) {
        sign = '';
      }

      if (argumentsOk(response, 'Not all required arguments (rawtext,' +
          'target_keys, always_trust) provided.', rawtext, targetKeys,
          alwaysTrust) && (alwaysTrust == 'true' || alwaysTrust == 'false')) {
        var hk = parseCsvKeylist(hiddenKeyids);
        var tk = parseCsvKeylist(targetKeys);
        var at = (alwaysTrust == 'true');

        ciphertext = gpg.encryptText(rawtext, tk, hk, at, sign);
        copy(ciphertext, response);
      }
      break;

    case 'decrypt':
      var ciphertext = request.cipherText;
      var plaintext = undefined;

      if (argumentsOk(response, 'No ciphertext provided.', ciphertext)) {
        plaintext = gpg.decryptText(ciphertext);
        copy(plaintext, response);
      }
      break;

    case 'sign':
    case 'clearsign':
      var rawtext = request.rawtext;
      var key = request.keyid;
      var clearSign = (request.method == 'clearsign');

      key = checkProvidedKey(key, keys);

      if (argumentsOk(response, 'No rawtext or key ID provided.', rawtext,
          key)) {
        signature = gpg.signText(rawtext, key, clearSign);
        copy(signature, response);
      }
      break;

    case 'verify':
      var signedText = request.signedtext;
      var signature = request.signature;

      if (argumentsOk(response, 'No signedtext or signature provided.',
          signedText, signature)) {
        verify = gpg.verifySignedText(signedText, signature);
        copy(verify, response);
      }
      break;

    case 'verify_clear':
      var signedText = request.clearsignedtext;

      if (argumentsOk(response, 'No clear-signed text provided.', signedText)) {
        verify = gpg.verifySignedText(signedText, '');
        copy(verify, response);
      }
      break;

    case 'get_key':
      var keyid = request.keyid;
      var keyserver = request.keyserver;

      if (keyid && !validKeyId(keyid)) {
        keyid = null;
      }

      if (argumentsOk(response, 'Key ID or Keyserver not provided.', keyid,
          keyserver)) {
        result = gpg.getKey(keyid, keyserver);
        copy(result, response);
      }
      break;

    case 'get_uids':
      var key = checkProvidedKey(request.keyid, keys);

      if (argumentsOk(response, 'Invalid key ID or no key ID provided.',
          key)) {
        uids = gpg.getUids(key);
        copy(uids, response);
      }
      break;

    case 'get_gnupg_version':
      var version = gpg.getGnupgVersion();
      copy(version, response);
      break;

    case 'get_fingerprint':
      var key = checkProvidedKey(request.keyid, keys);

      if (argumentsOk(response, 'No key ID provided.', key)) {
        fp = gpg.getFingerprint(key);
        copy(fp, response);
      }
      break;

    case 'get_trust':
      var key = request.keyid;
      if (key && !validKeyId(key)) {
        key = null;
      }

      if (argumentsOk(response, 'No key ID provided.', key)) {
        trust = gpg.getTrust(key);
        copy(trust, response);
      }
      break;

    case 'sign_uid':
      var uid = request.uid;
      var level = request.level;
      var key = checkProvidedKey(request.keyid, keys);

      if (argumentsOk(response, 'No key ID, uid, or level provided.', key,
          uid, level)) {
        sig = gpg.signUid(key, uid, level);
        copy(sig, response);
      }
      break;

    default:
      response.errorStr = 'Unsupported method';
      break;

  }
  return response;
}
