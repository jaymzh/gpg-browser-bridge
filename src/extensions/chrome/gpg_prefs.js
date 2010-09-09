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
 * @fileoverview Preference specific handling functions for Chrome.
 * @author philames@google.com (Phil Ames)
 */

/*
 * This function sets all configuration values from the locally
 * stored preferences.  If the plugin is available, it will also
 * update the preference store with the current date/time as the
 * last date of successful configuration.
 * @returns A boolean value indicating whether configuration was successful.
 */
function configurePlugin() {
  if (gpg == null) {
    return false;
  }
  gpgPrefs.setPreference('gpg_last_configured', new Date());

  if (gpgPrefs.getPreference('gpg_binary_path') == null ||
      gpgPrefs.getPreference('gpg_binary_path').length == 0) {
    alert('GPG binary path not specified, functionality will be disabled.');
    gpg.setConfigValue('gpg_plugin_initialized', 'false');
    return false;
  }

  gpg.setConfigValue('gpg_binary_path',
      gpgPrefs.getPreference('gpg_binary_path'));
  gpg.setConfigValue('gpg_plugin_initialized', 'true');

  return true;
}


/*
 * This function returns an object that retrieves preferences
 * from the Chrome specific preference store.
 * @returns An object for interfacing with the preference store.
 */
function getPreferenceService() {
  var rv = {
    getPreference:
      function(pref) {
        return localStorage[pref];
      },
    setPreference:
      function(pref, value) {
        localStorage[pref] = value;
      }
  };
  return rv;
}
