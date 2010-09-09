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
 * @fileoverview GPG-specific API for accessing preferences in Firefox.
 * @author philames@google.com (Phil Ames)
 */

function getPreferenceService() {
  var prefService = Components.classes['@mozilla.org/preferences-service;1'].
      getService(Components.interfaces.nsIPrefService).
      getBranch('extensions.gpg.');
  prefService.QueryInterface(Components.interfaces.nsIPrefBranch2);

  var rv = {
    gpgPrefService: prefService,
    getPreference: function(pref) {
      switch (this.gpgPrefService.getPrefType(pref)) {
        case this.gpgPrefService.PREF_STRING:
          return this.gpgPrefService.getCharPref(pref);
        case this.gpgPrefService.PREF_INT:
          return this.gpgPrefService.getIntPref(pref);
        case this.gpgPrefService.PREF_BOOL:
          return this.gpgPrefService.getBoolPref(pref);
        default:
          /*
           * Don't warn about Chrome-specific preference values that get
           * queried by gpg_common.js
           */
          if (pref != 'gpg_last_configured' && pref != 'gpg_last_updated') {
            alert('Invalid preference type for ' + pref);
          }
          break;
      }
      return false;
    },
    addObserver: function(anObserver, aTopic, ownsWeak) {
      this.gpgPrefService.addObserver(anObserver, aTopic, ownsWeak);
    }
  };

  return rv;
}

var preferenceObserver = {
  startup:
  function(preferences) {
    if (preferences != null) {
      preferences.addObserver('', this, false);
    }
  },
  observe:
  function(subject, topic, data) {
    if (topic != 'nsPref:changed') {
      return;
    }

    /*
     * TODO(philames): only respond to events when the 'apply changes' button
     * is clicked in options.xul.  This involves creating a new preference
     * (boolean) that is toggled when the user clicks that button, but has no
     * impact on the functionality (we just want to observe its state change).
     * To understand why, read the comment in 'gpgApplyPreferences()' in
     * preferences.js
     */
    switch (data) {
      case 'gpg_binary_path':
        gpg.setConfigValue('gpg_plugin_initialized', 'true');
        if (gpgPrefs.getPreference('gpg_binary_path') == null ||
           gpgPrefs.getPreference('gpg_binary_path').length == 0) {
          alert('GPG binary path not specified, functionality will be ' +
                'disabled.');
          gpg.setConfigValue('gpg_plugin_initialized', 'false');
        }
        gpg.setConfigValue('gpg_binary_path',
                           gpgPrefs.getPreference('gpg_binary_path'));
        break;
      case 'gpg_key_id':
        break;
      default:
        alert('unknown preference \'' + data + '\' updated');
        break;
    }
  }
};


/*
 * preferenceObserver handles configuring the plug-in, but this is needed for
 * initial bootstrapping.
 */
function configurePlugin(gpg, preferences) {
  if (gpg == null) {
    return false;
  }
  if (!gpg.setConfigValue('gpg_binary_path',
      preferences.getPreference('gpg_binary_path')).retbool) {
    return false;
  }

  if (!gpg.setConfigValue('gpg_plugin_initialized', 'true').retbool) {
    return false;
  }

  return true;
}
