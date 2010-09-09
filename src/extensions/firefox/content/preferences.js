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
 * @fileoverview Helper functions for options.xul.
 * @author philames@google.com (Phil Ames)
 */

function gpgApplyPreferences() {
  /* Currently a no-op.  Firefox changes preferences in realtime (as you type).
   * This results in things like the gpg_binary_path being set to '/', then
   * '/u', then '/us', then '/usr', etc. on to /usr/bin/gpg (not really ideal).
   * This function will eventually toggle some arbitrary boolean preference in
   * the extensions.gpg tree (designed for this purpose) and the observer will
   * update _all_ preferences at the time that preference is toggled to prevent
   * the unnecessary extra work/logs.
   */
  alert('Preferences Updated');
  window.close();
}
