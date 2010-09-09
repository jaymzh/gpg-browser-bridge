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
 *   Phil Dibowitz <fixxxer@google.com>
 *
 * ***** END LICENSE BLOCK *****
 */

#include <npapi.h>

extern "C" {
  const char *NP_GetMIMEDescription(void) {
    return "application/gpg::GnuPG Javascript Bridge";
  }

  NPError NP_GetValue(NPP instance, NPPVariable variable, void *value) {
    switch (variable) {
      case NPPVpluginNameString:
        *static_cast<const char **>(value) = "GnuPG Plugin";
        break;
      case NPPVpluginDescriptionString:
        *static_cast<const char **>(value) = "GnuPG Plugin";
        break;
      default:
        return NPERR_INVALID_PARAM;
        break;
    }
    return NPERR_NO_ERROR;
  }
}
