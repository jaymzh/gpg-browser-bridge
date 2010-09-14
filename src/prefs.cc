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

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "logging.h"
#include "prefs.h"

/*
 * Valid configuration directives (the 'key' in key=value)
 *
 * To add a new configuration directive, add a new item here
 * and add the directive here, add an entry to the
 * GpgPreferences::ConfigDirective enum, add the appropriate
 * mappings/default values in the default constructor.
 */

static const char *kPLUGIN_INITIALIZED = "gpg_plugin_initialized";
static const char *kPATH_TO_GPG_BINARY = "gpg_binary_path";

/*
 * This function returns the bool form of the directive that was
 * passed in.  It uses the type hints in ConfigTypes[] to notify
 * the caller if they are calling this on a bool type.
 */
bool GpgPreferences::BoolPreference(ConfigDirective directive) const {
  if (ConfigTypes[directive] == kBoolPreference) {
    const std::string &value = Preferences[directive];

    return(value.compare("true") == 0);

  } else {
    LOG("error: boolean preference incorrectly requested for directive %d\n",
        directive);
  }
  return false;
}

/*
 * This function returns the string form of the directive that was
 * passed in.  It uses the type hints in ConfigTypes[] to notify
 * the caller if they are calling this on a string type.
 */
const std::string &GpgPreferences::StringPreference(ConfigDirective directive)
  const {
  static const std::string empty;
  if (ConfigTypes[directive] == kStringPreference) {
    return Preferences[directive];
  } else {
    LOG("error: string preference incorrectly requested for directive %d\n",
        directive);
  }
  return empty;
}


/*
 * This function is responsible for setting a configuration directive.
 * It uses the type hints provided in ConfigTypes[] to convert the
 * string to lowercase (in the case of boolean types) for ease
 * of comparison later.  string types are stored exactly as they were
 * passed in.
 */
bool GpgPreferences::SetDirective(const std::string &key,
                                  const std::string &value) {
  bool rv = false;
  ConfigDirective directive;

  if (ConfigMap.find(key) == ConfigMap.end())
    return false;
  else
    directive = ConfigMap[key];

  switch (ConfigTypes[directive]) {
    case kStringPreference:
      Preferences[directive] = value;
      rv = true;
      break;
    case kBoolPreference:
      if (value.compare("true") == 0 || value.compare("false") == 0) {
        Preferences[directive] = value;
        rv = true;
      } else {
        LOG("error: boolean value incorrectly set(%s) for %d\n",
            value.c_str(), directive);
      }
      break;
    default:
      LOG("error: unknown config type for directive %d\n", directive);
      break;
  }
  return rv;
}


/*
 * The default constructor for GpgPreferences is responsible for:
 * 1. initializing the map of strings to config directives
 * 2. setting the type(string or bool) for each directive,
 * 3. initializing sane defaults
 */
GpgPreferences::GpgPreferences() {
  // Step 1
  ConfigMap[kPLUGIN_INITIALIZED] = GpgPluginInitialized;
  ConfigMap[kPATH_TO_GPG_BINARY] = GpgBinaryPath;

  // Step 2
  ConfigTypes[GpgPluginInitialized] = kBoolPreference;
  ConfigTypes[GpgBinaryPath] = kStringPreference;

  // Step 3
  Preferences[GpgPluginInitialized] = "false";
#if defined(OS_WINDOWS)
  Preferences[GpgBinaryPath] = "C:\\Program Files\\GNU\\GnuPG\\gpg.exe";
#elif defined(OS_MACOSX)
  Preferences[GpgBinaryPath] = "/opt/local/bin/gpg";
#else
  Preferences[GpgBinaryPath] = "/usr/bin/gpg";
#endif
}
