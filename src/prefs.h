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

#ifndef GPG_PLUGIN_PREFS_H_
#define GPG_PLUGIN_PREFS_H_

#include <map>
#include <string>

class GpgPreferences {
 public:
  enum ConfigDirective {
    GpgPluginInitialized,
    GpgBinaryPath,
    NumberOfDirectives
  };

  GpgPreferences();

  bool BoolPreference(ConfigDirective directive) const;
  const std::string& StringPreference(ConfigDirective directive) const;
  bool SetDirective(const std::string &key, const std::string &value);

 private:
  static const unsigned int kStringPreference = 0;
  static const unsigned int kBoolPreference = 1;

  std::map<std::string, ConfigDirective> ConfigMap;
  unsigned int ConfigTypes[NumberOfDirectives];
  std::string Preferences[NumberOfDirectives];
};

#endif  // GPG_PLUGIN_PREFS_H_
