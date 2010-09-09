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
 *   Fredrik Roubert <roubert@google.com>
 *   Phil Ames <philames@google.com>
 *
 * ***** END LICENSE BLOCK *****
 */

#ifndef _GPGPLUGIN_TMPWRAPPER_H_
#define _GPGPLUGIN_TMPWRAPPER_H_

#include <string>

/*
 * TmpWrapper is a class that handles opening temporary files and deleting
 * them when the wrapper goes out of scope. Think of it as an auto_ptr
 * for tmpfiles.
 */
class TmpWrapper {
 public:
  ~TmpWrapper() {if (!filename_.empty()) {unlink(filename_.c_str());}}
  /*
   * The primary caller, we'll figure out a useful temp file
   * based on |pattern|, write the filename back to |pattern|
   * write |content| to it
   *
   * |content| must be a real string, and |pattern| must follow the mktemp()
   * format for a pattern.
   */
  bool CreateAndWriteTmpFile(const std::string &content, std::string *pattern);
  /*
   * For files that other processes will create, make sure they're not there
   * and then track them in this object.
   */
  void UnlinkAndTrackFile(const std::string &filename);

 private:
  /* Handles the actual writing for CreateAndWriteTmpFile() */
  bool WriteStringToFile(const std::string &text, const char *filename);
  std::string filename_;
};


#endif  // _GPGPLUGIN_TMPWRAPPER_H_
