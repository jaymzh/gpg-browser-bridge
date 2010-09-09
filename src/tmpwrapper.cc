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
 *
 * ***** END LICENSE BLOCK *****
 */

#include "tmpwrapper.h"

#ifdef OS_WINDOWS
#include <io.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#endif

#include <fcntl.h>
#include <stdlib.h>

#include <cerrno>
#include <cstring>

#include "gnupg.h"
#include "logging.h"

#if !defined(S_IRUSR) && !defined(S_IWUSR)
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#endif

bool TmpWrapper::WriteStringToFile(const std::string &text,
                                   const char *filename) {
  LOG("GPG: Writing tempfile %s\n", filename);
  int fd = open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
  if (fd == -1) {
    LOG("GPG: Failed to open temp file %s: %s", filename, std::strerror(errno));
    return false;
  }
  FILE *fs = fdopen(fd, "w");
  if (!fs) {
    close(fd);
    unlink(filename);
    LOG("GPG: Failed to fdopen temp fd: %s", std::strerror(errno));
    return false;
  }
  if (fputs(text.c_str(), fs) == -1) {
    LOG("GPG: Failed to write to tmpfile %s: %s\n", filename,
        std::strerror(errno));
    /*
     * The state here is unknown. We should try to close/unlink the file,
     * but if they error there's nothign we can do, we're already returning
     * an error, so we don't check this.
     */
    fclose(fs);
    unlink(filename);
    return false;
  }
  fclose(fs);
  return true;
}

bool TmpWrapper::CreateAndWriteTmpFile(const std::string &content,
                                       std::string *pattern) {
  char *filename = strdup(pattern->c_str());
  /*
   * In theory mktemp is dangerous, but we emulate mkstemp behavior here.
   *
   * NOTE WELL: It is VERY important that the MODE in this open is SAFE.
   *    We MUST open files as 600. Otherwise we may let people read
   *    sensitive data!
   */
  mktemp(filename);
  filename_ = filename;
  if (!WriteStringToFile(content, filename)) {
    free(filename);
    return false;
  }
  *pattern = filename;
  free(filename);
  return true;
}

void TmpWrapper::UnlinkAndTrackFile(const std::string &filename) {
  unlink(filename.c_str());
  filename_ = filename;
}
