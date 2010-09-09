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

#include "logging.h"

/*
 * Implementations of those functions/macros declared in logging.h that aren't
 * definied inline.
 */

#ifdef OS_WINDOWS

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>

void LOG(LPCTSTR format, ...) {
  assert(format != NULL);

  va_list args;
  size_t size;
  LPTSTR buffer;

  size = _tcslen(format) + 1;
  va_start(args, format);
  for (;;) {
    buffer = new _TCHAR[size];
    if (_vsntprintf_s(buffer, size, size - 1, format, args) >= 0) break;
    delete[] buffer;
    size <<= 1;
  }
  va_end(args);

  OutputDebugString(buffer);
  delete[] buffer;
}

#endif  // OS_WINDOWS
