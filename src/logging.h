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

#ifndef _GPGPLUGIN_LOGGING_H_
#define _GPGPLUGIN_LOGGING_H_

#ifdef OS_WINDOWS

#include <windows.h>
void LOG(LPCTSTR format, ...);

#else

#include <stdio.h>
#define LOG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)

#endif  // OS_WINDOWS

#endif  // _GPGPLUGIN_LOGGING_H_
