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
 *   Fredrik Roubert <roubert@google.com>
 *
 * ***** END LICENSE BLOCK *****
 */

/*
 * This file declares the CreateProcessNoWindow() function, a workaround to
 * be used until the NSPR PR_CreateProcess() function has been updated to be
 * able to set the CREATE_NO_WINDOW flag to the Win32 CreateProcess() system
 * call.
 *
 * TODO(roubert): Delete this when NSPR has been updated.
 */

#ifndef _GPGPLUGIN_CREATEPROCESS_H_
#define _GPGPLUGIN_CREATEPROCESS_H_

struct PRProcess;
struct PRProcessAttr;

PRProcess *CreateProcessNoWindow(const char *path,
                                 char *const *argv,
                                 char *const *envp,
                                 const PRProcessAttr *attr);

#endif  // _GPGPLUGIN_CREATEPROCESS_H_
