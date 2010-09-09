#!/bin/bash
#
# * Copyright 2010, Google Inc.
# *
# * ***** BEGIN LICENSE BLOCK *****
# * Version: MPL 1.1
# *
# * The contents of this file are subject to the Mozilla Public License Version
# * 1.1 (the "License"); you may not use this file except in compliance with
# * the License. You may obtain a copy of the License at
# * http://www.mozilla.org/MPL/
# *
# * Software distributed under the License is distributed on an "AS IS" basis,
# * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# * for the specific language governing rights and limitations under the
# * License.
# *
# * The Original Code is the GPG Browser Bridge.
# *
# * The Initial Developer of the Original Code is Google Inc.
# *
# * Portions created by the Initial Developer are Copyright (C) 2010
# * the Initial Developer. All Rights Reserved.
# *
# * Contributor(s):
# *   Phil Ames <philames@google.com>
# *
# * ***** END LICENSE BLOCK *****
#

if [ -z "$CHROME" ]
then
  CHROME=google-chrome
fi

cp -fpv ../libnpgnupg.so common/gpg_common.js chrome
$CHROME --pack-extension=chrome
cat <<EOT
Package complete.  If no .crx present, please close all instances of Chrome.
EOT
