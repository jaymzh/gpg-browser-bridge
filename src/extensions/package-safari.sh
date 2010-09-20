#!/bin/bash
#
# Copyright 2010 Google Inc. All Rights Reserved.
# Author: philames@google.com (Phil Ames)


cp -fpv common/gpg_common.js safari/gpg.safariextension
cat <<EOT
  Common JS files are now in safari/gpg.safariextension.  Please use the Safari
  extension builder in order to package and sign the extension.  See
  http://developer.apple.com/safari/library/documentation/Tools/Conceptual/
  SafariExtensionGuide/UsingExtensionBuilder/UsingExtensionBuilder.html
  for additional details.
EOT

