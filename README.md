# INSTALLATION INSTRUCTIONS

## LINUX

0. Prereqs
   You will need to have the following installed:
   - scons
   - libnspr4-dev
   - GnuPG

1. Build the plugin
   $ cd src && scons

2. Install the plugin
   $ sudo cp libnpgnupg.so /path/to/firefox/plugins
   (e.g., ~/.mozilla/plugins)

3. Check the installation
   Open firefox, go to "about:plugins" and ensure it's there

4. Test
   See http://www/~fixxxer/gpg_test/gpg_test.html


## MAC

0. Prereqs
   You will need the following installed:
   - XCode (or some other way of getting g++ and friends)
   - SCons
   - NSPR
   - GMock
   - GnuPG

   MacPorts is your best bet for SCons, NSPR and GMock. Make sure to specify
   the +universal flag to get both 32- and 64-bit libraries installed:

   sudo port install scons
   sudo port install nspr +universal
   sudo port install gmock +universal

   GnuPG can be had from http://macgpg.sourceforge.net/ or from MacPorts.

1. Build the plugin
   $ cd src && scons

2. Install the plugin
   $ pushd ~/Library/Internet\ Plugins/
   $ mkdir -p gpg.plugin/Contents/MacOS
   $ popd
   $ cp mac/Info.plist ~/Library/Internet\ Plugins/gpg.plugin/Contents
   $ cp libnpgnupg.dylib ~/Library/Internet\ Plugins/gpg.plugin/Contents/MacOS

3. Check the installation
   - Firefox:
     Open firefox, go to "about:plugins" and ensure it's there
   - Safari:
     Open safari, go to Help -> Installed Plugins, and ensure it's there

4. Unit Test
   $ scons gnupg_unittest && ./gnupg_unittest


## WINDOWS

0. Prereqs
   You will need the following installed:
   - Microsoft Visual C++
   - XULRunner

   XULRunner is the easiest way to get the NSPR SDK for Windows. It can be
   downloaded from here:

   http://releases.mozilla.org/pub/mozilla.org/xulrunner/releases/

   (It's however not necessary to get NSPR through XULRunner, see the
   --with-nspr-include and --with-nspr-libdir options to SCons.)

   You need to download and build GMock yourself. If you have MSVC 2005, then
   you can just download the latest stable source release from here:

   http://code.google.com/p/googlemock/downloads/list

   Then unzip the source in a directory next to your gpg-browser-bridge
   directory and build GMock like this:

   cd gmock-1.5.0\msvc
   msbuild /t:gmock /p:Configuration=Release gmock.sln

   If you have MSVC 2010, then you need to check out revision 357 or later from
   the Subversion repository as described here:

   http://code.google.com/p/googlemock/source/checkout

   Check out the source to a directory next to your gpg-browser-bridge
   directory and build GMock like this:

   cd googlemock-read-only\msvc\2010
   msbuild /t:gmock /p:Configuration=Release gmock.sln

1. Build the plugin and tests

   The default is to look for XULRunner in the root of the current drive. If
   it's installed somewhere else, specify --with-xulrunner-prefix to SCons.

   If you built GMock from the 1.5.0 source release, just type:

   scons .

   If you built GMock from a Subversion checkout, then type:

   scons --with-gmock-prefix=..\..\googlemock-read-only
         --with-gmock-libdir=..\..\googlemock-read-only\msvc\2010\Release .

   If compilation succeeds, run the tests by typing "gnupg_unittest.exe".


# UNITTESTS

If you have gmock and gtest available, you can build unittests with
  $ scons gnupg_unittest

And then run them with:
  # ./gnupg_unittest

# BROWSER EXTENSION

In order for the plugin to work, it is also necessary to install the
appropriate browser extension (located in src/extensions/...).

To prepare the extension directories for packing (or for loading unpacked
extensions directly from these directories), run the following commands:

scons extensions/chrome
scons extensions/firefox
scons extensions/safari

There are also build rules to pack the extensions for Chrome and Firefox:

scons extensions/chrome.crx
scons extensions/gpg.xpi

(Note that there can't be any already running Chrome instance when packing the
Chrome extension, and if running on Linux it must be able to connect to an X
server.)

To install the Firefox extension without building an XPI, in your
Mozilla profile directory (which will look something like
~/.mozilla/firefox/6711k3x8.default/extensions/) create a file named
'gpg@google' and for the file contents, put the path to the extension, a single
line such as: /home/user/gpg/opensource/gpg_plugin/src/extensions/firefox/.

To install the Chrome extension, launch Chrome and enter chrome://extensions in
the address bar.  Ensure that Developer Mode is enabled, and then click the
'Load Unpacked Extension' button.  Select the directory that contains the
Chrome extension files.  To create a crx file, once you have loaded the
unpacked extension, you can click 'pack extension' from the
chrome://extensions/ page.

The Safari extension should function properly once the following bug is
resolved:
https://bugs.webkit.org/show_bug.cgi?id=44351

Also notice that there is a special build target for a Safari version of the
plugin to work around the facts that Safari doesn't provide NSPR and that NSPR
can't be statically linked to 32-bit binaries (probably because of some arcane
bug that might or might not be fixed in the future):

scons libnpgnupg-nspr-64.dylib

To pack the extension (even though it doesn't work yet) use the Safari
extension builder in order to package and sign the extension.  See
http://developer.apple.com/safari/library/documentation/Tools/Conceptual/
SafariExtensionGuide/UsingExtensionBuilder/UsingExtensionBuilder.html
for additional details.

There are some known limitations between browsers.  None of the browsers
seem to support dispatching events/passing messages between pages loaded
from a file:// origin.  On Firefox, the event is properly dispatched and
the extension code can see that it would have to post a message back to
a file:// page and create an alert() box telling the user that their operation
has failed, but on Chrome, the message does not appear to be dispatched to
the extension.
