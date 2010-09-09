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

#ifndef _GPGPLUGIN_GNUPG_H_
#define _GPGPLUGIN_GNUPG_H_

#include <iosfwd>
#include <string>
#include <vector>

#include "prefs.h"
#include "types.h"

struct PRFileDesc;
struct PRProcess;

/*
 * EXCEPTION INFORMATION
 * Nixysa doesn't support execptions. These are our version of exceptions.
 * Each one is referenced by a short-name here which will be used in
 * documenting the functions below. However, what's returned in the javascript
 * object is actually a proper descriptive error message.
 *
 * ERR_INTERNAL
 * Reserved for things like fork(), write(), open(), etc. failed.
 *
 * ERR_NO_GPG_OUTPUT
 * We expected gpg output but didn't get any. This isn't a common exception
 * since we usually catch this with the exit code of gpg and then will either
 * raise a specific exception or at least ERR_UNKNOWN_GPG_ERR.
 *
 * ERR_NO_SECRET_KEY
 * The secret key that we were requested to sign/decrypt with is unavailable.
 *
 * ERR_NO_PUBLIC_KEY
 * The public key we were asked to encrypt/verify with is unavailable.
 *
 * ERR_UNKNOWN_GPG_ERR
 * GPG failed but we did not recognize the error string. This is also used when
 * gpg reports success but an expected output file is missing or empty.
 *
 * ERR_BAD_SIGNATURE
 * Signature verification failed.
 *
 * ERR_SIGNATURE_ERR
 * The signature was malformed or unreadable or not there.
 *
 * ERR_UNEXPECTED_GPG_OUTPUT
 * GPG seemed to succeed but we got output we weren't expecting and are treating
 * it as a failure.
 *   TODO(fixxxer): Some of our output checking is too specific and we should
 *       try to be more lenient...
 *
 * ERR_ALREADY_HAVE_KEY
 * We already have the key we were requested to fetch.
 *
 * ERR_PUBLIC_KEY_NOT_TRUSTED
 * At least one public key we're supposed to be encrypting to is not trusted.
 *
 * ERR_BAD_PUBLIC_KEY
 * At least one public key we're supposed to be encrypting to is expired,
 * revoked or otherwise problematic.
 */

/*
 * BaseGnupg is where most of our plugin is defined. There are two subclasses
 * of it: One is Gnupg, the actual object created from javascript, and the other
 * is the Mock class made from the unittests. Only things that need mocking are
 * created in the subclass, Gnupg. These must be virtual, which is why there's a
 * base class.
 */
class BaseGnupg {
 public:

  virtual ~BaseGnupg() {}

  /*
   * Simple check for if GPG is installed. You should always call this first.
   *
   * OUT: bool
   */
  GpgRetBool IsGpgInstalled();

  /*
   * Get the version text from 'gpg --version'
   *
   * OUT: string
   * RAISES:
   *    ERR_INTERNAL
   */
  GpgRetString GetGnupgVersion();

  /*
   * Two ways to call this function:
   *    * For detached signatures, the signed_text will be
   *      verified using the signature in |signature|.
   *    * For inline signatures, include the signed text
   *      in signed_text and make signature NULL.
   *
   * IN: string SignedText, string Signature
   * OUT: JSObject (signer, trust_level, debug)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_BAD_SIGNATURE
   *    ERR_SIGNATURE_ERR
   *    ERR_UNKNOWN_GPG_ERR
   *    ERR_UNEXPECTED_GPG_OUTPUT
   */
  GpgRetSignerInfo VerifySignedText(const std::string &signed_text,
                                    const std::string &signature);

  /*
   * Encrypt rawtext to keyids (and with hidden recipients kidden_keyids).
   * If always_trust is set, we trust the key even if we wouldn't otherwise.
   * If sign is not null we also sign with the keyid in sign.
   *
   * IN: string ClearText, array KeyIds, array HiddenKeyIds bool always_trust,
   *     optional string signer
   * OUT: JSObject (data, retval)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_GPG_OUTPUT
   *    ERR_PUBLIC_KEY_NOT_TRUSTED
   *    ERR_NO_PUBLIC_KEY
   *    ERR_BAD_PUBLIC_KEY
   *    ERR_UNKNOWN_GPG_ERR
   *    ERR_UNEXPECTED_GPG_OUTPUT
   */
  GpgRetEncryptInfo EncryptText(const std::string &rawtext,
                                const std::vector<std::string> &keyids,
                                const std::vector<std::string> &hidden_keyids,
                                bool always_trust,
                                const std::string &sign);

  /*
   * Sign rawtext using keyid. By default we detach sign and return
   * the signature, however, if clearsign is set, we return the
   * clearsigned text.
   *
   * IN: string RawText, string KeyId, optional bool clearsign
   * OUT: JSObject (retstring)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_SECRET_KEY
   *    ERR_UNKNOWN_GPG_ERR
   *    ERR_UNEXPECTED_GPG_OUTPUT
   *    ERR_UNKNOWN_GPG_ERR
   */
  GpgRetString SignText(const std::string &rawtext,
                        const std::string &keyid,
                        bool clearsign);

  /*
   * Decrypt the text in cipher_text.
   *
   * IN: string CipherText
   * OUT: JSObject (data, debug, optional signer, optional trust)
   *      signer/trust are returned of the encrypted data has a signature in it
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_SECRET_KEY
   *    ERR_UNKNOWN_GPG_ERR
   *    ERR_UNEXPECTED_GPG_OUTPUT
   *    ERR_UNKNOWN_GPG_ERR
   */
  GpgRetDecryptInfo DecryptText(const std::string &cipher_text);

  /*
   * Fetch keyid from keyserver to the local keyring. If keyserver is
   * NULL we won't pass one to gpg so one must be configured locally.
   *
   * IN: string keyid, optional string keyserver
   * OUT: JSOject (retbool)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_UNKNOWN_GPG_ERR
   *    ERR_ALREADY_HAVE_KEY -- NOTE, this is a sort-of success
   *    ERR_UNEXPECTED_GPG_OUTPUT
   */
  GpgRetBool GetKey(const std::string &keyid,
                    const std::string &keyserver);

  /*
   * Return a list of the UIDs on keyid.
   *
   * IN: string keyid
   * OUT: JSObject (uids)
   *      uids is an array of strings
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_PUBLIC_KEY
   */
  GpgRetUidsInfo GetUids(const std::string &keyid);

  /*
   * Get the output of 'gpg --fingerprint' for keyid
   *
   * IN: string keyid
   * OUT: JSObject (retstring)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_PUBLIC_KEY
   */
  GpgRetString GetFingerprint(const std::string &keyid);

  /*
   * Return the trust level of keyid. We return the string version
   * of this such as TRUST_FULL or TRUST_ULTIMATE.
   * IN: string keyid
   * OUT: JSObject (retstring)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_PUBLIC_KEY
   */
  GpgRetString GetTrust(const std::string &keyid);

  /*
   * Sign the uid-th UID on keyid at level.
   *
   * IN: string keyid
   * OUT: JSObject (retbool)
   * RAISES:
   *    ERR_INTERNAL
   *    ERR_NO_PUBLIC_KEY
   */
  GpgRetBool SignUid(const std::string &keyid, const std::string &uid,
                     const std::string &level);

  /*
   * Set a configuration key/value pair to support user preferences.
   * IN: string key
   * IN: string value
   * OUT: JSObject (retbool)
   */
  GpgRetBool SetConfigValue(const std::string &key, const std::string &value);

  /*
   * In theory, these would be private, but then we can't test them.
   * There's no security reason to have them be private - the Nixysa
   * framework only exports what we want it to anyway.
   */
  virtual PRProcess *CallGpg(const std::vector<const char*> &args) = 0;
  virtual bool ReadAllGpgOutput(std::string *output) = 0;
  virtual int WaitOnGpg(PRProcess *process) = 0;
  virtual bool ReadFileToString(const char *filename, std::string *text) = 0;
  bool ParseGpgLine(const std::string &line,
                    std::vector<std::string> *output);
  bool ParseGpgOutput(const std::string &input,
                      std::vector< std::vector<std::string> > *lines);
  bool ExpectString(const std::string &response);
  bool CheckForOrderedOutput(
          const std::vector<std::string> &expected,
          const std::vector< std::vector<std::string> > &output);
  bool CheckForUnorderedOutput(
          const std::vector<std::string> &expected,
          const std::vector< std::vector<std::string> > &output);
  bool CheckForSingleOutput(
          const char *string,
          const std::vector< std::vector<std::string> > &output);
  bool SplitOnChar(const std::string &line,
                   char schar,
                   std::vector<std::string> *output);
  std::string ReadFromFdIntoString(int fd);
  bool SplitOnSpaces(const std::string &line, std::vector<std::string> *output);
  bool CallReadAndWaitOnGpg(const std::vector<const char*> &args,
                            int *retval, std::string *output);


 protected:
  std::istream *instream_;
  std::ostream *outstream_;
  PRFileDesc *command_pipe_[2];
  PRFileDesc *status_pipe_[2];
  GpgPreferences preferences_;
};

/*
 * This is the actual object one will get back from Javascript. See the comment
 * above BaseGnupg for more details.
 */
class Gnupg : public BaseGnupg {
 public:
  PRProcess *CallGpg(const std::vector<const char*> &args);
  bool ReadAllGpgOutput(std::string *output);
  int WaitOnGpg(PRProcess *process);
  bool ReadFileToString(const char *filename, std::string *text);
};


#endif  // _GPGPLUGIN_GNUPG_H_
