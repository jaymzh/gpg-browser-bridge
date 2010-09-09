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

/*
 * READ THIS!!!
 *
 * WARNING:
 * All functions that take in keys/recipients/signers expect keyids. Some of
 * them will work with email/uid specifications, but only because gpg is
 * lenient on some functions. This hasn't been tested with those code.
 *
 * The TODO here is for major features that haven't been implemented yet or
 * globally-effecting TODOs, but many of the call-points below have their own
 * TODO list as well.
 *
 * TODO(fixxxer):
 *  - search keys method
 *  - list-of-keys method
 */

#include "gnupg.h"

#include <npapi.h>
#include <npfunctions.h>
#include <prerror.h>
#include <prio.h>
#include <prproces.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "logging.h"
#include "prstrms.h"
#include "static_object.h"
#include "tmpwrapper.h"
#include "types.h"

#if defined(OS_WINDOWS)
#include "createprocess.h"
#endif

static const char *kTMP_SIGNED_TEXT = "/tmp/plugin_gnupg_signed_txt_XXXXXX";
/* CIPHER_TEXT should be whatever this comes out to, plus ".asc" */
static const char *kTMP_RAW_TEXT = "/tmp/plugin_gnupg_raw_txt_XXXXXX";
static const char *kTMP_SIGNATURE = "/tmp/plugin_gnupg_signature_XXXXXX";

#if defined(OS_WINDOWS)
#define DEV_NULL "NUL:"
#else
#define DEV_NULL "/dev/null"
#endif

/*
 * Various GPG responses
 */
static const char *kGPG_INV_RECP = "INV_RECP";
/* BEING: Sub-reasons for kGPG_INV_RECP */
static const char *kGPG_INV_NOT_TRUSTED = "10";
/* It's supposed to be "1", but is often "0"... */
static const char *kGPG_INV_NOT_FOUND1 = "0";
static const char *kGPG_INV_NOT_FOUND2 = "1";
/* END: Sub-reasons for kGPG_INV_RECP */
static const char *kGPG_END_ENCRYPTION = "END_ENCRYPTION";
static const char *kGPG_BADSIG = "BADSIG";
static const char *kGPG_NODATA = "NODATA";
static const char *kGPG_SIG_ID = "SIG_ID";
static const char *kGPG_GOODSIG = "GOODSIG";
static const char *kGPG_VALIDSIG = "VALIDSIG";
static const char *kGPG_USERID_HINT = "USERID_HINT";
static const char *kGPG_NEED_PASSPHRASE = "NEED_PASSPHRASE";
static const char *kGPG_GOOD_PASSPHRASE = "GOOD_PASSPHRASE";
static const char *kGPG_BAD_PASSPHRASE = "BAD_PASSPHRASE";
static const char *kGPG_BEGIN_SIGNING = "BEGIN_SIGNING";
static const char *kGPG_SIG_CREATED = "SIG_CREATED";
static const char *kGPG_ENC_TO = "ENC_TO";
static const char *kGPG_PLAINTEXT = "PLAINTEXT";
static const char *kGPG_PLAINTEXT_LENGTH = "PLAINTEXT_LENGTH";
static const char *kGPG_DECRYPTION_OKAY = "DECRYPTION_OKAY";
static const char *kGPG_GOODMDC = "GOODMDC";
static const char *kGPG_END_DECRYPTION = "END_DECRYPTION";
static const char *kGPG_DECRYPTION_FAILED = "DECRYPTION_FAILED";
static const char *kGPG_IMPORT_OK = "IMPORT_OK";
static const char *kGPG_IMPORTED = "IMPORTED";
static const char *kGPG_PROMPT = "GET_LINE";
static const char *kGPG_ACK = "GOT_IT";
static const char *kGPG_CONFIRM = "GET_BOOL";
static const char *kGPG_ALREADY_SIGNED = "ALREADY_SIGNED";

/*
 * Exceptions we raise
 */
static const char *kERR_INTERNAL = "Internal error";
static const char *kERR_NO_SECRET_KEY = "Secret key not available";
static const char *kERR_NO_PUBLIC_KEY = "Public key not available";
static const char *kERR_UNKNOWN_GPG_ERR = "Unknown gpg error";
static const char *kERR_BAD_SIGNATURE = "Bad signature";
static const char *kERR_SIGNATURE_ERR = "Signature not found or unreadable";
static const char *kERR_UNEXPECTED_GPG_OUTPUT = "Unexpected gpg output";
static const char *kERR_ALREADY_HAVE_KEY = "Already have key";
static const char *kERR_PUBLIC_KEY_NOT_TRUSTED = "Key not trusted";
static const char *kERR_BAD_PUBLIC_KEY = "Key expired or revoked";
static const char *kERR_ALREADY_SIGNED = "Key/Uid already signed";
static const char *kERR_BAD_PASSPHRASE =
    "Bad passphrase or couldn't talk to gpg-agent";


/*
 * *** BEGIN HELPER FUNCTIONS ***
 */

/*
 * This is a function to handle the execution of gpg as well as setup the
 * pipes appropriately.
 *
 * It will set up two pipes so that command_pipe_[1] can be used to write to
 * the gpg process and status_pipe_[0] can be used to read from it.
 *
 * The passphrase must always be written to the command pipe first before gpg
 * will do anything. If no passphrase will be needed an newline may be written.
 */
PRProcess *Gnupg::CallGpg(const std::vector<const char*> &args) {
  PRProcessAttr *attr;
  PRFileDesc *null;
  PRProcess *process;
  std::vector<const char*> command;
  char *const *argv;
  const char *gpg_path = preferences_.StringPreference(
      GpgPreferences::GpgBinaryPath).c_str();

  LOG("GPG: In CallGpg\n");

  if (PR_CreatePipe(&command_pipe_[0], &command_pipe_[1]) == PR_FAILURE) {
    LOG("GPG: PR_CreatePipe failed: %d\n", PR_GetError());
    goto error_return;
  }
  if (PR_CreatePipe(&status_pipe_[0], &status_pipe_[1]) == PR_FAILURE) {
    LOG("GPG: PR_CreatePipe failed: %d\n", PR_GetError());
    goto error_cleanup_from_command_pipe;
  }

  /*
   * Set reading end of the command pipe and the writing end of the status pipe
   * to be inheritable by a child process, and set the other ends to be not
   * inheritable, so that the process that's created later inherits the file
   * descriptors it needs (and no others).
   */
  if (PR_SetFDInheritable(command_pipe_[0], PR_TRUE) == PR_FAILURE) {
    LOG("GPG: PR_SetFDInheritable failed: %d\n", PR_GetError());
    goto error_cleanup_from_status_pipe;
  }
  if (PR_SetFDInheritable(command_pipe_[1], PR_FALSE) == PR_FAILURE) {
    LOG("GPG: PR_SetFDInheritable failed: %d\n", PR_GetError());
    goto error_cleanup_from_status_pipe;
  }
  if (PR_SetFDInheritable(status_pipe_[0], PR_FALSE) == PR_FAILURE) {
    LOG("GPG: PR_SetFDInheritable failed: %d\n", PR_GetError());
    goto error_cleanup_from_status_pipe;
  }
  if (PR_SetFDInheritable(status_pipe_[1], PR_TRUE) == PR_FAILURE) {
    LOG("GPG: PR_SetFDInheritable failed: %d\n", PR_GetError());
    goto error_cleanup_from_status_pipe;
  }

  attr = PR_NewProcessAttr();
  if (attr == NULL) {
    LOG("GPG: PR_NewProcessAttr failed: %d\n", PR_GetError());
    goto error_cleanup_from_status_pipe;
  }

  if (PR_ProcessAttrSetCurrentDirectory(attr, "/") == PR_FAILURE) {
    LOG("GPG: PR_ProcessAttrSetCurrentDirectory failed: %d\n", PR_GetError());
    goto error_cleanup_from_attr;
  }

  /*
   * You have to do something with stderr if you don't want pgp to hang.
   */
  null = PR_Open(DEV_NULL, PR_WRONLY, 0);
  if (null == NULL) {
    LOG("GPG: PR_Open failed: %d\n", PR_GetError());
    goto error_cleanup_from_attr;
  }

  PR_ProcessAttrSetStdioRedirect(attr, PR_StandardInput, command_pipe_[0]);
  PR_ProcessAttrSetStdioRedirect(attr, PR_StandardOutput, status_pipe_[1]);
  PR_ProcessAttrSetStdioRedirect(attr, PR_StandardError, null);

  command.push_back(gpg_path);
  command.push_back("--use-agent");
  command.push_back("--command-fd");
  command.push_back("0");
  command.push_back("--status-fd");
  command.push_back("1");
  command.push_back("--quiet");
  command.push_back("--batch");
  command.push_back("--no-tty");
  command.insert(command.end(), args.begin(), args.end());
  command.push_back(NULL);
  argv = const_cast<char *const *>(&(command[0]));

  LOG("GPG: PR_CreateProcess pgp\n");
#if defined(OS_WINDOWS)
  /*
   * Use a workaround until NSPR has been updated to allow execution of Windows
   * Console Applications without opening an empty window.
   *
   * TODO(roubert): Delete this when NSPR has been updated.
   */
  process = CreateProcessNoWindow(gpg_path, argv, NULL, attr);
#else
  process = PR_CreateProcess(gpg_path, argv, NULL, attr);
#endif
  if (process == NULL) {
    LOG("GPG: PR_CreateProcess failed: %d\n", PR_GetError());
    goto error_cleanup_from_null;
  }

  PR_DestroyProcessAttr(attr);

  /*
   * We close the file descriptors we don't need.
   */
  if (PR_Close(command_pipe_[0]) == PR_FAILURE) {
    LOG("GPG: PR_Close failed: %d\n", PR_GetError());
  }
  if (PR_Close(status_pipe_[1]) == PR_FAILURE) {
    LOG("GPG: PR_Close failed: %d\n", PR_GetError());
  }
  if (PR_Close(null) == PR_FAILURE) {
    LOG("GPG: PR_Close failed: %d\n", PR_GetError());
  }

  /*
   * Here we wrap the pipes in streams. This is so we can use C++
   * functions to do string reading and parsing which is far less
   * error_return prone than doing it manually...
   *
   * In particular this is useful for the interactive cases where
   * we'd rather be calling std::getline() then reading one char
   * at a time looking for newlines, ourselves.
   */
  outstream_ = new PRofstream(command_pipe_[1]);
  instream_ = new PRifstream(status_pipe_[0]);

  return process;

error_cleanup_from_null:
  PR_Close(null);

error_cleanup_from_attr:
  PR_DestroyProcessAttr(attr);

error_cleanup_from_status_pipe:
  PR_Close(status_pipe_[1]);
  PR_Close(status_pipe_[0]);

error_cleanup_from_command_pipe:
  PR_Close(command_pipe_[1]);
  PR_Close(command_pipe_[0]);

error_return:
  return NULL;
}

/*
 * Reads the output stream of gpg and returns a string.
 *
 * |out| must point to a valid string object.
 */
bool Gnupg::ReadAllGpgOutput(std::string *out) {
  LOG("GPG: Reading pgp\n");
  if (!out) {
    LOG("GPG: out is NULL!\n");
    return false;
  }
  std::string line;
  while (std::getline(*instream_, line)) {
    out->append(line + "\n");
  }
  if (instream_->bad()) {
    LOG("GPG: Failed to read from gpg\n");
    return false;
  }
  LOG("GPG: Read %u bytes\n", static_cast<unsigned int>(out->size()));
  LOG("GPG: Read: \"%s\"\n", out->c_str());
  return true;
}

/*
 * This is for functions that require interaction with gpg. After a
 * command, this function looks for the expected response. If multiple
 * responses are expect, it is suggested you call ExpectString() on each
 * one.
 */
bool BaseGnupg::ExpectString(const std::string &response) {
  LOG("GPG: ExpectString\n");

  LOG("GPG:   looking for %s\n", response.c_str());
  std::string line;
  std::getline(*instream_, line);
  if (instream_->fail()) {
    LOG("GPG:   reading from stream failed\n");
    return false;
  }
  std::vector<std::string> parsed_line;
  if (!ParseGpgLine(line, &parsed_line)) {
    LOG("GPG:   failed to parse line\n");
    return false;
  }
  LOG("GPG:   got %s\n", parsed_line[0].c_str());
  if (parsed_line[0] == response) {
    return true;
  }
  return false;
}

/*
 * Helper function for the ParseGpgOutput() function below.
 *
 * This parses GPG standardized-output lines that look like this:
 *
 *    [GNUPG:] <RESPONSE> <EXTRA_INFO>
 *
 * It does this by ignoring the "[GNUPG:] ", and returns a vector
 * of two strings. The first is <RESPONSE> and the second is <EXTRA_INFO>
 */
bool BaseGnupg::ParseGpgLine(const std::string &line,
                             std::vector<std::string> *output) {
  LOG("GPG: Parsing line %s\n", line.c_str());

  std::stringstream line_stream(line);

  std::string token;
  /* drop "[GNUPG:]" */
  if (!std::getline(line_stream, token, ' ')) {
    LOG("GPG: Failed nuke lame token\n");
    return false;
  }
  /* get the right token */
  if (!std::getline(line_stream, token, ' ')) {
    LOG("GPG: Failed grab good token\n");
    return false;
  }

  LOG("GPG: resp: \"%s\"\n", token.c_str());
  std::string rest;
  /*
   * Get the rest of the line - note we don't error check
   * because there may be nothing left, and that's OK.
   */
  std::getline(line_stream, rest);
  LOG("GPG: rest: \"%s\"\n", rest.c_str());

  output->push_back(token);
  output->push_back(rest);

  return true;
}

/*
 * A function to parse GPG output. Lines are parsed by the above ParseGpgLine()
 * function, and this returns a vector of vectors. Each outer vector is a line
 * and each inner vector is the output of the above parsing function on that
 * line.
 */
bool BaseGnupg::ParseGpgOutput(const std::string &input,
                               std::vector< std::vector<std::string> > *lines) {
  LOG("GPG: ParseGpgOutput\n");
  std::istringstream gpgout(input);
  std::string line;

  while (getline(gpgout, line)) {
    LOG("GPG: Got line \"%s\"\n", line.c_str());
    std::vector<std::string> lineparts;
    if (!ParseGpgLine(line, &lineparts)) {
      LOG("GPG: Failing parse, line parse failed on %s\n", line.c_str());
      return false;
    }
    lines->push_back(lineparts);
  }
  return true;
}

/*
 * A wrapper on wait to do the logging and return the status.
 */
int Gnupg::WaitOnGpg(PRProcess *process) {
  delete instream_;
  delete outstream_;
  instream_ = NULL;
  outstream_ = NULL;

  LOG("GPG: Waiting on pgp...");
  PRInt32 ret;
  if (PR_WaitProcess(process, &ret) == PR_FAILURE) {
    LOG("GPG: Failed to PR_WaitProcess: %d\n", PR_GetError());
    return -1;
  }
  LOG(" done\n");
  return ret;
}

/*
 * A convenience wrapper to call CallGpg, ReadAllGpgOutput, WaitOnGpg.
 *
 * For our non-interactive calls this works well, we only do it manually
 * in interactive calls.
 *
 * |output| must point to a valid string object.
 */
bool BaseGnupg::CallReadAndWaitOnGpg(const std::vector<const char*> &args,
                                     int *retval, std::string *output) {
  LOG("GPG: In CallReadAndWaitOnGpg\n");

  if (!preferences_.BoolPreference(GpgPreferences::GpgPluginInitialized)) {
    LOG("GPG: plugin not initialized\n");
    return false;
  }

  PRProcess *process = CallGpg(args);

  if (process == NULL) {
    LOG("GPG: Failed to execute\n");
    return false;
  }

  LOG("GPG: Reading GPG Output\n");
  if (!ReadAllGpgOutput(output)) {
    return false;
  }

  LOG("GPG: Waiting on gpg\n");
  *retval = WaitOnGpg(process);

  return true;
}

/*
 * Given an ordered series of responses we expect, make sure that happened.
 */
bool BaseGnupg::CheckForOrderedOutput(
    const std::vector<std::string> &expected,
    const std::vector< std::vector<std::string> > &output) {
  if (expected.size() > output.size()) {
    return false;
  }
  for (size_t i = 0; i < expected.size(); i++) {
    if (expected[i] != output[i][0]) {
      LOG("GPG: Was expecting \"%s\" but got \"%s\"\n", expected[i].c_str(),
           output[i][0].c_str());
      return false;
    }
  }
  return true;
}

/*
 * An alternative to the CheckForOrderedOutput approach - we get a list
 * of required responses and make sure they're there.
 *
 * The difference between this and the above is that this one does
 * not enforce order.
 */
bool BaseGnupg::CheckForUnorderedOutput(
    const std::vector<std::string> &expected,
    const std::vector< std::vector<std::string> > &output) {
  std::set<std::string> output_set;
  for (size_t i = 0; i < output.size(); i++)
    output_set.insert(output[i][0]);

  for (size_t i = 0; i < expected.size(); i++) {
    if (output_set.find(expected[i]) == output_set.end()) {
      return false;
    }
  }

  return true;
}

/*
 * Wrapper around the above to make the vector for you.
 */
bool BaseGnupg::CheckForSingleOutput(
    const char *expected,
    const std::vector< std::vector<std::string> > &output) {
  std::vector<std::string> expected_outputs;
  expected_outputs.push_back(expected);
  return CheckForUnorderedOutput(expected_outputs, output);
}

/*
 * Split on a character, nuf said.
 */
bool BaseGnupg::SplitOnChar(const std::string &line,
                            char schar,
                            std::vector<std::string> *output) {
  LOG("GPG: SplitOnChar: \"%c\"\n", schar);

  std::stringstream line_stream(line);
  std::string token;

  while (getline(line_stream, token, schar)) {
    output->push_back(token);
  }

  return true;
}

/*
 * Wrapper on the above.
 */
bool BaseGnupg::SplitOnSpaces(const std::string &line,
                              std::vector<std::string> *output) {
  LOG("GPG: SplitOnSpaces\n");
  return SplitOnChar(line, ' ', output);
}

/*
 * Read all of the data from a file - generally an output file from GPG.
 */
bool Gnupg::ReadFileToString(const char *filename, std::string *text) {
  LOG("GPG: Reading tempfile %s\n", filename);

  if (!text || !filename) {
    return false;
  }

  std::ifstream file(filename);
  if (!file.is_open()) {
    LOG("GPG: Failed to open file: %s\n", filename);
    return false;
  }
  std::string line;
  std::string data;
  while (getline(file, line)) {
    data.append(line);
    data.append("\n");
  }
  file.close();
  LOG("GPG: Read %u bytes\n", static_cast<unsigned int>(data.size()));
  LOG("GPG: Read: \"%s\"\n", data.c_str());
  *text = data;
  return true;
}


/*
 * *** BEGIN API FUNCTIONS ***
 */

/*
 * A base test to make sure that we can find the gpg binary.
 * Returns true if we can, false otherwise.
 */
GpgRetBool BaseGnupg::IsGpgInstalled() {
  struct stat file_info;
  GpgRetBool retobj;
  if (stat(preferences_.StringPreference(
      GpgPreferences::GpgBinaryPath).c_str(), &file_info)) {
    retobj.set_retbool(false);
    return retobj;
  }
  retobj.set_retbool(true);
  return retobj;
}

/*
 * Returns the version output of GPG as a JS string.
 */
GpgRetString BaseGnupg::GetGnupgVersion() {
  GpgRetString retobj;

  std::vector<const char*> args;
  args.push_back("--version");

  int ret;
  std::string version;
  if (!CallReadAndWaitOnGpg(args, &ret, &version)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  if (ret) {
    LOG("GPG: GPG failed with status: %d\n", ret);
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  retobj.set_retstring(version);
  return retobj;
}

/*
 * Verify signature for signed_text.
 *
 * Note there are two ways to call this function:
 *   - with "signature" - this is for detached signatures
 *   - without "signature" - this is for clearsigned text and the
 *     signature is assumed to be in signed_text
 */
GpgRetSignerInfo BaseGnupg::VerifySignedText(const std::string &signed_text,
                                             const std::string &signature) {
  GpgRetSignerInfo retobj;

  LOG("GPG: In VerifySignedText\n");

  std::string signed_file = kTMP_SIGNED_TEXT;
  TmpWrapper signed_wrapper;
  if (!signed_wrapper.CreateAndWriteTmpFile(signed_text, &signed_file)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  std::string sig_file = kTMP_SIGNATURE;
  TmpWrapper sig_wrapper;
  if (signature.size()) {
    if (!sig_wrapper.CreateAndWriteTmpFile(signature, &sig_file)) {
      retobj.set_error_str(kERR_INTERNAL);
      return retobj;
    }
  }

  std::vector<const char *> args;
  args.push_back("--verify");
  if (signature.size()) {
    args.push_back(sig_file.c_str());
  }
  args.push_back(signed_file.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  std::vector< std::vector<std::string> > parsed_output;
  ParseGpgOutput(ret_text, &parsed_output);

  if (ret) {
    LOG("GPG: Gnupg retval is %d, returning\n", ret);
    if (parsed_output.size() == 0) {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    } else if (parsed_output[0][0] == kGPG_BADSIG) {
      retobj.set_error_str(kERR_BAD_SIGNATURE);
    } else if (parsed_output[0][0] == kGPG_NODATA) {
      retobj.set_error_str(kERR_SIGNATURE_ERR);
    } else {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    }
    return retobj;
  }

  std::vector<std::string> expected;
  expected.push_back(kGPG_SIG_ID);
  expected.push_back(kGPG_GOODSIG);
  expected.push_back(kGPG_VALIDSIG);

  LOG("GPG: Checking output\n");
  if (!CheckForOrderedOutput(expected, parsed_output)) {
    retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
    return retobj;
  }

  LOG("GPG: Parsing signer\n");
  std::vector<std::string> line_parts;
  SplitOnSpaces(parsed_output[1][1], &line_parts);

  /* Everything after the first part is the signer. */
  std::string signer;
  for (size_t i = 1; i < line_parts.size(); i++) {
    if (i > 1) {
      signer += " ";
    }
    signer += line_parts[i];
  }

  retobj.set_signer(signer);
  retobj.set_trust_level(parsed_output[3][0]);
  retobj.set_debug(ret_text);

  return retobj;
}

/*
 * Encrypt rawtext to keyid.
 */
GpgRetEncryptInfo BaseGnupg::EncryptText(
    const std::string &rawtext,
    const std::vector<std::string> &keyids,
    const std::vector<std::string> &hidden_keyids,
    bool always_trust,
    const std::string &sign) {
  GpgRetEncryptInfo retobj;

  LOG("GPG: In EncryptText\n");

  LOG("GPG: Opening tmp file\n");
  std::string raw_file = kTMP_RAW_TEXT;
  TmpWrapper raw_wrapper;
  if (!raw_wrapper.CreateAndWriteTmpFile(rawtext, &raw_file)) {
    retobj.set_error_str(kERR_INTERNAL);
  }

  std::string res_filename;
  res_filename.append(raw_file);
  res_filename.append(".asc");
  /* Make sure gpg isn't going to write to an existing file */
  TmpWrapper res_wrapper;
  res_wrapper.UnlinkAndTrackFile(res_filename);

  std::vector<const char *> args;
  args.push_back("--encrypt");
  args.push_back("--armor");
  if (sign.size()) {
    args.push_back("--sign");
    args.push_back("--local-user");
    args.push_back(sign.c_str());
  }
  if (always_trust)
    args.push_back("--always-trust");
  for (size_t i = 0; i < keyids.size(); i++) {
    LOG("GPG: RECP: %s\n", keyids[i].c_str());
    args.push_back("--recipient");
    args.push_back(keyids[i].c_str());
  }
  for (size_t i = 0; i < hidden_keyids.size(); i++) {
    args.push_back("--hidden-recipient");
    LOG("GPG: HIDRECP: %s\n", hidden_keyids[i].c_str());
    args.push_back(hidden_keyids[i].c_str());
  }
  args.push_back(raw_file.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  std::vector< std::vector<std::string> > parsed_output;
  ParseGpgOutput(ret_text, &parsed_output);

  LOG("GPG: Removing tmpfile\n");

  retobj.set_debug(ret_text);

  LOG("GPG: Error checking gpg run\n");
  if (ret) {
    LOG("GPG: Gnupg retval is %d, returning\n", ret);
    int line = 0;
    if (sign.size())
      line = 3;
    if (parsed_output.size() == 0) {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    } else if (parsed_output[line][0] == kGPG_INV_RECP) {
      /*
       * If the key isn't trusted we get
       *   kGPG_INV_RECP kGPG_INV_NOT_TRUSTED
       * If the key is not found we'll get either
       *   kGPG_INV_RECP kGPG_INV_NOT_FOUND1
       * or:
       *   kGPG_INV_RECP kGPG_INV_NOT_FOUND2
       *
       * The second "word" is a number and is a code for
       * why the recipient is invalid. For any other code
       * we report a generic error as it's unexpected.
       */
      std::vector<std::string> line_parts;
      SplitOnSpaces(parsed_output[line][1], &line_parts);
      if (line_parts[0] == kGPG_INV_NOT_TRUSTED) {
        LOG("GPG: Key not trusted\n");
        retobj.set_error_str(kERR_PUBLIC_KEY_NOT_TRUSTED);
      } else if (line_parts[0] == kGPG_INV_NOT_FOUND1 ||
                 line_parts[0] == kGPG_INV_NOT_FOUND2) {
        LOG("GPG: Key not found\n");
        retobj.set_error_str(kERR_NO_PUBLIC_KEY);
      } else {
        LOG("GPG: Key bad\n");
        retobj.set_error_str(kERR_BAD_PUBLIC_KEY);
      }
    } else {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
      LOG("GPG: Unexpected GPG failure output: %s %s\n",
          parsed_output[0][0].c_str(),
          parsed_output[0][1].c_str());
    }
    return retobj;
  }

  if (parsed_output.size() == 0) {
    retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    return retobj;
  }

  LOG("GPG: Output checking gpg run\n");
  if (sign.size()) {
    LOG("GPG: Checking output for signing confirmation\n");
    if (parsed_output[4][0] != kGPG_SIG_CREATED) {
      retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
      LOG("GPG: Unexpected GPG output: %s %s\n", parsed_output[0][0].c_str(),
             parsed_output[0][1].c_str());
      return retobj;
    }
  }

  LOG("GPG: Checking output for encryption confirmation\n");
  if (parsed_output[parsed_output.size()-1][0] != kGPG_END_ENCRYPTION) {
      retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
      LOG("GPG: Unexpected GPG output: %s %s\n", parsed_output[0][0].c_str(),
             parsed_output[0][1].c_str());
      return retobj;
  }

  std::string data;
  if (!ReadFileToString(res_filename.c_str(), &data)) {
    retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    return retobj;
  }

  retobj.set_cipher_text(data);
  return retobj;
}

/*
 * Signs rawtext with keyid and returns the detached signature.
 */
GpgRetString BaseGnupg::SignText(const std::string &rawtext,
                                 const std::string &keyid,
                                 bool clearsign) {
  GpgRetString retobj;

  LOG("GPG: In SignText\n");

  LOG("GPG: Opening tmp files\n");
  std::string raw_file = kTMP_RAW_TEXT;
  TmpWrapper raw_wrapper;
  if (!raw_wrapper.CreateAndWriteTmpFile(rawtext, &raw_file)) {
    retobj.set_error_str(kERR_INTERNAL);
  }

  std::vector<const char *> args;
  args.push_back("--armor");
  if (clearsign)
    args.push_back("--clearsign");
  else
    args.push_back("--detach-sign");
  args.push_back("--local-user");
  args.push_back(keyid.c_str());
  args.push_back(raw_file.c_str());

  /* Prep the output file before calling gpg. */
  std::string res_file;
  res_file.append(raw_file.c_str());
  res_file.append(".asc");
  TmpWrapper res_wrapper;
  res_wrapper.UnlinkAndTrackFile(res_file);

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  if (ret) {
    /*
     * If the key we're supposed to use is not available, we'll get *NO*
     * output (bad form, gpg). So if we get output, that's some unknown
     * error.
     */
    if (!ret_text.size()) {
      LOG("GPG: Signing failed (%d) - no output\n", ret);
      retobj.set_error_str(kERR_NO_SECRET_KEY);
    } else {
      std::vector< std::vector<std::string> > parsed_output;
      ParseGpgOutput(ret_text, &parsed_output);
      if (CheckForSingleOutput(kGPG_BAD_PASSPHRASE, parsed_output)) {
        LOG("GPG: Bad passphrase or couldn't talk to agent\n");
        retobj.set_error_str(kERR_BAD_PASSPHRASE);
      } else {
        LOG("GPG: Signing failed (%d): \"%s\"\n", ret, ret_text.c_str());
        retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
      }
    }
    return retobj;
  }

  std::vector< std::vector<std::string> > parsed_output;
  ParseGpgOutput(ret_text, &parsed_output);

  std::vector<std::string> expected;
  expected.push_back(kGPG_USERID_HINT);
  expected.push_back(kGPG_NEED_PASSPHRASE);
  expected.push_back(kGPG_GOOD_PASSPHRASE);
  expected.push_back(kGPG_BEGIN_SIGNING);
  expected.push_back(kGPG_SIG_CREATED);

  if (!CheckForOrderedOutput(expected, parsed_output)) {
    LOG("GPG: CheckForOrderedOutput returned false\n");
    retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
    return retobj;
  }

  std::string data;
  LOG("GPG: Reading output files\n");
  if (!ReadFileToString(res_file.c_str(), &data)) {
    retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    return retobj;
  }

  retobj.set_retstring(data);

  return retobj;
}

/*
 * Given cipher text, decrypt it.
 *
 * If the ciphertext has a signature in it, we will verify it
 * and set the same entries in the return object that we would
 * in VerifySignedText()
 */
GpgRetDecryptInfo BaseGnupg::DecryptText(const std::string &cipher_text) {
  GpgRetDecryptInfo retobj;

  LOG("GPG: In DecryptText");

  LOG("GPG: Opening tmp files");

  std::string cipher_file = kTMP_RAW_TEXT;
  TmpWrapper cipher_wrapper;
  if (!cipher_wrapper.CreateAndWriteTmpFile(cipher_text, &cipher_file)) {
    retobj.set_error_str(kERR_INTERNAL);
  }

  std::string raw_file = cipher_file;
  raw_file.append(".plain");

  /* Make sure gpg doesn't write to an existing file. */
  TmpWrapper raw_wrapper;
  raw_wrapper.UnlinkAndTrackFile(raw_file);

  std::vector<const char *> args;
  args.push_back("--output");
  args.push_back(raw_file.c_str());
  args.push_back("--decrypt");
  args.push_back(cipher_file.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  std::vector< std::vector<std::string> > parsed_output;
  ParseGpgOutput(ret_text, &parsed_output);

  bool is_signed = false;
  if (CheckForSingleOutput(kGPG_SIG_ID, parsed_output)) {
    is_signed = true;
  }

  if (ret) {
    if (parsed_output.size() == 0) {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    } else if (CheckForSingleOutput(kGPG_DECRYPTION_FAILED, parsed_output)) {
      LOG(("GPG: Private key not available"));
      retobj.set_error_str(kERR_NO_SECRET_KEY);
    } else if (is_signed) {
      if (CheckForSingleOutput(kGPG_BADSIG, parsed_output)) {
        retobj.set_error_str(kERR_BAD_SIGNATURE);
      } else if (CheckForSingleOutput(kGPG_NODATA, parsed_output)) {
        retobj.set_error_str(kERR_SIGNATURE_ERR);
      }
    } else {
      LOG("GPG: Decryption failed for unknown reasons, is_signed: %d",
          is_signed);
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    }
    return retobj;
  }

  std::vector<std::string> expected;
  expected.push_back(kGPG_ENC_TO);
  expected.push_back(kGPG_USERID_HINT);
  expected.push_back(kGPG_PLAINTEXT);
  expected.push_back(kGPG_PLAINTEXT_LENGTH);
  expected.push_back(kGPG_DECRYPTION_OKAY);
  expected.push_back(kGPG_GOODMDC);
  expected.push_back(kGPG_END_DECRYPTION);

  if (!CheckForUnorderedOutput(expected, parsed_output)) {
    LOG(("GPG: CheckRequiredOutput failed for decyrption check"));
    retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
    return retobj;
  }

  if (is_signed) {
    expected.clear();
    expected.push_back(kGPG_GOODSIG);
    expected.push_back(kGPG_VALIDSIG);
    if (!CheckForUnorderedOutput(expected, parsed_output)) {
      LOG(("GPG: CheckRequiredOutput failed for signing check (in decrypt)"));
      retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
      return retobj;
    }

    std::vector<std::string> line_parts;
    SplitOnSpaces(parsed_output[8][1], &line_parts);

    /* Everything after the first part is the signer. */
    std::string signer = "";
    for (size_t i = 1; i < line_parts.size(); i++) {
      if (i > 1) {
        signer += " ";
      }
      signer += line_parts[i];
    }

    retobj.set_signer(signer);

    retobj.set_trust_level(parsed_output[10][0]);
  }

  retobj.set_debug(ret_text);

  std::string data;
  if (!ReadFileToString(raw_file.c_str(), &data)) {
    retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    return retobj;
  }

  retobj.set_data(data);
  return retobj;
}

/*
 * Fetch keyid (optionally from keyserver) onto the local keyring.
 */
GpgRetBool BaseGnupg::GetKey(const std::string &keyid,
                          const std::string &keyserver) {
  GpgRetBool retobj;

  LOG("GPG: In GetKey\n");

  std::vector<const char *> args;
  if (keyserver.size()) {
    args.push_back("--keyserver");
    args.push_back(keyserver.c_str());
  }
  args.push_back("--recv-key");
  args.push_back(keyid.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  std::vector< std::vector<std::string> > parsed_output;
  ParseGpgOutput(ret_text, &parsed_output);

  if (ret) {
    if (parsed_output.size() == 0) {
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    } else if (parsed_output[0][0] == kGPG_NODATA) {
      LOG("GPG: Key not found\n");
      retobj.set_error_str(kERR_NO_PUBLIC_KEY);
    } else {
      LOG("GPG: Unknown error in output");
      retobj.set_error_str(kERR_UNKNOWN_GPG_ERR);
    }
    return retobj;
  }

  if (parsed_output[0][0] == kGPG_IMPORT_OK) {
    LOG("GPG: Key already on keyring\n");
    retobj.set_error_str(kERR_ALREADY_HAVE_KEY);
  } else if (parsed_output[0][0] == kGPG_IMPORTED) {
    retobj.set_retbool(true);
  } else {
    retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
  }
  return retobj;
}

/*
 * Return an array of uids on keyid
 */
GpgRetUidsInfo BaseGnupg::GetUids(const std::string &keyid) {
  GpgRetUidsInfo retobj;

  LOG("GPG: In GetUids\n");

  std::vector<const char *> args;
  args.push_back("--with-colons");
  args.push_back("--fixed-list-mode");
  args.push_back("--fingerprint");
  args.push_back(keyid.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  /*
   * For --fingerprint, gpg will never output the "standard" output
   * however, if we fail here it's almost certainly because we don't
   * have the key.
   */
  if (ret) {
    retobj.set_error_str(kERR_NO_PUBLIC_KEY);
    return retobj;
  }

  LOG("GPG: Processing this: \"%s\"\n", ret_text.c_str());
  std::vector<std::string> lines;
  SplitOnChar(ret_text, '\n', &lines);
  for (size_t i = 0; i < lines.size(); i++) {
    std::vector<std::string> parts;
    SplitOnChar(lines[i], ':', &parts);
    if (parts[0] == "uid") {
      LOG("GPG: Got UID %s\n", parts[9].c_str());
      retobj.add_uid(parts[9]);
    } else {
      LOG("GPG: skipping non-uid line\n");
    }
  }

  for (size_t i = 0; i < retobj.uids().size(); i++) {
    LOG("GPG: DEBUG: UID: %s\n", retobj.uids()[i].c_str());
  }

  return retobj;
}

/*
 * For verification: returns the fingerprint of keyid
 */
GpgRetString BaseGnupg::GetFingerprint(const std::string &keyid) {
  GpgRetString retobj;

  LOG("GPG: In GetFingerprint\n");

  std::vector<const char *> args;
  args.push_back("--fingerprint");
  args.push_back(keyid.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  /*
   * for --fingerprint, gpg will never output the "standard" output
   * however, if we fail here it's almost certainly because we don't
   * have the key.
   */
  if (ret) {
    retobj.set_error_str(kERR_NO_PUBLIC_KEY);
    return retobj;
  }

  retobj.set_retstring(ret_text);

  return retobj;
}

/*
 * Returns the trust value of keyid
 */
GpgRetString BaseGnupg::GetTrust(const std::string &keyid) {
  GpgRetString retobj;

  LOG("GPG: In GetFingerprint\n");

  std::vector<const char *> args;
  args.push_back("--fixed-list-mode");
  args.push_back("--with-colons");
  args.push_back("--list-keys");
  args.push_back(keyid.c_str());

  int ret;
  std::string ret_text;
  if (!CallReadAndWaitOnGpg(args, &ret, &ret_text)) {
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  /*
   * for --list-keys, gpg will never output the "standard" output
   * however, if we fail here it's almost certainly because we don't
   * have the key.
   */
  if (ret) {
    retobj.set_error_str(kERR_NO_PUBLIC_KEY);
    return retobj;
  }

  LOG("GPG: Processing this: \"%s\"\n", ret_text.c_str());
  std::vector<std::string> lines;
  SplitOnChar(ret_text, '\n', &lines);
  for (size_t i = 0; i < lines.size(); i++) {
    std::vector<std::string> parts;
    SplitOnChar(lines[i], ':', &parts);
    if (parts[0] == "pub") {
      LOG("GPG: Got trust %s\n", parts[1].c_str());
      std::string trust;
      switch (parts[1].c_str()[0]) {
        case 'f': trust = "TRUST_FULL"; break;
        case 'u': trust = "TRUST_ULTIMATE"; break;
        case 'i': trust = "TRUST_INVALID"; break;
        case 'r': trust = "TRUST_REVOKED"; break;
        case 'e': trust = "TRUST_EXPIRED"; break;
        case '-':
        case 'q': trust = "TRUST_UNKNOWN"; break;
        case 'n': trust = "TRUST_UNTRUSTED"; break;
        case 'm': trust = "TRUST_MARGINAL"; break;
      }
      retobj.set_retstring(trust);
      break;
    } else {
      LOG("GPG: skipping non-pub line\n");
    }
  }

  return retobj;
}

/*
 * This will sign uid <uid> on key <keyid> at level <level>.
 * It uses the --edit-key functionality for interactive conversation
 * with gpg.
 */
GpgRetBool BaseGnupg::SignUid(const std::string &keyid, const std::string &uid,
                           const std::string &level) {
  GpgRetBool retobj;
  /*
   * We use a goto below, which means all initialization has to be up-top.
   */
  std::string line;
  std::vector<std::string> parsed_line;

  LOG("GPG: In SignUid\n");

  std::vector<const char *>args;
  args.push_back("--default-cert-level");
  args.push_back(level.c_str());
  args.push_back("--edit-key");
  args.push_back(keyid.c_str());

  PRProcess *process = CallGpg(args);

  if (process == NULL) {
    LOG("GPG: Failed to execute\n");
    retobj.set_error_str(kERR_INTERNAL);
    return retobj;
  }

  if (!ExpectString(kGPG_PROMPT)) {
    goto unexpected;
  }

  /*
   * FIXME: Why doesn't writing with streams work?
   */
  LOG("GPG: Choosing uid %s\n", uid.c_str());
  *outstream_ << uid << std::endl;

  if (!ExpectString(kGPG_ACK)) {
    goto unexpected;
  }
  if (!ExpectString(kGPG_PROMPT)) {
    goto unexpected;
  }

  LOG("GPG: Issueing sign command\n");
  *outstream_ << "sign" << std::endl;

  if (!ExpectString(kGPG_ACK)) {
    goto unexpected;
  }

  if (!std::getline(*instream_, line)) {
    goto unexpected;
  }
  if (!ParseGpgLine(line, &parsed_line)) {
    goto unexpected;
  }

  if (parsed_line[0] == kGPG_ALREADY_SIGNED) {
    retobj.set_error_str(kERR_ALREADY_SIGNED);
    *outstream_ << "exit" << std::endl;
    WaitOnGpg(process);
    return retobj;
  } else if (parsed_line[0] != kGPG_CONFIRM) {
    LOG("GPG: Expected %s, got %s\n", kGPG_CONFIRM, parsed_line[0].c_str());
    goto unexpected;
  }

  LOG("GPG: Confirming sign\n");
  *outstream_ << "Y" << std::endl;

  if (!ExpectString(kGPG_ACK)) {
    goto unexpected;
  }
  if (!ExpectString(kGPG_USERID_HINT)) {
    goto unexpected;
  }
  if (!ExpectString(kGPG_NEED_PASSPHRASE)) {
    goto unexpected;
  }

  /*
   * NOTE:
   * In the current version of gpg/gpg-agent, the agent will prompt
   * 3 times *BUT* will return "BAD_PASSPHRASE" after the first one.
   *
   * To make matters worse, if a good passphrase is specified, no further
   * feedback is given, so all we can do is report back to the user it
   * didn't work.
   *
   * This is made slightly better , since once the agent has the right
   * passphrase, it won't prompt on the next try it'll "just work"
   *
   * If they fix this in the future, we'll loop on this until
   * we get an exit condition.
   */
  if (!std::getline(*instream_, line)) {
    goto unexpected;
  }
  parsed_line.clear();
  if (!ParseGpgLine(line, &parsed_line)) {
    goto unexpected;
  }
  if (parsed_line[0] == kGPG_BAD_PASSPHRASE) {
    retobj.set_error_str(kERR_BAD_PASSPHRASE);
    *outstream_ << "exit" << std::endl;
    WaitOnGpg(process);
    return retobj;
  } else if (parsed_line[0] != kGPG_GOOD_PASSPHRASE) {
    LOG("GPG: Expected %s, got %s\n", kGPG_GOOD_PASSPHRASE,
        parsed_line[0].c_str());
    goto unexpected;
  }

  if (!ExpectString(kGPG_PROMPT)) {
    goto unexpected;
  }

  LOG("GPG: Saving key");
  *outstream_ << "save" << std::endl;

  WaitOnGpg(process);

  /* No need to check return values here, GPG gave us feedback the whole way */
  retobj.set_retbool(true);
  return retobj;

 unexpected:
    retobj.set_error_str(kERR_UNEXPECTED_GPG_OUTPUT);
    PR_KillProcess(process);
    WaitOnGpg(process);
    return retobj;
}

GpgRetBool BaseGnupg::SetConfigValue(const std::string &key,
                                     const std::string &value) {
  GpgRetBool retobj;

  retobj.set_retbool(preferences_.SetDirective(key, value));

  return retobj;
}

namespace glue {
namespace class_Gnupg {
bool IsTrustedOrigin(void *pdata) {
  globals::NPAPIObject *static_object;
  NPIdentifier identifier;
  NPObject *window;
  NPP npp = NULL;
  NPVariant window_location, window_location_href;
  std::vector<std::string> trusted_origins;
  std::string origin;
  bool rv = false;

  /*
   * This origin is for Firefox (ex: chrome://content/browser/overlay.xul).
   */
  trusted_origins.push_back("chrome://");
  /*
   * This origin can be more specific if we can predict the ID that Chrome
   * will create for our bundle (ex:
   * chrome-extension://lkkgggklgcdplphoncoaolblnimcjfnj/background.html).
   */
  trusted_origins.push_back("chrome-extension://");

  static_object = static_cast<globals::NPAPIObject*>(pdata);
  if(!static_object || !(npp = static_object->npp()))
    return rv;

  identifier = NPN_GetStringIdentifier("location");
  if (NPN_GetValue(npp, NPNVWindowNPObject, &window) == NPERR_NO_ERROR
      && window != NULL) {
    if (NPN_GetProperty(npp, window, identifier, &window_location)) {
      identifier = NPN_GetStringIdentifier("href");
      if (NPN_GetProperty(npp, window_location.value.objectValue,
                          identifier, &window_location_href)) {
        if (NPVARIANT_IS_STRING(window_location_href)) {
          const NPUTF8 *origin =
              NPVARIANT_TO_STRING(window_location_href).UTF8Characters;
          size_t origin_length = strlen(origin);
          /*
           * This block iterates over all trusted_origins and attempts to match
           * the scheme of the origin the plugin resides in (origin is a value
           * such as 'http://example.com/foo.html', scheme is 'http://') with
           * the scheme defined in trusted_origin (e.g. chrome://).  If a match
           * is found, the origin is considered trusted and can set
           * configuration values.
           */
          for (std::vector<std::string>::const_iterator it =
              trusted_origins.begin(); it != trusted_origins.end(); ++it) {
            if (origin_length < it->length())
              continue;
            if (it->compare(0, it->length(), origin, it->length()) == 0) {
              rv = true;
              break;
            }
          }
          if (rv == false)
            LOG("GPG: origin validation failed for %s\n", origin);
        }
        NPN_ReleaseVariantValue(&window_location_href);
      }
      NPN_ReleaseVariantValue(&window_location);
    }
    NPN_ReleaseObject(window);
  }
  return rv;
}

GpgRetBool userglue_method_SetConfigValue(void *pdata, Gnupg *object,
                                          const std::string &param_key,
                                          const std::string &param_val) {
  GpgRetBool retobj;

  retobj.set_retbool(false);

  if (object && IsTrustedOrigin(pdata)) {
    LOG("GPG: setting configuration directive '%s' to '%s'\n",
        param_key.c_str(), param_val.c_str());
    retobj.set_retbool(object->SetConfigValue(param_key,
                                              param_val).retbool());
  }

  return retobj;
}
} /* namespace class_Gnupg */
} /* namespace glue */
