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

#include "gnupg.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <npapi.h>
#include <npruntime.h>

#include "static_object.h"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgumentPointee;
using ::testing::ElementsAre;
using ::testing::StrEq;


namespace {

static const std::string kTEST_STRING = "this is test stuff\n";
static PRProcess *const kFAKE_PROCESS = reinterpret_cast<PRProcess *>(0xdead);

static const std::string kFIREFOX_ORIGIN =
    "chrome://browser/content/browser.xul";
static const std::string kCHROME_ORIGIN =
    "chrome-extension://abcdefghijklmnopqrstuvwxyz";
static const std::string kSAFARI_ORIGIN =
    "safari-extension://com.google.gpg-0123456789ABC";
static const std::string kINVALID_ORIGIN = "http://www.example.com";
static void *kFIREFOX_TEST = reinterpret_cast<void *>(0x1);
static void *kCHROME_TEST = reinterpret_cast<void *>(0x2);
static void *kSAFARI_TEST = reinterpret_cast<void *>(0x3);
static void *kINVALID_TEST = reinterpret_cast<void *>(0x4);
static const NPIdentifier kLOCATION = reinterpret_cast<NPIdentifier>(0x1);
static const NPIdentifier kHREF = reinterpret_cast<NPIdentifier>(0x2);
static const NPIdentifier kUNKNOWN_IDENTIFIER =
    reinterpret_cast<NPIdentifier>(0x3);

class MockGnupg : public BaseGnupg {
 public:
  MOCK_METHOD1(CallGpg, PRProcess *(const std::vector<const char*> &args));
  MOCK_METHOD1(ReadAllGpgOutput, bool(std::string *output));
  MOCK_METHOD1(WaitOnGpg, int(PRProcess *process));
  MOCK_METHOD2(ReadFileToString, bool(const char *filename, std::string *text));
};

/*
 * This exercizes ParseGpgLine() and ParseGpgOutput()
 */
TEST(GnupgTestParseGpgOutput, DoesParse) {
  /* This test verifies that Gnupg does job Foo. */
  std::string output;
  output = "[GNUPG:] FOO Bar baz\n[GNUPG:] WONK wink bink\n";
  std::vector< std::vector<std::string> > parsed;
  Gnupg gpg;
  gpg.ParseGpgOutput(output, &parsed);
  EXPECT_EQ("FOO", parsed[0][0]);
}

/*
 * The next few functions exercize the CheckOutput* functions.
 */
TEST(GnupgTestCheckOuput, HasSeries) {
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line, expected;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);
  line.clear();
  line.push_back("SER3");
  output.push_back(line);

  expected.push_back("SER1");
  expected.push_back("SER2");
  expected.push_back("SER3");

  Gnupg gpg;
  EXPECT_TRUE(gpg.CheckForOrderedOutput(expected, output));
}

TEST(GnuTestCheckOutput, DoesNotHaveSeries) {
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line, expected;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);
  line.clear();
  line.push_back("SER3");
  output.push_back(line);

  expected.push_back("SER1");
  expected.push_back("SER3");
  expected.push_back("SER2");

  Gnupg gpg;
  EXPECT_FALSE(gpg.CheckForOrderedOutput(expected, output));
}

TEST(GnupgTestCheckOuput, CheckHasVariousOutputs) {
  /* This is the same setup as above - except in this case, it should pass. */
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line, expected;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);
  line.clear();
  line.push_back("SER3");
  output.push_back(line);

  expected.push_back("SER1");
  expected.push_back("SER3");
  expected.push_back("SER2");

  Gnupg gpg;
  EXPECT_TRUE(gpg.CheckForUnorderedOutput(expected, output));
}

TEST(GnupgTestCheckOuput, CheckDoesNotHaveVariousOutputs) {
  /* This is the same setup as above - except in this case, it should pass. */
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line, expected;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);

  expected.push_back("SER1");
  expected.push_back("SER3");
  expected.push_back("SER2");

  Gnupg gpg;
  EXPECT_FALSE(gpg.CheckForUnorderedOutput(expected, output));
}

TEST(GnupgTestCheckOutput, CheckHasSingleOutput) {
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);

  Gnupg gpg;
  EXPECT_TRUE(gpg.CheckForSingleOutput("SER2", output));
}

TEST(GnupgTestCheckOutput, CheckDoesNotHaveSingleOutput) {
  std::vector< std::vector<std::string> > output;
  std::vector<std::string> line;
  line.push_back("SER1");
  line.push_back("details");
  output.push_back(line);
  line.clear();
  line.push_back("SER2");
  line.push_back("more details");
  output.push_back(line);

  Gnupg gpg;
  EXPECT_FALSE(gpg.CheckForSingleOutput("SER3", output));
}

/*
 * Here we start testing the top-level API functions
 *
 * For the rest of the tests, here's what you have to know:
 *
 *   * We use MockGnupg to simulate calls to gpg so that
 *     actual gpg and actual keychains are not required
 *     for tests.
 *   * We mock ReadAllGpgOutput to inject the specific response
 *     from gpg that we want to test.
 *
 *  With these we can test our code without having to test gpg or have
 *  it setup.
 */

/*
 * This first test is much simpler than the test and is mostly intended
 * to ensure that CallGpg is called correctly.
 */
TEST(GnupgGetGnupgVersion, CheckCallsVersion) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  std::vector<const char *> args;
  args.push_back("--version");
  /*
   * Oddly Contains(StrEq("--version")) doesn't work, but
   * ElementsAre(StrEq("--version")) does... weird.
   *
   * Apparently Contains() isn't actually here until the next release.
   */
  EXPECT_CALL(gpg, CallGpg(ElementsAre(StrEq("--version"))))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(Return(true));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS));
  gpg.GetGnupgVersion();
}

/*
 * For the rest of the tests we setup the data that gpg will return (or
 * bad versions of it), and set the Mocks to return it, and then validate
 * our code behaves as expected.
 */

TEST(GnupgVerifySignedText, VerifiesValidSig) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  std::string ret =
      "[GNUPG:] SIG_ID zfbsbRvH9ylP1xK1wApNqj56WR8 2009-07-16 1247743312\n"
      "[GNUPG:] GOODSIG 2C157CF124CB0839 Phil Dibowitz"
      " <fixxxer@google.com>\n"
      "[GNUPG:] VALIDSIG 792836377D99F13F68B4D49B2C157CF124CB0839"
      " 2009-07-16 1247743312 0 3 0 17 2 00"
      " 792836377D99F13F68B4D49B2C157CF124CB0839\n"
      "[GNUPG:] TRUST_ULTIMATE\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(0));
  GpgRetSignerInfo si = gpg.VerifySignedText("", "");
  EXPECT_EQ("Phil Dibowitz <fixxxer@google.com>", si.signer());
  EXPECT_EQ("TRUST_ULTIMATE", si.trust_level());
}

TEST(GnupgVerifySignedText, DoesNotVerifyInvalidSig) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  std::string ret =
     "[GNUPG:] BADSIG 2C157CF124CB0839 Phil Dibowitz <fixxxer@google.com>\n";
  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(2));
  GpgRetSignerInfo si = gpg.VerifySignedText("", "");
  EXPECT_TRUE(si.is_error());
  EXPECT_EQ("Bad signature", si.error_str());
}

TEST(GnupgEncryptText, EncryptsToValidKey) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  std::vector<std::string> keyids, hidden_keyids;

  std::string ret = "[GNUPG:] BEGIN_ENCRYPTION 2 9\n"
      "[GNUPG:] END_ENCRYPTION\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, ReadFileToString(_, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kTEST_STRING), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(0));
  GpgRetEncryptInfo ei =
      gpg.EncryptText("", keyids, hidden_keyids, false, "");
  EXPECT_EQ(kTEST_STRING, ei.cipher_text());
}

TEST(GnupgEncryptText, ErrorsOnBadKey) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  std::vector<std::string> keyids, hidden_keyids;

  std::string ret = "[GNUPG:] INV_RECP 0 3592D514\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(2));
  GpgRetEncryptInfo ei =
      gpg.EncryptText("", keyids, hidden_keyids, false, "");
  EXPECT_TRUE(ei.is_error());
  EXPECT_EQ("Public key not available", ei.error_str());
}

/*
 * Since we mock gpg, and since the output for clear and detached
 * signing is the same, the test cases are identical - there's no need for both.
 */

TEST(GnupgSignText, DetachSigns) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  bool clearsign = false;

  std::string ret = "[GNUPG:] USERID_HINT 2C157CF124CB0839 Phil Dibowitz"
      " <fixxxer@google.com>\n"
      "[GNUPG:] NEED_PASSPHRASE 2C157CF124CB0839 2C157CF124CB0839 17 0\n"
      "[GNUPG:] GOOD_PASSPHRASE\n"
      "[GNUPG:] BEGIN_SIGNING\n"
      "[GNUPG:] SIG_CREATED D 17 2 00 1251728234"
      " 792836377D99F13F68B4D49B2C157CF124CB0839\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, ReadFileToString(_, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kTEST_STRING), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(0));
  GpgRetString rs = gpg.SignText("", "", clearsign);
  EXPECT_FALSE(rs.is_error());
  EXPECT_EQ(kTEST_STRING, rs.retstring());
}

TEST(GnupgSignText, ClearSigns) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  bool clearsign = true;

  std::string ret = "[GNUPG:] USERID_HINT 2C157CF124CB0839 Phil Dibowitz"
      " <fixxxer@google.com>\n"
      "[GNUPG:] NEED_PASSPHRASE 2C157CF124CB0839 2C157CF124CB0839 17 0\n"
      "[GNUPG:] GOOD_PASSPHRASE\n"
      "[GNUPG:] BEGIN_SIGNING\n"
      "[GNUPG:] SIG_CREATED D 17 2 00 1251728234"
      " 792836377D99F13F68B4D49B2C157CF124CB0839\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, ReadFileToString(_, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kTEST_STRING), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(0));

  GpgRetString rs = gpg.SignText("", "", clearsign);
  EXPECT_EQ(kTEST_STRING, rs.retstring());
}

TEST(GnupgSignText, FailsToSign) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");
  bool clearsign = true;

  std::string ret = "[GNUPG:] USERID_HINT 2C157CF124CB0839 Phil Dibowitz"
      " <fixxxer@google.com>\n"
      "[GNUPG:] NEED_PASSPHRASE 2C157CF124CB0839 2C157CF124CB0839 17 0\n"
      "[GNUPG:] MISSING_PASSPHRASE\n"
      "[GNUPG:] BAD_PASSPHRASE 2C157CF124CB0839";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  /* Code won't call ReadFileToString due to error code of 2 from gpg */
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(2));

  GpgRetString rs = gpg.SignText("", "", clearsign);
  EXPECT_TRUE(rs.is_error());
}

TEST(GnupgDecryptText, DecryptsText) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");

  std::string ret = "[GNUPG:] ENC_TO D7974AEBC4DC6340 16 0\n"
      "[GNUPG:] USERID_HINT D7974AEBC4DC6340 Phil Dibowitz"
      "<fixxxer@google.com>\n"
      "[GNUPG:] NEED_PASSPHRASE D7974AEBC4DC6340 2C157CF124CB0839 16 0\n"
      "[GNUPG:] GOOD_PASSPHRASE\n"
      "[GNUPG:] BEGIN_DECRYPTION\n"
      "[GNUPG:] PLAINTEXT 62 1253809952 test\n"
      "[GNUPG:] PLAINTEXT_LENGTH 4\n"
      "[GNUPG:] DECRYPTION_OKAY\n"
      "[GNUPG:] GOODMDC\n"
      "[GNUPG:] END_DECRYPTION\n";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  EXPECT_CALL(gpg, ReadFileToString(_, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kTEST_STRING), Return(true)));
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(0));

  GpgRetDecryptInfo rd = gpg.DecryptText("");
  EXPECT_EQ(kTEST_STRING, rd.data());
}

TEST(GnupgDecryptText, FailsToDecrypt) {
  MockGnupg gpg;
  gpg.SetConfigValue("gpg_plugin_initialized", "true");

  std::string ret = "[GNUPG:] ENC_TO D7974AEBC4DC6340 16 0\n"
      "[GNUPG:] USERID_HINT 2C157CF124CB0839 Phil Dibowitz"
      " <fixxxer@google.com>\n"
      "[GNUPG:] NEED_PASSPHRASE 2C157CF124CB0839 2C157CF124CB0839 17 0\n"
      "[GNUPG:] MISSING_PASSPHRASE\n"
      "[GNUPG:] BAD_PASSPHRASE 2C157CF124CB0839";

  EXPECT_CALL(gpg, CallGpg(_))
      .WillOnce(Return(kFAKE_PROCESS));
  EXPECT_CALL(gpg, ReadAllGpgOutput(_))
      .WillOnce(DoAll(SetArgumentPointee<0>(ret), Return(true)));
  /* Won't call ReadFileToString() with retval from gpg as 2 */
  EXPECT_CALL(gpg, WaitOnGpg(kFAKE_PROCESS))
      .WillOnce(Return(2));

  GpgRetDecryptInfo rd = gpg.DecryptText("");
  EXPECT_TRUE(rd.is_error());
}

TEST(GnupgOriginDetection, TrustsSafeOrigins) {
  NPP npp = new NPP_t;
  glue::globals::NPAPIObject *object;

  /* Test Firefox */
  npp->pdata = kFIREFOX_TEST;
  object = new glue::globals::NPAPIObject(npp);
  EXPECT_TRUE(glue::class_Gnupg::IsTrustedOrigin(
      reinterpret_cast<void *>(object)));
  delete object;

  /* Test Chrome */
  npp->pdata = kCHROME_TEST;
  object = new glue::globals::NPAPIObject(npp);
  EXPECT_TRUE(glue::class_Gnupg::IsTrustedOrigin(
      reinterpret_cast<void *>(object)));
  delete object;

  /* Test Safari */
  npp->pdata = kSAFARI_TEST;
  object = new glue::globals::NPAPIObject(npp);
  EXPECT_TRUE(glue::class_Gnupg::IsTrustedOrigin(
      reinterpret_cast<void *>(object)));
  delete object;

  /* Test Invalid */
  npp->pdata = kINVALID_TEST;
  object = new glue::globals::NPAPIObject(npp);
  EXPECT_FALSE(glue::class_Gnupg::IsTrustedOrigin(
      reinterpret_cast<void *>(object)));
  delete object;

  delete npp;
}
} /* namespace */


/*
 * NPN_xxx helper functions which are ordinarily provided by the browser.
 * These lightweight implementations are needed to test the glue code that
 * nixysa generates to proxy calls to SetConfigValue().
 */

NPIdentifier NPN_GetStringIdentifier(const NPUTF8 *name) {
  std::string location = "location";
  std::string href = "href";

  if (location.compare(name) == 0)
    return kLOCATION;
  else if (href.compare(name) == 0)
    return kHREF;
  else  // This case should never happen.
    return kUNKNOWN_IDENTIFIER;
}

NPError NPN_GetValue(NPP /*instance*/, NPNVariable variable, void *value) {
  if (variable == NPNVWindowNPObject) {
    value = reinterpret_cast<void *>(0xdead);
    return NPERR_NO_ERROR;
  } else {
    value = NULL;
    return NPERR_GENERIC_ERROR;
  }
}

bool NPN_GetProperty(NPP npp, NPObject* /*npobj*/, NPIdentifier propertyname,
                NPVariant *result) {
  // The fixed NPIdentifier values are 0x1 for location and 0x2 for href.
  if (propertyname == kLOCATION) {
    return true;
  } else if (propertyname == kHREF) {
    // Return a safe origin, e.g. chrome-extension://..."
    const char *origin;
    if (npp->pdata == kFIREFOX_TEST)
      origin = kFIREFOX_ORIGIN.c_str();
    else if (npp->pdata == kCHROME_TEST)
      origin = kCHROME_ORIGIN.c_str();
    else if (npp->pdata == kSAFARI_TEST)
      origin = kSAFARI_ORIGIN.c_str();
    else
      origin = kINVALID_ORIGIN.c_str();

    result->type = NPVariantType_String;
    result->value.stringValue.UTF8Characters = strdup(origin);
    result->value.stringValue.UTF8Length = strlen(origin);
    return true;
  }
  ADD_FAILURE();
  return false;
}

void NPN_ReleaseVariantValue(NPVariant *variant) {
  if (variant && variant->type == NPVariantType_String)
    free(reinterpret_cast<void *>(
        const_cast<char *>(variant->value.stringValue.UTF8Characters)));
  return;
}

void NPN_ReleaseObject(NPObject* /*npobj*/) {
  return;
}


NPObject *NPN_RetainObject(NPObject *npobj) {
  return npobj;
}

void *NPN_MemAlloc(uint32_t size) {
  return malloc(size);
}

/* End NPN_xxx helper functions. */


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
