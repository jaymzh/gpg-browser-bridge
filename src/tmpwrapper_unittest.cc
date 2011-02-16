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
 *
 * ***** END LICENSE BLOCK *****
 */

#include <gtest/gtest.h>
#include <prerror.h>
#include <prio.h>

#include <string>

#include "tmpwrapper.h"

namespace {

/*
 * Make sure that temp files go away when created by
 * the wrapper class.
 */

TEST(TmpWrapperTestCreateAndWriteTmpFile, DoesRemove) {
  std::string pattern = "gpgut";
  TmpWrapper *tmp = new TmpWrapper;
  tmp->CreateAndWriteTmpFile("Bla", &pattern);

  /* test it exists */
  PRFileInfo info;
  EXPECT_EQ(PR_SUCCESS, PR_GetFileInfo(pattern.c_str(), &info));

  /* and test it goes away */
  delete tmp;
  EXPECT_EQ(PR_FAILURE, PR_GetFileInfo(pattern.c_str(), &info));
  EXPECT_EQ(PR_FILE_NOT_FOUND_ERROR, PR_GetError());
}

/*
 * Make sure the temp files go away when created outside
 * the wrapper class.
 */
TEST(TmpWrapperTestUnlinkAndTrackFile, DoesRemoveWithNonexistingFile) {
  static const char data[] = "Bla";

  /* Get filename */
  std::string filename = TmpWrapper::MkTmpFileName("gpgut");
  ASSERT_FALSE(filename.empty());

  /* track file */
  TmpWrapper *tmp = new TmpWrapper;
  tmp->UnlinkAndTrackFile(filename.c_str());

  /* create file */
  PRFileDesc *fd =
      PR_Open(filename.c_str(), TmpWrapper::kFLAGS, TmpWrapper::kMODE);
  ASSERT_TRUE(fd != NULL);
  EXPECT_NE(-1, PR_Write(fd, data, sizeof data - 1));
  EXPECT_EQ(PR_SUCCESS, PR_Close(fd));

  /* test it exists */
  PRFileInfo info;
  EXPECT_EQ(PR_SUCCESS, PR_GetFileInfo(filename.c_str(), &info));

  /* and test it goes away */
  delete tmp;
  EXPECT_EQ(PR_FAILURE, PR_GetFileInfo(filename.c_str(), &info));
  EXPECT_EQ(PR_FILE_NOT_FOUND_ERROR, PR_GetError());
}

/*
 * Make sure the temp files go away when created outside
 * the wrapper class.
 */
TEST(TmpWrapperTestUnlinkAndTrackFile, DoesRemoveWithExistingFile) {
  static const char data[] = "Bla";

  /* Get filename */
  std::string filename = TmpWrapper::MkTmpFileName("gpgut");
  ASSERT_FALSE(filename.empty());

  /* create file */
  PRFileDesc *fd =
      PR_Open(filename.c_str(), TmpWrapper::kFLAGS, TmpWrapper::kMODE);
  ASSERT_TRUE(fd != NULL);
  EXPECT_NE(-1, PR_Write(fd, data, sizeof data - 1));
  EXPECT_EQ(PR_SUCCESS, PR_Close(fd));

  /* track file - it should get removed */
  TmpWrapper *tmp = new TmpWrapper;
  tmp->UnlinkAndTrackFile(filename.c_str());

  /* Make sure the call removed it. */
  PRFileInfo info;
  EXPECT_EQ(PR_FAILURE, PR_GetFileInfo(filename.c_str(), &info));
  EXPECT_EQ(PR_FILE_NOT_FOUND_ERROR, PR_GetError());

  /* create file */
  fd = PR_Open(filename.c_str(), TmpWrapper::kFLAGS, TmpWrapper::kMODE);
  ASSERT_TRUE(fd != NULL);
  EXPECT_NE(-1, PR_Write(fd, data, sizeof data - 1));
  EXPECT_EQ(PR_SUCCESS, PR_Close(fd));

  /* test it exists */
  EXPECT_EQ(PR_SUCCESS, PR_GetFileInfo(filename.c_str(), &info));

  /* and test it goes away */
  delete tmp;
  EXPECT_EQ(PR_FAILURE, PR_GetFileInfo(filename.c_str(), &info));
  EXPECT_EQ(PR_FILE_NOT_FOUND_ERROR, PR_GetError());
}

} /* namespace */
