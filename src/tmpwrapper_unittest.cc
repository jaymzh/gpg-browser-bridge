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

#include "tmpwrapper.h"

#include <gtest/gtest.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef OS_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif

#include <cerrno>

#if !defined(S_IRUSR) && !defined(S_IWUSR)
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#endif

namespace {

/*
 * Make sure that temp files go away when created by
 * the wrapper class.
 */

/* This fails on Windows. TODO(roubert): Fix. */
TEST(TmpWrapperTestCreateAndWriteTmpFile, DoesRemove) {
  std::string pattern = "/tmp/test_XXXXXX";
  TmpWrapper *tmp = new TmpWrapper;
  tmp->CreateAndWriteTmpFile("Bla", &pattern);
  struct stat statbuf;
  EXPECT_EQ(0, stat(pattern.c_str(), &statbuf));
  delete tmp;
  int ret = stat(pattern.c_str(), &statbuf);
  EXPECT_EQ(-1, ret);
  EXPECT_EQ(ENOENT, errno);
}

#ifndef OS_WINDOWS /* These crash on Windows. TODO(roubert): Fix. */
/*
 * Make sure the temp files go away when created outside
 * the wrapper class.
 */
TEST(TmpWrapperTestUnlinkAndTrackFile, DoesRemoveWithNonexistingFile) {
  /* Get filename */
  std::string pattern = "/tmp/test_XXXXXX";
  char *filename = strdup(pattern.c_str());
  mktemp(filename);

  /* track file */
  TmpWrapper *tmp = new TmpWrapper;
  tmp->UnlinkAndTrackFile(filename);

  /* create file */
  int fd = open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
  EXPECT_NE(0, fd);
  FILE *fs = fdopen(fd, "w");
  EXPECT_TRUE(fs);
  int ret = fputs("Bla", fs);
  EXPECT_EQ(1, ret);
  fclose(fs);

  /* test it exists */
  struct stat statbuf;
  EXPECT_EQ(0, stat(filename, &statbuf));

  /* and test it goes away */
  delete tmp;
  ret = stat(filename, &statbuf);
  EXPECT_EQ(-1, ret);
  EXPECT_EQ(ENOENT, errno);
  free(filename);
}

/*
 * Make sure the temp files go away when created outside
 * the wrapper class.
 */
TEST(TmpWrapperTestUnlinkAndTrackFile, DoesRemoveWithExistingFile) {
  /* Get filename */
  std::string pattern = "/tmp/test_XXXXXX";
  char *filename = strdup(pattern.c_str());
  mktemp(filename);

  /* create file */
  int fd = open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
  EXPECT_NE(0, fd);
  FILE *fs = fdopen(fd, "w");
  EXPECT_TRUE(fs);
  int ret = fputs("Bla", fs);
  EXPECT_EQ(1, ret);
  fclose(fs);

  /* track file - it should get removed */
  TmpWrapper *tmp = new TmpWrapper;
  tmp->UnlinkAndTrackFile(filename);

  /* Make sure the call removed it. */
  struct stat statbuf;
  EXPECT_EQ(-1, stat(filename, &statbuf));

  /* create file */
  fd = open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
  EXPECT_NE(0, fd);
  fs = fdopen(fd, "w");
  EXPECT_TRUE(fs);
  ret = fputs("Bla", fs);
  EXPECT_EQ(1, ret);
  fclose(fs);

  /* test it exists */
  EXPECT_EQ(0, stat(filename, &statbuf));

  /* and test it goes away */
  delete tmp;
  ret = stat(filename, &statbuf);
  EXPECT_EQ(-1, ret);
  EXPECT_EQ(ENOENT, errno);
  free(filename);
}
#endif

} /* namespace */
