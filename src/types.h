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

#ifndef _GPGPLUGIN_TYPES_H_
#define _GPGPLUGIN_TYPES_H_

/*
 * These classes are essentially Javascript objects. Nixysa wraps these
 * and provides access to them from JS. This allows us to return complex
 * objects.
 */

class GpgRetBase {
 public:
  GpgRetBase()
      : is_error_(false) {
  }

  virtual ~GpgRetBase() {}

  bool is_error() const {
    return is_error_;
  }

  const std::string& error_str() const {
    return error_str_;
  }

  void set_error_str(const std::string& error_str) {
    is_error_ = true;
    error_str_ = error_str;
  }

 private:
  bool is_error_;
  std::string error_str_;
};


class GpgRetString : public GpgRetBase {
 public:
  const std::string& retstring() const {
    return retstring_;
  }

  void set_retstring(const std::string& retstring) {
    retstring_ = retstring;
  }

 private:
  std::string retstring_;
};


class GpgRetBool : public GpgRetBase {
 public:
  GpgRetBool()
      : retbool_(false) {
  }

  bool retbool() const {
    return retbool_;
  }

  void set_retbool(bool retbool) {
    retbool_ = retbool;
  }

 private:
  bool retbool_;
};


class GpgRetSignerInfo : public GpgRetBase {
 public:
  const std::string& signer() const {
    return signer_;
  }

  void set_signer(const std::string& signer) {
    signer_ = signer;
  }

  const std::string& trust_level() const {
    return trust_level_;
  }

  void set_trust_level(const std::string& trust_level) {
    trust_level_ = trust_level;
  }

  const std::string& debug() const {
    return debug_;
  }

  void set_debug(const std::string& debug) {
    debug_ = debug;
  }

 private:
  std::string signer_, trust_level_, debug_;
};


class GpgRetEncryptInfo : public GpgRetBase {
 public:
  const std::string& cipher_text() const {
    return cipher_text_;
  }

  void set_cipher_text(const std::string& cipher_text) {
    cipher_text_ = cipher_text;
  }

  const std::string& debug() const {
    return debug_;
  }

  void set_debug(const std::string& debug) {
    debug_ = debug;
  }

 private:
  std::string cipher_text_, debug_;
};


class GpgRetDecryptInfo : public GpgRetSignerInfo {
 public:
  const std::string& data() const {
    return data_;
  }

  void set_data(const std::string& data) {
    data_ = data;
  }

 private:
  std::string data_;
};


class GpgRetUidsInfo : public GpgRetBase {
 public:
  const std::vector<std::string>& uids() const {
    return uids_;
  }

  void add_uid(const std::string& uid) {
    uids_.push_back(uid);
  }

 private:
  std::vector<std::string> uids_;
};

#endif  // _GPGPLUGIN_TYPES_H_
