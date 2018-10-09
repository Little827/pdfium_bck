// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_widetextbuf.h"

void CFX_WideTextBuf::AppendChar(wchar_t ch) {
  stream_ << ch;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(const WideStringView& str) {
  stream_ << str;
  return *this;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(const WideString& str) {
  stream_ << str;
  return *this;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(int i) {
  stream_ << i;
  return *this;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(double f) {
  stream_ << f;
  return *this;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(const wchar_t* lpsz) {
  stream_ << lpsz;
  return *this;
}

CFX_WideTextBuf& CFX_WideTextBuf::operator<<(const CFX_WideTextBuf& buf) {
  stream_ << buf.stream_.str();
  return *this;
}
