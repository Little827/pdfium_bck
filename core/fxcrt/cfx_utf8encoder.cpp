// Copyright 2018 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_utf8encoder.h"

#include "build/build_config.h"

CFX_UTF8Encoder::CFX_UTF8Encoder() = default;

CFX_UTF8Encoder::~CFX_UTF8Encoder() = default;

void CFX_UTF8Encoder::Input(wchar_t unicodeAsWchar) {
#if defined(WCHAR_T_IS_UTF16)
  if (unicodeAsWchar >= 0xD800 && unicodeAsWchar < 0xDC00) {
    // High surrogate.
    high_surrogate_ = unicodeAsWchar;
  } else if (unicodeAsWchar >= 0xDC00 && unicodeAsWchar <= 0xDFFF) {
    // Low surrogate.
    if (high_surrogate_) {
      char32_t code_point = unicodeAsWchar & 0x3FF;
      code_point |= (high_surrogate_ & 0x3FF) << 10;
      code_point += 0x10000;
      high_surrogate_ = 0;
      AppendCodePoint(code_point);
    }
  } else {
    high_surrogate_ = 0;
    AppendCodePoint(unicodeAsWchar);
  }
#else
  AppendCodePoint(unicodeAsWchar);
#endif  // defined(WCHAR_T_IS_UTF16)
}

void CFX_UTF8Encoder::AppendCodePoint(char32_t code_point) {
  if (code_point < 0x80) {
    // 7-bit code points are unchanged in UTF-8.
    buffer_.push_back(code_point);
    return;
  }

  int nbytes;
  if (code_point < 0x800) {
    nbytes = 2;
  } else if (code_point < 0x10000) {
    nbytes = 3;
  } else if (code_point < 0x110000) {
    nbytes = 4;
  } else {
    // Invalid code point above U+10FFFF.
    return;
  }

  static constexpr uint8_t kPrefix[] = {0xc0, 0xe0, 0xf0};
  int order = 1 << ((nbytes - 1) * 6);
  buffer_.push_back(kPrefix[nbytes - 2] | (code_point / order));
  for (int i = 0; i < nbytes - 1; i++) {
    code_point = code_point % order;
    order >>= 6;
    buffer_.push_back(0x80 | (code_point / order));
  }
}
