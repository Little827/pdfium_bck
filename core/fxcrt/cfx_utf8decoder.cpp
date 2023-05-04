// Copyright 2017 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_utf8decoder.h"

#include <stdint.h>

#include <utility>

CFX_UTF8Decoder::CFX_UTF8Decoder(ByteStringView input) {
  for (char byte : input) {
    uint8_t code_unit = static_cast<uint8_t>(byte);
    if (code_unit < 0x80) {
      pending_bytes_ = 0;
      AppendCodePoint(code_unit);
    } else if (code_unit < 0xc0) {
      if (pending_bytes_ == 0) {
        return;
      }
      pending_bytes_--;
      pending_code_point_ |= (code_unit & 0x3f) << (pending_bytes_ * 6);
      if (pending_bytes_ == 0) {
        AppendCodePoint(pending_code_point_);
      }
    } else if (code_unit < 0xe0) {
      pending_bytes_ = 1;
      pending_code_point_ = (code_unit & 0x1f) << 6;
    } else if (code_unit < 0xf0) {
      pending_bytes_ = 2;
      pending_code_point_ = (code_unit & 0x0f) << 12;
    } else if (code_unit < 0xf8) {
      pending_bytes_ = 3;
      pending_code_point_ = (code_unit & 0x07) << 18;
    } else {
      pending_bytes_ = 0;
    }
  }
}

CFX_UTF8Decoder::~CFX_UTF8Decoder() = default;

WideString CFX_UTF8Decoder::TakeResult() {
  return std::move(buffer_);
}

void CFX_UTF8Decoder::AppendCodePoint(char32_t code_point) {
  if (code_point > 0x10FFFF) {
    // Invalid code point above U+10FFFF.
    return;
  }

  buffer_ += static_cast<wchar_t>(code_point);
}
