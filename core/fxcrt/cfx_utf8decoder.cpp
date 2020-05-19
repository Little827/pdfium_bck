// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_utf8decoder.h"

CFX_UTF8Decoder::CFX_UTF8Decoder() = default;

CFX_UTF8Decoder::~CFX_UTF8Decoder() = default;

void CFX_UTF8Decoder::AppendCodePoint(uint32_t ch) {
  buffer_.AppendChar(static_cast<wchar_t>(ch));
}

void CFX_UTF8Decoder::Input(uint8_t byte) {
  if (byte < 0x80) {
    pending_bytes_ = 0;
    buffer_.AppendChar(byte);
  } else if (byte < 0xc0) {
    if (pending_bytes_ == 0) {
      return;
    }
    pending_bytes_--;
    pending_char_ |= (byte & 0x3f) << (pending_bytes_ * 6);
    if (pending_bytes_ == 0) {
      AppendCodePoint(pending_char_);
    }
  } else if (byte < 0xe0) {
    pending_bytes_ = 1;
    pending_char_ = (byte & 0x1f) << 6;
  } else if (byte < 0xf0) {
    pending_bytes_ = 2;
    pending_char_ = (byte & 0x0f) << 12;
  } else if (byte < 0xf8) {
    pending_bytes_ = 3;
    pending_char_ = (byte & 0x07) << 18;
  } else if (byte < 0xfc) {
    pending_bytes_ = 4;
    pending_char_ = (byte & 0x03) << 24;
  } else if (byte < 0xfe) {
    pending_bytes_ = 5;
    pending_char_ = (byte & 0x01) << 30;
  } else {
    pending_bytes_ = 0;
  }
}
