// Copyright 2017 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_utf8decoder.h"

#include <utility>

CFX_UTF8Decoder::CFX_UTF8Decoder(ByteStringView input) {
  for (char c : input) {
    ProcessByte(c);
  }
}

CFX_UTF8Decoder::~CFX_UTF8Decoder() = default;

WideString CFX_UTF8Decoder::TakeResult() {
  return std::move(m_Buffer);
}

void CFX_UTF8Decoder::AppendCodePoint(uint32_t ch) {
  // Overlong sequences.
  if (ch < m_MinCodePoint) {
    m_HasError = true;
  }

  m_Buffer += static_cast<wchar_t>(ch);
  m_MinCodePoint = 0;
}

void CFX_UTF8Decoder::ProcessByte(uint8_t byte) {
  if (byte < 0x80) {
    if (m_PendingBytes) {
      m_HasError = true;
    }
    m_PendingBytes = 0;
    AppendCodePoint(byte);
  } else if (byte < 0xc0) {
    if (m_PendingBytes == 0) {
      m_HasError = true;
      return;
    }
    m_PendingBytes--;
    m_PendingChar |= (byte & 0x3f) << (m_PendingBytes * 6);
    if (m_PendingBytes == 0) {
      AppendCodePoint(m_PendingChar);
    }
  } else if (byte < 0xe0) {
    m_PendingBytes = 1;
    m_MinCodePoint = 0x80;
    m_PendingChar = (byte & 0x1f) << 6;
  } else if (byte < 0xf0) {
    m_PendingBytes = 2;
    m_MinCodePoint = 0x800;
    m_PendingChar = (byte & 0x0f) << 12;
  } else if (byte < 0xf8) {
    m_PendingBytes = 3;
    m_MinCodePoint = 0x10000;
    m_PendingChar = (byte & 0x07) << 18;
  } else if (byte < 0xfc) {
    m_PendingBytes = 4;
    m_MinCodePoint = 0x200000;
    m_PendingChar = (byte & 0x03) << 24;
  } else if (byte < 0xfe) {
    m_PendingBytes = 5;
    m_MinCodePoint = 0x4000000;
    m_PendingChar = (byte & 0x01) << 30;
  } else {
    m_PendingBytes = 0;
    m_HasError = true;
  }
}

bool CFX_UTF8Decoder::HasError() const {
  return m_HasError || m_PendingBytes != 0;
}
