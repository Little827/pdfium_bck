// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_UTF8DECODER_H_
#define CORE_FXCRT_CFX_UTF8DECODER_H_

#include "core/fxcrt/cfx_widetextbuf.h"

class CFX_UTF8Decoder {
 public:
  CFX_UTF8Decoder();
  ~CFX_UTF8Decoder();

  void Input(uint8_t byte);
  void AppendCodePoint(uint32_t ch);
  void ClearStatus() { pending_bytes_ = 0; }
  WideStringView GetResult() const { return buffer_.AsStringView(); }

 private:
  int pending_bytes_ = 0;
  uint32_t pending_char_ = 0;
  CFX_WideTextBuf buffer_;
};

#endif  // CORE_FXCRT_CFX_UTF8DECODER_H_
