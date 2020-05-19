// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CSS_CFX_CSSEXTTEXTBUF_H_
#define CORE_FXCRT_CSS_CFX_CSSEXTTEXTBUF_H_

#include "core/fxcrt/fx_string.h"

class CFX_CSSExtTextBuf {
 public:
  explicit CFX_CSSExtTextBuf(WideStringView str);
  ~CFX_CSSExtTextBuf();

  bool IsEOF() const { return pos_ >= buffer_.GetLength(); }
  void MoveNext() { pos_++; }
  wchar_t GetChar() const { return buffer_[pos_]; }
  wchar_t GetNextChar() const {
    return pos_ + 1 < buffer_.GetLength() ? buffer_[pos_ + 1] : 0;
  }

 protected:
  const WideStringView buffer_;
  size_t pos_ = 0;
};

#endif  // CORE_FXCRT_CSS_CFX_CSSEXTTEXTBUF_H_
