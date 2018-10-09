// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_WIDETEXTBUF_H_
#define CORE_FXCRT_CFX_WIDETEXTBUF_H_

#include <sstream>

#include "core/fxcrt/cfx_binarybuf.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "third_party/base/optional.h"

class CFX_WideTextBuf final/* : public CFX_BinaryBuf*/ {
 public:
  const wchar_t* GetBuffer() const {
    return GetString().c_str();
  }

  std::wstring GetModifiableBuffer() {
    return GetString();
  }

  size_t GetSize() const {
    return GetLength() * sizeof(wchar_t);
  };

  size_t GetLength() const {
    return GetString().length();
  };

  size_t GetLength() {
    return stream_.tellp();
  };

  void SetAllocStep(size_t step) {}

  WideStringView AsStringView() const {
    return WideStringView(GetString().c_str());
  }
  WideString MakeString() const {
    return WideString(GetString().c_str());
  }

  std::wstring GetString() const {
    return stream_.str();
  }

  void SetString(std::wstring str) {
    stream_.str(str);
  }

  void Delete(int start_index, int count) {
    std::wstring str = stream_.str();
    str.erase(start_index, count);
    stream_.str(str);
  }

  void Clear() {
    stream_.clear();
  }

  void AppendChar(wchar_t wch);
  CFX_WideTextBuf& operator<<(int i);
  CFX_WideTextBuf& operator<<(double f);
  CFX_WideTextBuf& operator<<(const wchar_t* lpsz);
  CFX_WideTextBuf& operator<<(const WideStringView& str);
  CFX_WideTextBuf& operator<<(const WideString& str);
  CFX_WideTextBuf& operator<<(const CFX_WideTextBuf& buf);

 private:

  std::wostringstream stream_;
};

#endif  // CORE_FXCRT_CFX_WIDETEXTBUF_H_
