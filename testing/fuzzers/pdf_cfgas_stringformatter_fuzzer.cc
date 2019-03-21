// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "xfa/fgas/crt/cfgas_stringformatter.h"

#include <stdint.h>

#include "core/fxcrt/fx_string.h"
#include "third_party/base/ptr_util.h"
#include "xfa/fxfa/parser/cxfa_localemgr.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  size_t widelen = size / sizeof(wchar_t);
  if (widelen < 2)
    return 0;

  size_t pattern_len = widelen / 2;
  size_t value_len = widelen - pattern_len;
  WideString pattern(reinterpret_cast<const wchar_t*>(data), pattern_len);
  WideString value(reinterpret_cast<const wchar_t*>(data) + pattern_len,
                   value_len);
  WideString result;
  auto mgr = pdfium::MakeUnique<CXFA_LocaleMgr>(nullptr, L"en");
  auto fmt = pdfium::MakeUnique<CFGAS_StringFormatter>(mgr.get(), pattern);
  fmt->FormatText(value, &result);
  fmt->FormatNum(value, &result);
  fmt->FormatDateTime(value, FX_DATETIMETYPE_DateTime, &result);
  return 0;
}
