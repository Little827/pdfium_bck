// Copyright 2018 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "core/fxcrt/widestring.h"
#include "fxjs/cjs_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 2) {
    WideString input =
        WideString::FromUTF16LE(reinterpret_cast<const unsigned short*>(data),
                                size / sizeof(unsigned short));
    std::wstring winput(input.c_str(), input.GetLength());
    CJS_Util::ParseDataType(&winput);
  }
  if (size > 4) {
    size_t len1 = size / 2;
    size_t len2 = size - len1;
    WideString input1 =
        WideString::FromUTF16LE(reinterpret_cast<const unsigned short*>(data),
                                len1 / sizeof(unsigned short));
    WideString input2 =
        WideString::FromUTF16LE(reinterpret_cast<const unsigned short*>(data) +
                                    len1 / sizeof(unsigned short),
                                len2 / sizeof(unsigned short));
    CJS_Util::StringPrintx(input1, input2);
  }
  return 0;
}
