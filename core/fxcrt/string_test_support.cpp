// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>

#include "core/fxcrt/bytestring.h"

namespace fxcrt {

void PrintTo(const ByteString& str, ::std::ostream* os) {
  *os << str;
}

}  // namespace fxcrt
