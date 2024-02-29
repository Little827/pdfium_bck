// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_RAW_SPAN_H_
#define CORE_FXCRT_RAW_SPAN_H_

#include "core/fxcrt/span.h"

namespace pdfium {

template <typename T>
using raw_span = span<T, dynamic_extent, raw_ptr<T, AllowPtrArithmetic>>;

}  // namespace pdfium

#endif  // CORE_FXCRT_RAW_SPAN_H_
