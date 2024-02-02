// Copyright 2014 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_FX_SAFE_TYPES_H_
#define CORE_FXCRT_FX_SAFE_TYPES_H_

#include <stddef.h>
#include <stdint.h>

#include "core/fxcrt/fx_types.h"
#include "third_party/base/numerics/safe_math.h"

using FX_SAFE_UINT32 = pdfium::base::CheckedNumeric<uint32_t>;
using FX_SAFE_INT32 = pdfium::base::CheckedNumeric<int32_t>;
using FX_SAFE_SIZE_T = pdfium::base::CheckedNumeric<size_t>;
using FX_SAFE_FILESIZE = pdfium::base::CheckedNumeric<FX_FILESIZE>;

using FX_STRICT_UINT8 = pdfium::base::StrictNumeric<uint8_t>;
using FX_STRICT_UINT16 = pdfium::base::StrictNumeric<uint16_t>;
using FX_STRICT_UINT32 = pdfium::base::StrictNumeric<uint32_t>;
using FX_STRICT_SIZE_T = pdfium::base::StrictNumeric<size_t>;

#endif  // CORE_FXCRT_FX_SAFE_TYPES_H_
