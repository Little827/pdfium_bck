// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_DATA_VECTOR_H_
#define CORE_FXCRT_DATA_VECTOR_H_

#include <stdint.h>

#include <vector>

#include "core/fxcrt/fx_memory_wrappers.h"

namespace fxcrt {

using DataVectorUint8 = std::vector<uint8_t, FxAllocAllocator<uint8_t>>;

}  // namespace fxcrt

using fxcrt::DataVectorUint8;

#endif  // CORE_FXCRT_DATA_VECTOR_H_
