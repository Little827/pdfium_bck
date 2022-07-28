// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_SMALL_BUFFER_H_
#define CORE_FXCRT_SMALL_BUFFER_H_

#include <array>
#include <memory>

#include "core/fxcrt/fx_memory_wrappers.h"

namespace fxcrt {

template <class T, size_t FixedSize>
class SmallBuffer {
 public:
  explicit SmallBuffer(size_t actual_size) : m_pSize(actual_size) {
    if (actual_size > FixedSize) {
      m_pDynamicData.reset(FX_Alloc(T, actual_size));
      return;
    }
    memset(m_FixedData.data(), 0, sizeof(T) * FixedSize);
  }
  T* data() {
    return m_pDynamicData ? m_pDynamicData.get() : m_FixedData.data();
  }
  T* begin() { return data(); }
  T* end() { return begin() + m_pSize; }

 private:
  const size_t m_pSize;
  std::unique_ptr<T, FxFreeDeleter> m_pDynamicData;
  std::array<T, FixedSize> m_FixedData;
};

}  // namespace fxcrt

using fxcrt::SmallBuffer;

#endif  // CORE_FXCRT_SMALL_BUFFER_H_
