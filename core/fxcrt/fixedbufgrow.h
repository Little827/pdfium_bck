// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_FIXEDBUFGROW_H_
#define CORE_FXCRT_FIXEDBUFGROW_H_

#include <memory>

#include "core/fxcrt/fx_memory.h"

namespace fxcrt {

template <class DataType, int FixedSize>
class FixedBufGrow {
 public:
  explicit FixedBufGrow(int data_size) {
    if (data_size > FixedSize) {
      m_pGrowData.reset(FX_Alloc(DataType, data_size));
      return;
    }
    memset(m_FixedData, 0, sizeof(DataType) * FixedSize);
  }
  operator DataType*() { return m_pGrowData ? m_pGrowData.get() : m_FixedData; }

 private:
  std::unique_ptr<DataType, FxFreeDeleter> m_pGrowData;
  DataType m_FixedData[FixedSize];
};

}  // namespace fxcrt

using fxcrt::FixedBufGrow;

#endif  // CORE_FXCRT_FIXEDBUFGROW_H_
