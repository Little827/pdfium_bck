// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCODEC_DATA_AND_BYTES_CONSUMED_H_
#define CORE_FXCODEC_DATA_AND_BYTES_CONSUMED_H_

#include <stdint.h>

#include "core/fxcrt/data_vector.h"

namespace fxcodec {

struct DataAndBytesConsumed {
  DataAndBytesConsumed();
  DataAndBytesConsumed(DataAndBytesConsumed&) = delete;
  DataAndBytesConsumed& operator=(DataAndBytesConsumed&) = delete;
  DataAndBytesConsumed(DataAndBytesConsumed&&) noexcept;
  DataAndBytesConsumed& operator=(DataAndBytesConsumed&&) noexcept;
  ~DataAndBytesConsumed();

  DataVector<uint8_t> data;
  uint32_t bytes_consumed;
};

}  // namespace fxcodec

using DataAndBytesConsumed = fxcodec::DataAndBytesConsumed;

#endif  // CORE_FXCODEC_DATA_AND_BYTES_CONSUMED_H_
