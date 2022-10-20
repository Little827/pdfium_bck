// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcodec/data_and_bytes_consumed.h"

namespace fxcodec {

DataAndBytesConsumed::DataAndBytesConsumed() = default;

DataAndBytesConsumed::DataAndBytesConsumed(DataAndBytesConsumed&&) noexcept =
    default;

DataAndBytesConsumed& DataAndBytesConsumed::operator=(
    DataAndBytesConsumed&&) noexcept = default;

DataAndBytesConsumed::~DataAndBytesConsumed() = default;

}  // namespace fxcodec
