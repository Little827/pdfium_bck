// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/cfx_read_only_vector_stream.h"

#include <utility>

#include "core/fxcrt/cfx_read_only_span_stream.h"
#include "third_party/base/numerics/safe_conversions.h"

CFX_ReadOnlyVectorStream::CFX_ReadOnlyVectorStream(DataVector<uint8_t> data)
    : data_(std::move(data)), span_(data_) {}

CFX_ReadOnlyVectorStream::~CFX_ReadOnlyVectorStream() = default;

FX_FILESIZE CFX_ReadOnlyVectorStream::GetSize() {
  return pdfium::base::checked_cast<FX_FILESIZE>(span_.size());
}

bool CFX_ReadOnlyVectorStream::ReadBlockAtOffset(void* buffer,
                                                 FX_FILESIZE offset,
                                                 size_t size) {
  return CFX_ReadOnlySpanStream::ReadBlockAtOffsetFromSpan(span_, buffer,
                                                           offset, size);
}
