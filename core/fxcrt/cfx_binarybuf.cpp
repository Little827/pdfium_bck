// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_binarybuf.h"

#include <algorithm>
#include <utility>

#include "core/fxcrt/fx_safe_types.h"

CFX_BinaryBuf::CFX_BinaryBuf() = default;

CFX_BinaryBuf::~CFX_BinaryBuf() = default;

void CFX_BinaryBuf::Delete(size_t start_index, size_t count) {
  if (!buffer_ || count > data_size_ || start_index > data_size_ - count)
    return;

  memmove(buffer_.get() + start_index, buffer_.get() + start_index + count,
          data_size_ - start_index - count);
  data_size_ -= count;
}

pdfium::span<uint8_t> CFX_BinaryBuf::GetSpan() {
  return {GetBuffer(), GetSize()};
}

pdfium::span<const uint8_t> CFX_BinaryBuf::GetSpan() const {
  return {GetBuffer(), GetSize()};
}

size_t CFX_BinaryBuf::GetLength() const {
  return data_size_;
}

void CFX_BinaryBuf::Clear() {
  data_size_ = 0;
}

std::unique_ptr<uint8_t, FxFreeDeleter> CFX_BinaryBuf::DetachBuffer() {
  data_size_ = 0;
  alloc_size_ = 0;
  return std::move(buffer_);
}

void CFX_BinaryBuf::EstimateSize(size_t size) {
  if (alloc_size_ < size)
    ExpandBuf(size - data_size_);
}

void CFX_BinaryBuf::ExpandBuf(size_t add_size) {
  FX_SAFE_SIZE_T new_size = data_size_;
  new_size += add_size;
  if (alloc_size_ >= new_size.ValueOrDie())
    return;

  size_t alloc_step = std::max(static_cast<size_t>(128),
                               alloc_step_ ? alloc_step_ : alloc_size_ / 4);
  new_size += alloc_step - 1;  // Quantize, don't combine these lines.
  new_size /= alloc_step;
  new_size *= alloc_step;
  alloc_size_ = new_size.ValueOrDie();
  buffer_.reset(buffer_ ? FX_Realloc(uint8_t, buffer_.release(), alloc_size_)
                        : FX_Alloc(uint8_t, alloc_size_));
}

void CFX_BinaryBuf::AppendSpan(pdfium::span<const uint8_t> span) {
  return AppendBlock(span.data(), span.size());
}

void CFX_BinaryBuf::AppendBlock(const void* pBuf, size_t size) {
  if (size == 0)
    return;

  ExpandBuf(size);
  if (pBuf) {
    memcpy(buffer_.get() + data_size_, pBuf, size);
  } else {
    memset(buffer_.get() + data_size_, 0, size);
  }
  data_size_ += size;
}
