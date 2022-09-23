// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_FIXED_SIZE_DATA_VECTOR_H_
#define CORE_FXCRT_FIXED_SIZE_DATA_VECTOR_H_

#include <stddef.h>

#include <memory>
#include <utility>

#include "core/fxcrt/fx_memory_wrappers.h"
#include "third_party/base/span.h"

namespace fxcrt {

// A simple data container that has a fixed size.
// Unlike std::vector, it cannot be implicitly copied and its data is only
// accessible using spans.
// It can either initialize its data with zeros, or leave its data
// uninitialized.
template <typename T>
class FixedSizeDataVector {
 public:
  FixedSizeDataVector(size_t size, bool initialize)
      : data_(MaybeInit(size, initialize)), size_(size) {}
  FixedSizeDataVector(const FixedSizeDataVector&) = delete;
  FixedSizeDataVector& operator=(const FixedSizeDataVector&) = delete;
  FixedSizeDataVector(FixedSizeDataVector&& that) noexcept {
    data_ = std::move(that.data_);
    size_ = that.size_;
    that.size_ = 0;
  }
  FixedSizeDataVector& operator=(FixedSizeDataVector&& that) noexcept {
    data_ = std::move(that.data_);
    size_ = that.size_;
    that.size_ = 0;
    return *this;
  }
  ~FixedSizeDataVector() = default;

  operator pdfium::span<const T>() const { return span(); }

  pdfium::span<T> writable_span() {
    return pdfium::make_span(data_.get(), size_);
  }

  pdfium::span<const T> span() const {
    return pdfium::make_span(data_.get(), size_);
  }

  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

 private:
  static T* MaybeInit(size_t size, bool initialize) {
    if (size == 0)
      return nullptr;
    return initialize ? FX_Alloc(T, size) : FX_AllocUninit(T, size);
  }

  std::unique_ptr<T, FxFreeDeleter> data_;
  size_t size_;
};

template <typename T>
class FixedDataVector : public FixedSizeDataVector<T> {
 public:
  FixedDataVector() : FixedDataVector(0) {}
  explicit FixedDataVector(size_t size)
      : FixedSizeDataVector<T>(size, /*initialize=*/true) {}
};

template <typename T>
class FixedUninitDataVector : public FixedSizeDataVector<T> {
 public:
  FixedUninitDataVector() : FixedUninitDataVector(0) {}
  explicit FixedUninitDataVector(size_t size)
      : FixedSizeDataVector<T>(size, /*initialize=*/false) {}
};

}  // namespace fxcrt

using fxcrt::FixedDataVector;
using fxcrt::FixedUninitDataVector;

#endif  // CORE_FXCRT_FIXED_SIZE_DATA_VECTOR_H_
