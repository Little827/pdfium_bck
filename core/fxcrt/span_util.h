// Copyright 2021 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_SPAN_UTIL_H_
#define CORE_FXCRT_SPAN_UTIL_H_

#include "core/fxcrt/fx_memcpy_wrappers.h"
#include "third_party/abseil-cpp/absl/types/optional.h"
#include "third_party/base/check_op.h"
#include "third_party/base/containers/span.h"

namespace fxcrt {

// Bounds-checked copies from spans into spans.
template <typename T,
          typename U,
          typename = pdfium::internal::EnableIfLegalSpanConversion<T, U>>
void spancpy(pdfium::span<T> dst, pdfium::span<U> src) {
  CHECK_GE(dst.size_bytes(), src.size_bytes());
  FXSYS_memcpy(dst.data(), src.data(), src.size_bytes());
}

// Bounds-checked moves from spans into spans.
template <typename T,
          typename U,
          typename = pdfium::internal::EnableIfLegalSpanConversion<T, U>>
void spanmove(pdfium::span<T> dst, pdfium::span<U> src) {
  CHECK_GE(dst.size_bytes(), src.size_bytes());
  FXSYS_memmove(dst.data(), src.data(), src.size_bytes());
}

// Bounds-checked sets into spans.
template <typename T>
void spanset(pdfium::span<T> dst, uint8_t val) {
  FXSYS_memset(dst.data(), val, dst.size_bytes());
}

// Bounds-checked zeroing of spans.
template <typename T>
void spanclr(pdfium::span<T> dst) {
  FXSYS_memset(dst.data(), 0, dst.size_bytes());
}

// These rely on implementation details of pdfium::span<T>, however they
// can be made to work with std-conforming implementation by doing the
// bounds checking explicitly here.
template <typename T>
absl::optional<pdfium::span<T>> try_subspan(
    pdfium::span<T> span,
    size_t offset,
    size_t count = pdfium::dynamic_extent) {
  if (!span.has_subspan(offset, count)) {
    return absl::nullopt;
  }
  return span.unsafe_subspan(offset, count);
}

template <typename T>
absl::optional<pdfium::span<T>> try_first(pdfium::span<T> span, size_t count) {
  if (!span.has_first(count)) {
    return absl::nullopt;
  }
  return span.unsafe_first(count);
}

template <typename T>
absl::optional<pdfium::span<T>> try_last(pdfium::span<T> span, size_t count) {
  if (!span.has_last(count)) {
    return absl::nullopt;
  }
  return span.unsafe_last(count);
}

}  // namespace fxcrt

#endif  // CORE_FXCRT_SPAN_UTIL_H_
