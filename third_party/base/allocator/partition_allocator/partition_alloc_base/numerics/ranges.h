// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_RANGES_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_RANGES_H_

#include <cmath>
#include <type_traits>

namespace pdfium::base::internal::base {

template <typename T>
constexpr bool IsApproximatelyEqual(T lhs, T rhs, T tolerance) {
  static_assert(std::is_arithmetic<T>::value, "Argument must be arithmetic");
  return std::abs(rhs - lhs) <= tolerance;
}

}  // namespace pdfium::base::internal::base

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_RANGES_H_
