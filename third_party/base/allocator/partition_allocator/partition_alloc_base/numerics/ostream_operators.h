// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_OSTREAM_OPERATORS_H_
#define THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_OSTREAM_OPERATORS_H_

#include <ostream>

namespace pdfium::base::internal::base::internal {

template <typename T>
class ClampedNumeric;
template <typename T>
class StrictNumeric;

// Overload the ostream output operator to make logging work nicely.
template <typename T>
std::ostream& operator<<(std::ostream& os, const StrictNumeric<T>& value) {
  os << static_cast<T>(value);
  return os;
}

// Overload the ostream output operator to make logging work nicely.
template <typename T>
std::ostream& operator<<(std::ostream& os, const ClampedNumeric<T>& value) {
  os << static_cast<T>(value);
  return os;
}

}  // namespace pdfium::base::internal::base::internal

#endif  // THIRD_PARTY_BASE_ALLOCATOR_PARTITION_ALLOCATOR_PARTITION_ALLOC_BASE_NUMERICS_OSTREAM_OPERATORS_H_
