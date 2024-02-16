// Copyright 2015 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_STL_UTIL_H_
#define CORE_FXCRT_STL_UTIL_H_

#include <memory>

#include "third_party/base/check_op.h"
#include "third_party/base/compiler_specific.h"
#include "third_party/base/numerics/safe_conversions.h"

namespace fxcrt {

// Means of generating a key for searching STL collections of std::unique_ptr
// that avoids the side effect of deleting the pointer.
template <class T>
class FakeUniquePtr : public std::unique_ptr<T> {
 public:
  using std::unique_ptr<T>::unique_ptr;
  ~FakeUniquePtr() { std::unique_ptr<T>::release(); }
};

// Type-deducing wrapper for FakeUniquePtr<T>.
template <class T>
FakeUniquePtr<T> MakeFakeUniquePtr(T* arg) {
  return FakeUniquePtr<T>(arg);
}

// Convenience routine for "int-fected" code, so that the stl collection
// size_t size() method return values will be checked.
template <typename ResultType, typename Collection>
ResultType CollectionSize(const Collection& collection) {
  return pdfium::base::checked_cast<ResultType>(collection.size());
}

// Convenience routine for "int-fected" code, to handle signed indices. The
// compiler can deduce the type, making this more convenient than the above.
template <typename IndexType, typename Collection>
bool IndexInBounds(const Collection& collection, IndexType index) {
  return index >= 0 && index < CollectionSize<IndexType>(collection);
}

// Convenience routines to get bounds-checked iterators from indices.
template <typename T>
T::iterator IterAfterBegin(T& container, size_t index) {
  CHECK_LT(index, container.size());
  // SAFTEY: CHECK() above ensures index is in bounds, so begin + index
  // is also in bounds.
  return UNSAFE_BUFFERS(container.begin() + index);
}

template <typename T>
T::iterator IterBeforeEnd(T& container, size_t index) {
  CHECK_LT(index, container.size());
  // SAFTEY: CHECK() above ensures index is in bounds, so end - index
  // is also in bounds.
  return UNSAFE_BUFFERS(container.end() - index);
}

}  // namespace fxcrt

#endif  // CORE_FXCRT_STL_UTIL_H_
