// Copyright 2017 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_UNOWNED_PTR_H_
#define CORE_FXCRT_UNOWNED_PTR_H_

// UnownedPtr is a smart pointer class that behaves very much like a
// standard C-style pointer. The advantages of using it over raw
// pointers are:
//
// 1. It documents the nature of the pointer with no need to add a comment
//    explaining that is it // Not owned. Additionally, an attempt to delete
//    an unowned ptr will fail to compile rather than silently succeeding,
//    since it is a class and not a raw pointer.
//
// 2. When built using the memory tool ASAN, the class provides a destructor
//    which checks that the object being pointed to is still alive.
//
// Hence, when using UnownedPtr, no dangling pointers are ever permitted,
// even if they are not de-referenced after becoming dangling. The style of
// programming required is that the lifetime an object containing an
// UnownedPtr must be strictly less than the object to which it points.
//
// The same checks are also performed at assignment time to prove that the
// old value was not a dangling pointer, either.
//
// The array indexing operation [] is not supported on an unowned ptr,
// because an unowned ptr expresses a one to one relationship with some
// other heap object. Use pdfium::span<> for the cases where indexing
// into an unowned array is desired, which performs the same checks.
//
// The actual implementation varies based upon the available allocators.

#if defined(PDF_USE_PARTITION_ALLOC)
#include "core/fxcrt/unowned_ptr_pa.h"
#else
#include "core/fxcrt/unowned_ptr_malloc.h"
#endif

using fxcrt::UnownedPtr;

namespace pdfium {

// Type-deducing wrapper to make an UnownedPtr from an ordinary pointer,
// since equivalent constructor is explicit.
template <typename T>
UnownedPtr<T> WrapUnowned(T* that) {
  return UnownedPtr<T>(that);
}

}  // namespace pdfium

#endif  // CORE_FXCRT_UNOWNED_PTR_H_
