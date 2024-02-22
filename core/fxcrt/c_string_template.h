// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_C_STRING_TEMPLATE_H_
#define CORE_FXCRT_C_STRING_TEMPLATE_H_

#include "core/fxcrt/check.h"
#include "core/fxcrt/compiler_specific.h"
#include "core/fxcrt/unowned_ptr_exclusion.h"

namespace fxcrt {

// CStringTemplate is a replacement for C-Style NUL-terminated strings.
// The caller must guarantee during construction that the string is NUL
// terminated. This is more specific than just the char* type, which may
// point to a non-NUL-terminated portion of memory, or even a single
// char (though StringView would be preferred for the former).
//
// CStringTemplate arguments should be passed by value, since they are
// small, rather than const-ref, even if they are not modified.
//
// CStringTeplate provides safe pre-increment and post-increment (++),
// but will CHECK() if an attempt is made to advance past the NUL. This
// avoids a lot of UNSAFE_BUFFER usage when advancing linearly through
// the string.  It forces the caller to evaluate buffer safety for
// ordinary + and += operations. It prohibits backing up the pointer
// altogether, to force a discipline on the programmer.
//
// Otherwise, CStringTemplate implicitly converts to T* so that other
// unsafe operations may be performed.
template <typename T>
class CStringTemplate {
 public:
  constexpr CStringTemplate() noexcept = default;
  constexpr CStringTemplate(const CStringTemplate& src) noexcept = default;

  UNSAFE_BUFFER_USAGE explicit CStringTemplate(const T* ptr) noexcept
      : ptr_(ptr) {}

  CStringTemplate& operator=(const CStringTemplate& src) = default;

  UNSAFE_BUFFER_USAGE CStringTemplate& operator=(const T* ptr) {
    ptr_ = ptr;
    return *this;
  }

  // Pre-increment.
  CStringTemplate& operator++() {
    CHECK(*ptr_);
    UNSAFE_BUFFERS(++ptr_);
    return *this;
  }

  // Post-increment.
  CStringTemplate operator++(int) {
    CHECK(*ptr_);
    const T* old = UNSAFE_BUFFERS(ptr_++);
    return CStringTemplate(old);
  }

  UNSAFE_BUFFER_USAGE CStringTemplate& operator+=(size_t count) {
    UNSAFE_BUFFERS(ptr_ += count);
    return *this;
  }

  UNSAFE_BUFFER_USAGE CStringTemplate operator+(size_t count) {
    return CStringTemplate(UNSAFE_BUFFERS(ptr_ + count));
  }

  // No decrement, since may back up before the start of the string.
  CStringTemplate& operator--() = delete;
  CStringTemplate operator--(int) = delete;
  CStringTemplate& operator-=(size_t) = delete;
  CStringTemplate operator-(size_t) = delete;

  // Implicit conversion back to T* for other uses.
  operator const T*() { return ptr_; }

 private:
  UNOWNED_PTR_EXCLUSION const T* ptr_ = nullptr;
};

using CString = CStringTemplate<char>;
using WCString = CStringTemplate<wchar_t>;

}  // namespace fxcrt

using CString = fxcrt::CString;
using WCString = fxcrt::WCString;

#endif  // CORE_FXCRT_C_STRING_TEMPLATE_H_
