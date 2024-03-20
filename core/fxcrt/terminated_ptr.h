// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_TERMINATED_PTR_H_
#define CORE_FXCRT_TERMINATED_PTR_H_

#include <cstddef>

#include "core/fxcrt/check.h"
#include "core/fxcrt/compiler_specific.h"
#include "core/fxcrt/unowned_ptr_exclusion.h"

namespace fxcrt {

// TerminatedPtr is a replacement for C-Style NUL-terminated strings (and other
// sequences whose end is represented by an in-band value, and where operator
// bool for the given type returns false at the end of the sequence).
//
// This is more specific than just a T* type, which may point to a non-NUL
// terminated portion of memory, or even a single char (though StringView would
// be preferred for the former). The caller must guarantee during construction
// that the string is NUL terminated.
//
// TerminatedPtr arguments should be passed by value, since they are the same
// size as any other pointer, rather than by const-ref, even if they are not
// modified.
//
// TerminatedPtr provides safe pre-increment and post-increment (++), but will
// CHECK() if an attempt is made to advance past the terminator. This avoids a
// lot of UNSAFE_BUFFER usage when advancing linearly through as string.  It
// converts implicitly back to T* to force the caller to evaluate buffer safety
// other operations, such as the ordinary `+` and `+=` operations. It prohibits
// backing up the pointer altogether, to force a discipline on the programmer.
//
// TerminatedPtr always points to const storage to make it less likely that
// overwriting the terminator can occur, leading to OOB access.
//
template <typename T>
class TerminatedPtr {
 public:
  UNSAFE_BUFFER_USAGE static TerminatedPtr FromPtr(const T* arg) {
    return TerminatedPtr(arg);
  }

  constexpr TerminatedPtr() = default;

  // Implicit construction from nullptr without requiring UNSAFE_BUFFERS.
  constexpr TerminatedPtr(std::nullptr_t ptr) {}  // NOLINT(runtime/explicit)

  // Implicit construction from literals without requiring UNSAFE_BUFFERS.
  template <size_t M>
  constexpr TerminatedPtr(const T (&lit)[M])  // NOLINT(runtime/explicit)
      noexcept
#if defined(__clang__) && HAS_ATTRIBUTE(enable_if)
      // clang-specific magic to restrict use of this implicit constructor to
      // cases where the compiler can prove a literal is terminated. For
      // non-clang compilers, this constructor always applies and the code
      // compiles even for non-terminated literals. This is ok since we can
      // rely on clang to catch any misuse during development.
      __attribute__((enable_if(lit[M - 1u] == T{0}, "not terminated")))
#endif
      : ptr_(&lit[0u]) {
  }

  // Pre-increment.
  TerminatedPtr& operator++() {
    CHECK(*ptr_);
    UNSAFE_BUFFERS(++ptr_);
    return *this;
  }

  // Post-increment.
  TerminatedPtr operator++(int) {
    auto old = *this;
    CHECK(*ptr_);
    UNSAFE_BUFFERS(ptr_++);
    return old;
  }

  // No advance by arbitrary amounts.
  TerminatedPtr& operator+=(size_t count) = delete;
  TerminatedPtr operator+(size_t count) = delete;

  // No decrement, since may back up before the start of the string.
  TerminatedPtr& operator--() = delete;
  TerminatedPtr operator--(int) = delete;
  TerminatedPtr& operator-=(size_t) = delete;
  TerminatedPtr operator-(size_t) = delete;

  // No indexing by arbitrary offsets.
  T& operator[](size_t index) = delete;
  const T& operator[](size_t index) const = delete;

  // Implicit conversion back to T* for other uses.
  operator const T*() const { return ptr_; }

  // Explicit conversion to T* for rare cases.
  const T* get() const { return ptr_; }

 private:
  // Must remain private and explicit to avoid ambiguity with (&lit)[N] form.
  explicit TerminatedPtr(const T* ptr) noexcept : ptr_(ptr) {}

  UNOWNED_PTR_EXCLUSION const T* ptr_ = nullptr;
};

static_assert(sizeof(TerminatedPtr<char>) == sizeof(char*),
              "TerminatedPtr can not be more expensive than char* pointers");

}  // namespace fxcrt

using fxcrt::TerminatedPtr;

#endif  // CORE_FXCRT_TERMINATED_PTR_H_
