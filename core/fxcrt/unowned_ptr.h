// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_UNOWNED_PTR_H_
#define CORE_FXCRT_UNOWNED_PTR_H_

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

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

namespace pdfium {

template <typename T>
class span;

}  // namespace pdfium

namespace fxcrt {

template <class T>
class UnownedPtr {
 public:
  constexpr UnownedPtr() noexcept = default;
  constexpr UnownedPtr(const UnownedPtr& that) noexcept = default;

  // Move-construct an UnownedPtr. After construction, |that| will be NULL.
  constexpr UnownedPtr(UnownedPtr&& that) noexcept : obj_(that.Release()) {}

  template <typename U>
  explicit constexpr UnownedPtr(U* pObj) noexcept : obj_(pObj) {}

  // Deliberately implicit to allow returning nullptrs.
  // NOLINTNEXTLINE(runtime/explicit)
  constexpr UnownedPtr(std::nullptr_t ptr) noexcept {}

  ~UnownedPtr() { ProbeForLowSeverityLifetimeIssue(); }

  void Reset(T* obj = nullptr) {
    ProbeForLowSeverityLifetimeIssue();
    obj_ = obj;
  }

  UnownedPtr& operator=(T* that) noexcept {
    Reset(that);
    return *this;
  }

  UnownedPtr& operator=(const UnownedPtr& that) noexcept {
    if (*this != that)
      Reset(that.Get());
    return *this;
  }

  // Move-assign an UnownedPtr. After assignment, |that| will be NULL.
  UnownedPtr& operator=(UnownedPtr&& that) noexcept {
    if (*this != that)
      Reset(that.Release());
    return *this;
  }

  bool operator==(const UnownedPtr& that) const { return Get() == that.Get(); }
  bool operator!=(const UnownedPtr& that) const { return !(*this == that); }
  bool operator<(const UnownedPtr& that) const {
    return std::less<T*>()(Get(), that.Get());
  }

  operator T*() const noexcept { return Get(); }
  T* Get() const noexcept { return obj_; }

  T* Release() {
    ProbeForLowSeverityLifetimeIssue();
    T* pTemp = nullptr;
    std::swap(pTemp, obj_);
    return pTemp;
  }

  explicit operator bool() const { return !!obj_; }
  T& operator*() const { return *obj_; }
  T* operator->() const { return obj_; }

 private:
  friend class pdfium::span<T>;

  inline void ProbeForLowSeverityLifetimeIssue() {
#if defined(ADDRESS_SANITIZER)
    if (obj_)
      reinterpret_cast<const volatile uint8_t*>(obj_)[0];
#endif
  }

  inline void ReleaseBadPointer() {
#if defined(ADDRESS_SANITIZER)
    obj_ = nullptr;
#endif
  }

  T* obj_ = nullptr;
};

}  // namespace fxcrt

using fxcrt::UnownedPtr;

#endif  // CORE_FXCRT_UNOWNED_PTR_H_
