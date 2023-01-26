// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_UNOWNED_PTR_PA_H_
#define CORE_FXCRT_UNOWNED_PTR_PA_H_

#include <cstddef>
#include <functional>
#include <type_traits>
#include <utility>

#include "third_party/base/compiler_specific.h"

// Currently, only the no-op implementation exists under PA.
// TODO(tsepez): shim onto base's raw_ptr<T>.

namespace pdfium {

template <typename T>
class span;

}  // namespace pdfium

namespace fxcrt {

template <class T>
class TRIVIAL_ABI GSL_POINTER UnownedPtr {
 public:
  constexpr UnownedPtr() noexcept = default;

  // Deliberately implicit to allow returning nullptrs.
  // NOLINTNEXTLINE(runtime/explicit)
  constexpr UnownedPtr(std::nullptr_t ptr) {}

  explicit constexpr UnownedPtr(T* pObj) noexcept : m_pObj(pObj) {}

  // Copy-construct an UnownedPtr.
  // Required in addition to copy conversion constructor below.
  constexpr UnownedPtr(const UnownedPtr& that) noexcept
      : m_pObj(static_cast<T*>(that)) {}

  // Move-construct an UnownedPtr. After construction, |that| will be NULL.
  // Required in addition to move conversion constructor below.
  constexpr UnownedPtr(UnownedPtr&& that) noexcept : m_pObj(that.Release()) {}

  // Copy-conversion constructor.
  template <class U,
            typename = typename std::enable_if<
                std::is_convertible<U*, T*>::value>::type>
  UnownedPtr(const UnownedPtr<U>& that) : UnownedPtr(static_cast<U*>(that)) {}

  // Move-conversion constructor.
  template <class U,
            typename = typename std::enable_if<
                std::is_convertible<U*, T*>::value>::type>
  UnownedPtr(UnownedPtr<U>&& that) noexcept {
    Reset(that.Release());
  }

  // Assign an UnownedPtr from nullptr.
  UnownedPtr& operator=(std::nullptr_t) noexcept {
    Reset();
    return *this;
  }

  // Assign an UnownedPtr from a raw ptr.
  UnownedPtr& operator=(T* that) noexcept {
    Reset(that);
    return *this;
  }

  // Copy-assign an UnownedPtr.
  // Required in addition to copy conversion assignment below.
  UnownedPtr& operator=(const UnownedPtr& that) noexcept {
    if (*this != that) {
      Reset(static_cast<T*>(that));
    }
    return *this;
  }

  // Move-assign an UnownedPtr. After assignment, |that| will be NULL.
  // Required in addition to move conversion assignment below.
  UnownedPtr& operator=(UnownedPtr&& that) noexcept {
    if (*this != that) {
      Reset(that.Release());
    }
    return *this;
  }

  // Copy-convert assignment.
  template <class U,
            typename = typename std::enable_if<
                std::is_convertible<U*, T*>::value>::type>
  UnownedPtr& operator=(const UnownedPtr<U>& that) noexcept {
    if (*this != that) {
      Reset(that);
    }
    return *this;
  }

  // Move-convert assignment. After assignment, |that| will be NULL.
  template <class U,
            typename = typename std::enable_if<
                std::is_convertible<U*, T*>::value>::type>
  UnownedPtr& operator=(UnownedPtr<U>&& that) noexcept {
    if (*this != that) {
      Reset(that.Release());
    }
    return *this;
  }

  ~UnownedPtr() { m_pObj = nullptr; }

  void Reset(T* obj = nullptr) { m_pObj = obj; }

  bool operator==(std::nullptr_t ptr) const { return m_pObj == nullptr; }
  bool operator==(const UnownedPtr& that) const {
    return m_pObj == static_cast<T*>(that);
  }
  bool operator<(const UnownedPtr& that) const {
    return std::less<T*>()(m_pObj, static_cast<T*>(that));
  }

  operator T*() const noexcept { return m_pObj; }
  T* Get() const noexcept { return m_pObj; }

  T* Release() {
    T* pTemp = nullptr;
    std::swap(pTemp, m_pObj);
    return pTemp;
  }

  explicit operator bool() const { return !!m_pObj; }
  T& operator*() const { return *m_pObj; }
  T* operator->() const { return m_pObj; }

 private:
  friend class pdfium::span<T>;

  void ReleaseBadPointer() {}

  T* m_pObj = nullptr;
};

}  // namespace fxcrt

#endif  // CORE_FXCRT_UNOWNED_PTR_PA_H_
