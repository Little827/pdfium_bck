// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_RETAIN_PTR_H_
#define CORE_FXCRT_RETAIN_PTR_H_

#include <functional>
#include <memory>
#include <utility>

#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/unowned_ptr.h"

namespace fxcrt {

// Used with std::unique_ptr to Release() objects that can't be deleted.
template <class T>
struct ReleaseDeleter {
  inline void operator()(T* ptr) const { ptr->Release(); }
};

// Analogous to base's scoped_refptr.
template <class T>
class RetainPtr {
 public:
  explicit RetainPtr(T* pObj) : obj_(pObj) {
    if (obj_)
      obj_->Retain();
  }

  RetainPtr() = default;
  RetainPtr(const RetainPtr& that) : RetainPtr(that.Get()) {}

  // Move-construct a RetainPtr. After construction, |that| will be NULL.
  RetainPtr(RetainPtr&& that) noexcept { Swap(that); }

  // Deliberately implicit to allow returning nullptrs.
  // NOLINTNEXTLINE(runtime/explicit)
  RetainPtr(std::nullptr_t ptr) {}

  template <class U>
  RetainPtr(const RetainPtr<U>& that) : RetainPtr(that.Get()) {}

  template <class U>
  RetainPtr<U> As() const {
    return RetainPtr<U>(static_cast<U*>(Get()));
  }

  void Reset(T* obj = nullptr) {
    if (obj)
      obj->Retain();
    obj_.reset(obj);
  }

  explicit operator T*() const { return Get(); }
  T* Get() const { return obj_.get(); }
  UnownedPtr<T> BackPointer() const { return UnownedPtr<T>(Get()); }
  void Swap(RetainPtr& that) { obj_.swap(that.obj_); }

  // Useful for passing notion of object ownership across a C API.
  T* Leak() { return obj_.release(); }
  void Unleak(T* ptr) { obj_.reset(ptr); }

  RetainPtr& operator=(const RetainPtr& that) {
    if (*this != that)
      Reset(that.Get());
    return *this;
  }

  // Move-assign a RetainPtr. After assignment, |that| will be NULL.
  RetainPtr& operator=(RetainPtr&& that) {
    obj_.reset(that.Leak());
    return *this;
  }

  // Use sparingly, may produce reference count churn.
  RetainPtr& operator=(T* that) {
    Reset(that);
    return *this;
  }

  bool operator==(const RetainPtr& that) const { return Get() == that.Get(); }
  bool operator!=(const RetainPtr& that) const { return !(*this == that); }

  template <typename U>
  bool operator==(const U& that) const {
    return Get() == that;
  }

  template <typename U>
  bool operator!=(const U& that) const {
    return !(*this == that);
  }

  bool operator<(const RetainPtr& that) const {
    return std::less<T*>()(Get(), that.Get());
  }

  explicit operator bool() const { return !!obj_; }
  T& operator*() const { return *obj_; }
  T* operator->() const { return obj_.get(); }

 private:
  std::unique_ptr<T, ReleaseDeleter<T>> obj_;
};

// Trivial implementation - internal ref count with virtual destructor.
class Retainable {
 public:
  Retainable() = default;

  bool HasOneRef() const { return ref_count_ == 1; }

 protected:
  virtual ~Retainable() = default;

 private:
  template <typename U>
  friend struct ReleaseDeleter;

  template <typename U>
  friend class RetainPtr;

  Retainable(const Retainable& that) = delete;
  Retainable& operator=(const Retainable& that) = delete;

  void Retain() const { ++ref_count_; }
  void Release() const {
    ASSERT(ref_count_ > 0);
    if (--ref_count_ == 0)
      delete this;
  }

  mutable intptr_t ref_count_ = 0;
};

template <typename T, typename U>
inline bool operator==(const U* lhs, const RetainPtr<T>& rhs) {
  return rhs == lhs;
}

template <typename T, typename U>
inline bool operator!=(const U* lhs, const RetainPtr<T>& rhs) {
  return rhs != lhs;
}

}  // namespace fxcrt

using fxcrt::ReleaseDeleter;
using fxcrt::Retainable;
using fxcrt::RetainPtr;

namespace pdfium {

// Helper to make a RetainPtr along the lines of std::make_unique<>().
// Arguments are forwarded to T's constructor. Classes managed by RetainPtr
// should have protected (or private) constructors, and should friend this
// function.
template <typename T, typename... Args>
RetainPtr<T> MakeRetain(Args&&... args) {
  return RetainPtr<T>(new T(std::forward<Args>(args)...));
}

// Type-deducing wrapper to make a RetainPtr from an ordinary pointer.
template <typename T>
RetainPtr<T> WrapRetain(T* that) {
  return RetainPtr<T>(that);
}

}  // namespace pdfium

#endif  // CORE_FXCRT_RETAIN_PTR_H_
