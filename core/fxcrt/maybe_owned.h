// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_MAYBE_OWNED_H_
#define CORE_FXCRT_MAYBE_OWNED_H_

#include <memory>
#include <utility>

#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/unowned_ptr.h"

namespace fxcrt {

// A template that can hold either owned or unowned references, and cleans up
// appropriately.  Possibly the most pernicious anti-pattern imaginable, but
// it crops up throughout the codebase due to a desire to avoid copying-in
// objects or data.
template <typename T, typename D = std::default_delete<T>>
class MaybeOwned {
 public:
  MaybeOwned() = default;
  explicit MaybeOwned(T* ptr) : obj_(ptr) {}
  explicit MaybeOwned(const UnownedPtr<T>& ptr) : obj_(ptr.Get()) {}
  explicit MaybeOwned(std::unique_ptr<T, D> ptr)
      : owned_obj_(std::move(ptr)), obj_(owned_obj_.get()) {}

  MaybeOwned(const MaybeOwned& that) = delete;
  MaybeOwned(MaybeOwned&& that) noexcept
      : owned_obj_(that.owned_obj_.release()), obj_(that.obj_) {
    that.obj_ = nullptr;
  }

  void Reset(std::unique_ptr<T, D> ptr) {
    obj_ = ptr.get();
    owned_obj_ = std::move(ptr);
  }
  void Reset(T* ptr = nullptr) {
    obj_ = ptr;
    owned_obj_.reset();
  }
  // Helpful for untangling a collection of intertwined MaybeOwned<>.
  void ResetIfUnowned() {
    if (!IsOwned())
      Reset();
  }

  T* Get() const { return obj_.Get(); }
  bool IsOwned() const { return !!owned_obj_; }

  // Downgrades to unowned, caller takes ownership.
  std::unique_ptr<T, D> Release() {
    ASSERT(IsOwned());
    return std::move(owned_obj_);
  }

  // Downgrades to empty, caller takes ownership.
  std::unique_ptr<T, D> ReleaseAndClear() {
    ASSERT(IsOwned());
    obj_ = nullptr;
    return std::move(owned_obj_);
  }

  MaybeOwned& operator=(const MaybeOwned& that) = delete;
  MaybeOwned& operator=(MaybeOwned&& that) {
    obj_ = that.obj_;
    owned_obj_ = std::move(that.owned_obj_);
    that.obj_ = nullptr;
    return *this;
  }
  MaybeOwned& operator=(T* ptr) {
    Reset(ptr);
    return *this;
  }
  MaybeOwned& operator=(const UnownedPtr<T>& ptr) {
    Reset(ptr.Get());
    return *this;
  }
  MaybeOwned& operator=(std::unique_ptr<T, D> ptr) {
    Reset(std::move(ptr));
    return *this;
  }

  bool operator==(const MaybeOwned& that) const { return Get() == that.Get(); }
  bool operator==(const std::unique_ptr<T, D>& ptr) const {
    return Get() == ptr.get();
  }
  bool operator==(T* ptr) const { return Get() == ptr; }

  bool operator!=(const MaybeOwned& that) const { return !(*this == that); }
  bool operator!=(const std::unique_ptr<T, D> ptr) const {
    return !(*this == ptr);
  }
  bool operator!=(T* ptr) const { return !(*this == ptr); }

  explicit operator bool() const { return !!obj_; }
  T& operator*() const { return *obj_; }
  T* operator->() const { return obj_.Get(); }

 private:
  std::unique_ptr<T, D> owned_obj_;
  UnownedPtr<T> obj_;
};

}  // namespace fxcrt

using fxcrt::MaybeOwned;

#endif  // CORE_FXCRT_MAYBE_OWNED_H_
