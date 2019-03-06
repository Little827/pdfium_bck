// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_BORROW_H_
#define CORE_FXCRT_BORROW_H_

#include <memory>
#include <utility>

namespace fxcrt {

template <typename T, typename D>
class BorrowRestorer {
 public:
  BorrowRestorer(std::unique_ptr<T, D>* ref)
      : old_(ref), val_(std::move(*old_)) {}
  BorrowRestorer(BorrowRestorer&& that) = default;
  BorrowRestorer(const BorrowRestorer& that) = delete;
  ~BorrowRestorer() { *old_ = std::move(val_); }

  // Deliberatley implict.
  operator T*() { return val_.get(); }

 private:
  std::unique_ptr<T, D>* old_;
  std::unique_ptr<T, D> val_;
};

template <typename T, typename D>
BorrowRestorer<T, D> Borrow(std::unique_ptr<T, D>* ref) {
  return BorrowRestorer<T, D>(ref);
}

}  // namespace fxcrt

using fxcrt::Borrow;

#endif  // CORE_FXCRT_BORROW_H_
