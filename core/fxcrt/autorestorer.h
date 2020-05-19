// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_AUTORESTORER_H_
#define CORE_FXCRT_AUTORESTORER_H_

namespace fxcrt {

template <typename T>
class AutoRestorer {
 public:
  explicit AutoRestorer(T* location)
      : location_(location), old_value_(*location) {}
  ~AutoRestorer() {
    if (location_)
      *location_ = old_value_;
  }
  void AbandonRestoration() { location_ = nullptr; }

 private:
  T* location_;
  const T old_value_;
};

}  // namespace fxcrt

using fxcrt::AutoRestorer;

#endif  // CORE_FXCRT_AUTORESTORER_H_
