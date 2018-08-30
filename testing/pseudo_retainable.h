// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_PSEUDO_RETAINABLE_H_
#define TESTING_PSEUDO_RETAINABLE_H_

class PseudoRetainable {
 public:
  PseudoRetainable() : retain_count_(0), release_count_(0) {}
  void Retain() { ++retain_count_; }
  void Release() { ++release_count_; }
  int retain_count() const { return retain_count_; }
  int release_count() const { return release_count_; }

 private:
  int retain_count_;
  int release_count_;
};

#endif  // TESTING_PSEUDO_RETAINABLE_H_
