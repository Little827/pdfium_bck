// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_GCED_UNITTEST_H_
#define TESTING_GCED_UNITTEST_H_

#include "fxjs/cfx_v8_unittest.h"
#include "fxjs/gc/heap.h"

class GCedUnitTest : public FXV8UnitTest {
 public:
  GCedUnitTest();
  ~GCedUnitTest() override;

  void SetUp() override;
  void TearDown() override;

  cppgc::Heap* heap() const { return heap_.get(); }

 private:
  FXGCScopedHeap heap_;
};

#endif  // TESTING_GCED_UNITTEST_H_
