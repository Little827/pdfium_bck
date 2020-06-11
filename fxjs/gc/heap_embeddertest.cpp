// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/gc/heap.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(Heap, Noop) {
  FXGC_Initialize(nullptr);
  FXGC_Release();
  ASSERT_TRUE(1);
}
