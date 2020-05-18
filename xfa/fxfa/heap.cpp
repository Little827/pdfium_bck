
// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "xfa/fxfa/heap.h"
#include "v8/include/cppgc/heap.h"

namespace {

std::unique_ptr<cppgc::Heap> g_heap;

}  // namespace

ScopedHeap::ScopedHeap() {
  g_heap = cppgc::Heap::Create();
}

ScopedHeap::~ScopedHeap() {
  g_heap.reset();
}

cppgc::Heap* GetHeap() {
  return g_heap.get();
}
