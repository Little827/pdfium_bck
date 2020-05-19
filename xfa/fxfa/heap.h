// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef XFA_FXFA_HEAP_H_
#define XFA_FXFA_HEAP_H_

#include "v8/include/cppgc/allocation.h"
#include "v8/include/cppgc/garbage-collected.h"
#include "v8/include/cppgc/heap.h"
#include "v8/include/cppgc/member.h"
#include "v8/include/cppgc/persistent.h"

class ScopedHeap {
 public:
  ScopedHeap();
  virtual ~ScopedHeap();
};

cppgc::Heap* GetHeap();

template <typename T, typename... Args>
T* MakeGarbageCollected(Args&&... args) {
  return cppgc::MakeGarbageCollected<T>(GetHeap(), std::forward<Args>(args)...);
}

#endif  // XFA_FXFA_HEAP_H_
