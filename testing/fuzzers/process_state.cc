// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/fuzzers/process_state.h"

#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
ProcessState::ProcessState(v8::Platform* platform, v8::Isolate* isolate)
    : platform_(platform), isolate_(isolate) {}
#else
ProcessState::ProcessState() = default;
#endif

ProcessState::~ProcessState() = default;

#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
cppgc::Heap* ProcessState::GetHeap() const {
  return heap_.get();
}

void ProcessState::MaybeForceGCAndPump() {
  if (++iterations_ > 1000) {
    FXGC_ForceGarbageCollection(heap_.get());
    iterations_ = 0;
  }
  while (v8::platform::PumpMessageLoop(platform_, isolate_))
    continue;
}
#endif
