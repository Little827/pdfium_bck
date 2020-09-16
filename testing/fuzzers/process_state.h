// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PROCESS_STATE_H_
#define TESTING_FUZZERS_PROCESS_STATE_H_

#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
#include "fxjs/gc/heap.h"
#endif

namespace v8 {
class Isolate;
class Platform;
}  // namespace v8

class ProcessState {
 public:
#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
  ProcessState(v8::Platform* platform, v8::Isolate* isolate);
#else
  ProcessState();
#endif
  ~ProcessState();

#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
  cppgc::Heap* GetHeap() const;
  void MaybeForceGCAndPump();
#endif

 private:
#if defined(PDF_ENABLE_V8) && defined(PDF_ENABLE_XFA)
  v8::Platform* const platform_;
  v8::Isolate* const isolate_;
  int iterations_ = 0;
  FXGCScopedHeap heap_;
#endif
};

#endif  // TESTING_FUZZERS_PROCESS_STATE_H_
