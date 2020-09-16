// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PROCESS_STATE_H_
#define TESTING_FUZZERS_PROCESS_STATE_H_

#ifdef PDF_ENABLE_V8
#ifdef PDF_ENABLE_XFA
#include "fxjs/gc/heap.h"
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8

namespace v8 {
class Isolate;
class Platform;
}  // namespace v8

class ProcessState {
 public:
#ifdef PDF_ENABLE_V8
  ProcessState(v8::Platform* platform, v8::Isolate* isolate);
#else
  ProcessState();
#endif
  ~ProcessState();

#ifdef PDF_ENABLE_V8
#ifdef PDF_ENABLE_XFA
  cppgc::Heap* GetHeap() const;
  void MaybeForceGCAndPump();
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8

 private:
#ifdef PDF_ENABLE_V8
  v8::Platform* const platform_;
  v8::Isolate* const isolate_;
#ifdef PDF_ENABLE_XFA
  int iterations_ = 0;
  FXGCScopedHeap heap_;
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8
};

#endif  // TESTING_FUZZERS_PROCESS_STATE_H_
