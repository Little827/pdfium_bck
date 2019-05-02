// Copyright 2016 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#if defined(WIN32)
#define IMPORT __declspec(dllimport)
#else
#define IMPORT
#endif

extern "C" IMPORT int FUZZER_IMPL(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  return FUZZER_IMPL(data, size);
}
