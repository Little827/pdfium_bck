// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdfview.h"

// INIT_FUNC is a macro defined at build time that contains the name of the
// real initialize function.
FPDF_EXPORT void INIT_FUNC();

// Initialize the library once for all runs of the fuzzer.
struct TestCase {
  TestCase() { INIT_FUNC(); }
};

static TestCase* g_test_cast = new TestCase();
