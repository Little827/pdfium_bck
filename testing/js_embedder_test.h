// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_JS_EMBEDDER_TEST_H_
#define TESTING_JS_EMBEDDER_TEST_H_

#include <memory>

#include "testing/embedder_test.h"
#include "v8/include/v8.h"

class JSEmbedderTest : public EmbedderTest {
 public:
  JSEmbedderTest();
  ~JSEmbedderTest() override;

  v8::Isolate* isolate() const;
};

#endif  // TESTING_JS_EMBEDDER_TEST_H_
