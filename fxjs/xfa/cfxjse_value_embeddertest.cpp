// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/xfa/cfxjse_value.h"

#include <memory>
#include <utility>
#include <vector>

#include "fxjs/fxv8.h"
#include "fxjs/xfa/cfxjse_engine.h"
#include "fxjs/xfa/cfxjse_isolatetracker.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/xfa_js_embedder_test.h"

class CFXJSE_ValueEmbedderTest : public XFAJSEmbedderTest {};

TEST_F(CFXJSE_ValueEmbedderTest, Empty) {
  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));

  std::unique_ptr<CFXJSE_Value> pValue;
  {
    CFXJSE_ScopeUtil_IsolateHandle scope(isolate());
    pValue = std::make_unique<CFXJSE_Value>(isolate(), v8::Local<v8::Value>());
  }
  EXPECT_TRUE(pValue->IsEmpty());
  EXPECT_FALSE(pValue->IsUndefined(isolate()));
  EXPECT_FALSE(pValue->IsNull(isolate()));
  EXPECT_FALSE(pValue->IsBoolean(isolate()));
  EXPECT_FALSE(pValue->IsString(isolate()));
}

TEST_F(CFXJSE_ValueEmbedderTest, Undefined) {
  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));

  std::unique_ptr<CFXJSE_Value> pValue;
  {
    CFXJSE_ScopeUtil_IsolateHandle scope(isolate());
    pValue = std::make_unique<CFXJSE_Value>(
        isolate(), fxv8::NewUndefinedHelper(isolate()));
  }
  EXPECT_FALSE(pValue->IsEmpty());
  EXPECT_TRUE(pValue->IsUndefined(isolate()));
  EXPECT_FALSE(pValue->IsNull(isolate()));
  EXPECT_FALSE(pValue->IsBoolean(isolate()));
  EXPECT_FALSE(pValue->IsString(isolate()));
}

TEST_F(CFXJSE_ValueEmbedderTest, Null) {
  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));

  std::unique_ptr<CFXJSE_Value> pValue;
  {
    CFXJSE_ScopeUtil_IsolateHandle scope(isolate());
    pValue = std::make_unique<CFXJSE_Value>(isolate(),
                                            fxv8::NewNullHelper(isolate()));
  }
  EXPECT_FALSE(pValue->IsEmpty());
  EXPECT_FALSE(pValue->IsUndefined(isolate()));
  EXPECT_TRUE(pValue->IsNull(isolate()));
  EXPECT_FALSE(pValue->IsBoolean(isolate()));
  EXPECT_FALSE(pValue->IsString(isolate()));
}

TEST_F(CFXJSE_ValueEmbedderTest, Boolean) {
  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));

  std::unique_ptr<CFXJSE_Value> pValue;
  {
    CFXJSE_ScopeUtil_IsolateHandle scope(isolate());
    pValue = std::make_unique<CFXJSE_Value>(
        isolate(), fxv8::NewBooleanHelper(isolate(), true));
  }
  EXPECT_FALSE(pValue->IsEmpty());
  EXPECT_FALSE(pValue->IsUndefined(isolate()));
  EXPECT_FALSE(pValue->IsNull(isolate()));
  EXPECT_TRUE(pValue->IsBoolean(isolate()));
  EXPECT_FALSE(pValue->IsString(isolate()));
  EXPECT_TRUE(pValue->ToBoolean(isolate()));
}

TEST_F(CFXJSE_ValueEmbedderTest, String) {
  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));

  std::unique_ptr<CFXJSE_Value> pValue;
  {
    CFXJSE_ScopeUtil_IsolateHandle scope(isolate());
    pValue = std::make_unique<CFXJSE_Value>(
        isolate(), fxv8::NewStringHelper(isolate(), "clams"));
  }
  EXPECT_FALSE(pValue->IsEmpty());
  EXPECT_FALSE(pValue->IsUndefined(isolate()));
  EXPECT_FALSE(pValue->IsNull(isolate()));
  EXPECT_FALSE(pValue->IsBoolean(isolate()));
  EXPECT_TRUE(pValue->IsString(isolate()));
  EXPECT_STREQ("clams", pValue->ToByteString(isolate()).c_str());
}
