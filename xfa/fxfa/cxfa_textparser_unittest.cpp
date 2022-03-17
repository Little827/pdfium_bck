// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "xfa/fxfa/cxfa_textparser.h"

#include "fxjs/gc/heap.h"
#include "testing/fxgc_unittest.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "v8/include/cppgc/heap.h"

class CXFA_TestTextParser final : public CXFA_TextParser {
 public:
  CONSTRUCT_VIA_MAKE_GARBAGE_COLLECTED;

 private:
  CXFA_TestTextParser() = default;

  // Add test cases as friends to access protected member functions.
  FRIEND_TEST(CXFATextParserTest, TagValidate);
};

class CXFATextParserTest : public FXGCUnitTest {};

TEST_F(CXFATextParserTest, TagValidate) {
  auto* parser = cppgc::MakeGarbageCollected<CXFA_TestTextParser>(
      heap()->GetAllocationHandle());
  EXPECT_TRUE(parser->TagValidate(WideString(L"br")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"Br")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"BR")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"a")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"b")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"i")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"p")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"li")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"ol")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"ul")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"sub")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"sup")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"span")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"body")));
  EXPECT_TRUE(parser->TagValidate(WideString(L"html")));

  EXPECT_FALSE(parser->TagValidate(WideString(L"")));
  EXPECT_FALSE(parser->TagValidate(WideString(L"tml")));
  EXPECT_FALSE(parser->TagValidate(WideString(L"xhtml")));
  EXPECT_FALSE(parser->TagValidate(WideString(L"htmlx")));
}
