// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/page/cpdf_function.h"

#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fxcrt/retain_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(CPDFFunction, BadFunctionType) {
  auto pDict = pdfium::MakeRetain<CPDF_Dictionary>();
  pDict->SetNewFor<CPDF_Number>("FunctionType", -2);
  EXPECT_EQ(nullptr, CPDF_Function::Load(pDict.Get()));

  pDict->SetNewFor<CPDF_Number>("FunctionType", 5);
  EXPECT_EQ(nullptr, CPDF_Function::Load(pDict.Get()));
}
