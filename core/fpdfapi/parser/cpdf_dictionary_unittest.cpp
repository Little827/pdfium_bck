// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_dictionary.h"

#include <utility>

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(DictionaryTest, LockerGetters) {
  auto dict = pdfium::MakeRetain<CPDF_Dictionary>();
  dict->SetNewFor<CPDF_Dictionary>("A");
  dict->SetNewFor<CPDF_Array>("B");
  dict->SetNewFor<CPDF_Stream>("C");
  dict->SetNewFor<CPDF_Number>("D", 42);

  CPDF_DictionaryLocker locked_dict(std::move(dict));
  EXPECT_TRUE(locked_dict.GetObjectFor("A"));
  EXPECT_FALSE(locked_dict.GetArrayFor("A"));
  EXPECT_TRUE(locked_dict.GetDictFor("A"));
  EXPECT_FALSE(locked_dict.GetStreamFor("A"));
  EXPECT_FALSE(locked_dict.GetNumberFor("A"));

  EXPECT_TRUE(locked_dict.GetObjectFor("B"));
  EXPECT_TRUE(locked_dict.GetArrayFor("B"));
  EXPECT_FALSE(locked_dict.GetDictFor("B"));
  EXPECT_FALSE(locked_dict.GetStreamFor("B"));
  EXPECT_FALSE(locked_dict.GetNumberFor("B"));

  EXPECT_TRUE(locked_dict.GetObjectFor("C"));
  EXPECT_FALSE(locked_dict.GetArrayFor("C"));
  EXPECT_FALSE(locked_dict.GetDictFor("C"));
  EXPECT_TRUE(locked_dict.GetStreamFor("C"));
  EXPECT_FALSE(locked_dict.GetNumberFor("C"));

  EXPECT_TRUE(locked_dict.GetObjectFor("D"));
  EXPECT_FALSE(locked_dict.GetArrayFor("D"));
  EXPECT_FALSE(locked_dict.GetDictFor("D"));
  EXPECT_FALSE(locked_dict.GetStreamFor("D"));
  EXPECT_TRUE(locked_dict.GetNumberFor("D"));

  EXPECT_FALSE(locked_dict.GetObjectFor("nonesuch"));
  EXPECT_FALSE(locked_dict.GetArrayFor("nonesuch"));
  EXPECT_FALSE(locked_dict.GetDictFor("nonesuch"));
  EXPECT_FALSE(locked_dict.GetStreamFor("nonesuch"));
  EXPECT_FALSE(locked_dict.GetNumberFor("nonesuch"));
}
