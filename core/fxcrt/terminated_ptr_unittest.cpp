// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/terminated_ptr.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace fxcrt {

TEST(TerminatedPtr, Empty) {
  TerminatedPtr<char> empty;
  EXPECT_EQ(nullptr, empty.get());
  EXPECT_DEATH((++empty), "");

  TerminatedPtr<char> blank = "";
  EXPECT_NE(nullptr, blank.get());
  EXPECT_DEATH((++blank), "");
}

TEST(TerminatedPtr, CharPtr) {
  TerminatedPtr<char> boo = "boo";
  EXPECT_EQ('b', *boo++);
  EXPECT_EQ('o', *boo++);
  EXPECT_EQ('o', *boo++);
  EXPECT_EQ('\0', *boo);
  EXPECT_DEATH((boo++), "");
}

TEST(TerminatedPtr, WidePtr) {
  TerminatedPtr<wchar_t> boo = L"boo";
  EXPECT_EQ(L'b', *boo++);
  EXPECT_EQ(L'o', *boo++);
  EXPECT_EQ(L'o', *boo++);
  EXPECT_EQ(L'\0', *boo);
  EXPECT_DEATH((boo++), "");
}

TEST(TerminatedPtr, PointerPtrs) {
  const char* const kPointers[] = {"off", "on", nullptr};
  TerminatedPtr<const char*> ptr = kPointers;
  EXPECT_NE(nullptr, *ptr++);
  EXPECT_NE(nullptr, *ptr++);
  EXPECT_EQ(nullptr, *ptr);
  EXPECT_DEATH((ptr++), "");
}

}  // namespace fxcrt
