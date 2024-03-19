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

  const char* ptr = "that";  // No longer a literal after assignment,
  auto that = UNSAFE_BUFFERS(TerminatedPtr<char>::Create(ptr));
  boo = that;
  EXPECT_EQ('t', *boo++);
  EXPECT_EQ('h', *boo++);
  EXPECT_EQ('a', *boo++);
  EXPECT_EQ('t', *boo++);
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

  const wchar_t* ptr = L"that";  // No longer a literal after assignment,
  auto that = UNSAFE_BUFFERS(TerminatedPtr<wchar_t>::Create(ptr));
  boo = that;
  EXPECT_EQ(L't', *boo++);
  EXPECT_EQ(L'h', *boo++);
  EXPECT_EQ(L'a', *boo++);
  EXPECT_EQ(L't', *boo++);
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
