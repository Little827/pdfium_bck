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

  TerminatedPtr<char> blank = TerminatedPtr<char>::Create("");
  EXPECT_NE(nullptr, blank.get());
  EXPECT_DEATH((++blank), "");
}

TEST(TerminatedPtr, Normal) {
  TerminatedPtr<char> boo = TerminatedPtr<char>::Create("boo");
  EXPECT_EQ('b', *boo++);
  EXPECT_EQ('o', *boo++);
  EXPECT_EQ('o', *boo++);
  EXPECT_EQ('\0', *boo);
  EXPECT_DEATH((boo++), "");

  const wchar_t* ptr = L"that";
  auto that = UNSAFE_BUFFERS(TerminatedPtr<wchar_t>::Create(ptr));
  that = UNSAFE_BUFFERS(TerminatedPtr<wchar_t>::Create(ptr));
}

TEST(TerminatedPtr, PointerPtrs) {
  const char* const kPointers[] = {"off", "on", nullptr};
  auto ptr = TerminatedPtr<const char*>::Create(kPointers);
  EXPECT_NE(nullptr, *ptr++);
  EXPECT_NE(nullptr, *ptr++);
  EXPECT_EQ(nullptr, *ptr);
  EXPECT_DEATH((ptr++), "");
}

}  // namespace fxcrt
