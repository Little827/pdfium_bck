// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fpdfsdk/cpdfsdk_helpers.h"

#include "testing/gtest/include/gtest/gtest.h"

TEST(CPDFSDK_HelpersTest, NulTerminateMaybeCopyAndReturnLength) {
  {
    const ByteString to_be_copied("toBeCopied");
    constexpr size_t kExpectedToBeCopiedLen = 10;
    ASSERT_EQ(kExpectedToBeCopiedLen, to_be_copied.GetLength());

    // Null buffer should not change.
    void* null_buf = nullptr;
    EXPECT_EQ(kExpectedToBeCopiedLen + 1,
              NulTerminateMaybeCopyAndReturnLength(to_be_copied, null_buf, 0));

    // Null buffer should not change even when declared buffer length is long
    // enough.
    EXPECT_FALSE(null_buf);
    EXPECT_EQ(kExpectedToBeCopiedLen + 1,
              NulTerminateMaybeCopyAndReturnLength(to_be_copied, null_buf,
                                                   kExpectedToBeCopiedLen + 1));
    EXPECT_FALSE(null_buf);

    // Buffer should not change if too short.
    char just_too_short_buf[kExpectedToBeCopiedLen];
    memset(just_too_short_buf, 0, kExpectedToBeCopiedLen);
    ASSERT_EQ(kExpectedToBeCopiedLen + 1,
              NulTerminateMaybeCopyAndReturnLength(
                  to_be_copied, just_too_short_buf, kExpectedToBeCopiedLen));
    EXPECT_EQ(ByteString(), ByteString(just_too_short_buf));

    // Buffer should copy over if long enough.
    char good_buf[kExpectedToBeCopiedLen + 1];
    memset(good_buf, 0, kExpectedToBeCopiedLen + 1);
    ASSERT_EQ(kExpectedToBeCopiedLen + 1,
              NulTerminateMaybeCopyAndReturnLength(to_be_copied, good_buf,
                                                   kExpectedToBeCopiedLen + 1));
    EXPECT_EQ(to_be_copied, ByteString(good_buf));
  }
  {
    // Empty ByteString should still copy NUL terminator.
    const ByteString empty;
    char buf[1];
    ASSERT_EQ(1u, NulTerminateMaybeCopyAndReturnLength(empty, buf, 1));
    EXPECT_EQ(empty, ByteString(buf));
  }
}
