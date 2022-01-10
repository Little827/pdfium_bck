// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/stringstream_util.h"

#include "testing/gtest/include/gtest/gtest.h"

TEST(StringStreamUtil, OStringStream) {
  fxcrt::ostringstream buf;
  buf << 22 << "C is " << 71.6f << 'F';
  EXPECT_STREQ("22C is 71.6F", buf.str().c_str());
}
