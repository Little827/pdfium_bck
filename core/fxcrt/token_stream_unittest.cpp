// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/token_stream.h"

#include <sstream>

#include "core/fxcrt/fx_coordinates.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(TokenStream, SimpleTypes) {
  std::ostringstream oss;
  TokenStream ts(&oss);

  (ts << 10 << 20.5f << "clams" << 42).NormalStream() << "px";
  EXPECT_EQ("10 20.5 clams 42px", oss.str());
}

TEST(TokenStream, Points) {
  std::ostringstream oss;
  TokenStream ts(&oss);

  CFX_PointF pt(10.5f, 20.5f);
  ts << pt << pt;
  EXPECT_EQ("10.5 20.5 10.5 20.5", oss.str());
}

TEST(TokenStream, Matrix) {
  std::ostringstream oss;
  TokenStream ts(&oss);

  CFX_Matrix mx(10.5f, 20.5f, 30.5, 40.5, 50.5, 60.5);
  ts << mx << mx;
  EXPECT_EQ("10.5 20.5 30.5 40.5 50.5 60.5 10.5 20.5 30.5 40.5 50.5 60.5",
            oss.str());
}

TEST(TokenStream, Separator) {
  std::ostringstream oss;
  TokenStream ts(&oss);
  ts.SetSeparator("--");

  ts << CFX_Matrix(10.5f, 20.5f, 30.5, 40.5, 50.5, 60.5);
  EXPECT_EQ("10.5--20.5--30.5--40.5--50.5--60.5", oss.str());
}
