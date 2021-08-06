// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/mask.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace fxcrt {
namespace {

enum class Privilege : uint8_t {
  kDriving = 1 << 0,
  kScubaDiving = 1 << 1,
  kStayingUpLate = 1 << 2,
};

const Mask<Privilege> kAllMask = {
    Privilege::kDriving,
    Privilege::kScubaDiving,
    Privilege::kStayingUpLate,
};

}  // namespace

static_assert(sizeof(Mask<Privilege>) == sizeof(Privilege),
              "Mask size must be the same as enum");

TEST(Mask, Empty) {
  constexpr Mask<Privilege> privs;
  EXPECT_EQ(0u, privs.Value());
  EXPECT_FALSE(privs & Privilege::kDriving);
  EXPECT_FALSE(privs & Privilege::kScubaDiving);
  EXPECT_FALSE(privs & Privilege::kStayingUpLate);
  EXPECT_FALSE(privs & kAllMask);
}

TEST(Mask, FromOne) {
  Mask<Privilege> privs = Privilege::kDriving;
  EXPECT_EQ(1u, privs.Value());
  EXPECT_TRUE(privs & Privilege::kDriving);
  EXPECT_FALSE(privs & Privilege::kScubaDiving);
  EXPECT_FALSE(privs & Privilege::kStayingUpLate);
  EXPECT_TRUE(privs & kAllMask);
}

TEST(Mask, FromMany) {
  Mask<Privilege> privs = {Privilege::kDriving, Privilege::kStayingUpLate};
  EXPECT_EQ(5u, privs.Value());
  EXPECT_TRUE(privs & Privilege::kDriving);
  EXPECT_FALSE(privs & Privilege::kScubaDiving);
  EXPECT_TRUE(privs & Privilege::kStayingUpLate);
  EXPECT_TRUE(privs & kAllMask);
}

TEST(Mask, AssignAndEQ) {
  Mask<Privilege> source = {Privilege::kDriving, Privilege::kStayingUpLate};
  Mask<Privilege> other = Privilege::kDriving;
  Mask<Privilege> dest;
  dest = source;
  EXPECT_EQ(5u, dest.Value());
  EXPECT_EQ(source, dest);
  EXPECT_NE(other, dest);
}

TEST(Mask, OrAndAnd) {
  Mask<Privilege> source = {Privilege::kDriving, Privilege::kStayingUpLate};
  Mask<Privilege> or_result =
      source | Mask<Privilege>{Privilege::kDriving, Privilege::kScubaDiving};
  Mask<Privilege> and_result =
      source & Mask<Privilege>{Privilege::kDriving, Privilege::kScubaDiving};
  EXPECT_EQ(or_result, kAllMask);
  EXPECT_EQ(and_result, Privilege::kDriving);
}

TEST(Mask, OrEqualsAndAndEquals) {
  Mask<Privilege> source_or = {Privilege::kDriving, Privilege::kStayingUpLate};
  Mask<Privilege> source_and = {Privilege::kDriving, Privilege::kStayingUpLate};
  source_or |= {Privilege::kDriving, Privilege::kScubaDiving};
  source_and &= {Privilege::kDriving, Privilege::kScubaDiving};
  EXPECT_EQ(source_or, kAllMask);
  EXPECT_EQ(source_and, Privilege::kDriving);
}

TEST(Mask, Clear) {
  Mask<Privilege> source = kAllMask;
  source.Clear({Privilege::kDriving, Privilege::kScubaDiving});
  EXPECT_EQ(source, Privilege::kStayingUpLate);
}

}  // namespace fxcrt
