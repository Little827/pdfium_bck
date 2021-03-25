// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/scoped_set_tz.h"

#include <stdlib.h>
#include <time.h>

#include "third_party/base/check_op.h"

namespace {

constexpr char kTZ[] = "TZ";

}  // namespace

ScopedSetTZ::ScopedSetTZ(const std::string& tz) {
  const char* old_tz = getenv(kTZ);
  old_tz_set_ = old_tz;
  if (old_tz_set_)
    old_tz_ = old_tz;

  CHECK_EQ(0, setenv(kTZ, tz.c_str(), 1));
  tzset();
}

ScopedSetTZ::~ScopedSetTZ() {
  if (old_tz_set_)
    CHECK_EQ(0, setenv(kTZ, old_tz_.c_str(), 1));
  else
    CHECK_EQ(0, unsetenv(kTZ));
  tzset();
}
