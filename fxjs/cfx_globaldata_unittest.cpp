// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/cfx_globaldata.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "testing/test_support.h"

namespace {

class TestDelegate : public CFX_GlobalData::Delegate {
  bool StoreBuffer(const uint8_t* pBuffer, size_t nLength) override {
    return true;
  }
  bool LoadBuffer(uint8_t*& pBuffer, size_t& nLength) override { return true; }
  void BufferDone(uint8_t* pBuffer) override {}
};

}  // namespace

TEST(CFXGlobalData, Bork) {
  TestDelegate delegate;
  CFX_GlobalData* pInstance = CFX_GlobalData::GetRetainedInstance(&delegate);
  ASSERT_TRUE(pInstance->Release());
}
