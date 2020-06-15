// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/gc/heap.h"

#include <memory>
#include <set>

#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/stl_util.h"
#include "v8/include/cppgc/allocation.h"

namespace {

class PseudoCollectable;
std::set<const PseudoCollectable*> s_live_;
std::set<const PseudoCollectable*> s_dead_;

class PseudoCollectable : public cppgc::GarbageCollected<PseudoCollectable> {
 public:
  static void Clear() {
    s_live_.clear();
    s_dead_.clear();
  }
  static size_t LiveCount() { return s_live_.size(); }
  static size_t DeadCount() { return s_dead_.size(); }

  PseudoCollectable() { s_live_.insert(this); }
  virtual ~PseudoCollectable() {
    s_live_.erase(this);
    s_dead_.insert(this);
  }

  bool IsLive() const { return pdfium::Contains(s_live_, this); }

  virtual void Trace(cppgc::Visitor*) const {}
};

}  // namespace

class HeapEmbedderTest : public EmbedderTest {};

TEST_F(HeapEmbedderTest, SeveralHeaps) {
  FXGCScopedHeap heap1 = FXGC_CreateHeap();
  EXPECT_TRUE(heap1);

  FXGCScopedHeap heap2 = FXGC_CreateHeap();
  EXPECT_TRUE(heap2);

  FXGCScopedHeap heap3 = FXGC_CreateHeap();
  EXPECT_TRUE(heap2);
}

TEST_F(HeapEmbedderTest, NoReferences) {
  FXGCScopedHeap heap1 = FXGC_CreateHeap();
  ASSERT_TRUE(heap1);

  PseudoCollectable* p =
      cppgc::MakeGarbageCollected<PseudoCollectable>(heap1.get());
  EXPECT_TRUE(p->IsLive());
  EXPECT_EQ(1u, PseudoCollectable::LiveCount());
  EXPECT_EQ(0u, PseudoCollectable::DeadCount());

  p = nullptr;
  heap1->ForceGarbageCollectionSlow("HeapEmbedderTest.NoReferences", "test");
  EXPECT_EQ(0u, PseudoCollectable::LiveCount());
  EXPECT_EQ(1u, PseudoCollectable::DeadCount());
}
