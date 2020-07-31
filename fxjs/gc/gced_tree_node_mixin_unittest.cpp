// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/gc/gced_tree_node_mixin.h"

#include <map>

#include "core/fxcrt/observed_ptr.h"
#include "fxjs/gc/heap.h"
#include "testing/fxgc_unittest.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/v8_test_environment.h"
#include "third_party/base/stl_util.h"
#include "v8/include/cppgc/allocation.h"
#include "v8/include/cppgc/persistent.h"

namespace {

class ObservableGCedTreeNodeForTest
    : public cppgc::GarbageCollected<ObservableGCedTreeNodeForTest>,
      public GCedTreeNodeMixin<ObservableGCedTreeNodeForTest>,
      public Observable {
 public:
  CONSTRUCT_VIA_MAKE_GARBAGE_COLLECTED;
  void Trace(cppgc::Visitor* visitor) const override {
    GCedTreeNodeMixin<ObservableGCedTreeNodeForTest>::Trace(visitor);
  }

 private:
  ObservableGCedTreeNodeForTest() = default;
};

}  // namespace

class GCedTreeNodeMixinUnitTest : public FXGCUnitTest {
 public:
  static cppgc::Persistent<ObservableGCedTreeNodeForTest> s_root;

  GCedTreeNodeMixinUnitTest() = default;
  ~GCedTreeNodeMixinUnitTest() override = default;

  // FXGCUnitTest:
  void TearDown() override {
    s_root = nullptr;  // Can't (yet) outlive |heap_|.
    FXGCUnitTest::TearDown();
  }

  ObservableGCedTreeNodeForTest* CreateNode() {
    return cppgc::MakeGarbageCollected<ObservableGCedTreeNodeForTest>(
        heap()->GetAllocationHandle());
  }

  void ForceGCAndPump() {
    FXGC_ForceGarbageCollection(heap());
    V8TestEnvironment::PumpPlatformMessageLoop(isolate());
  }

  void AddClutterToFront(ObservableGCedTreeNodeForTest* parent) {
    for (int i = 0; i < 4; ++i) {
      parent->AppendFirstChild(
          cppgc::MakeGarbageCollected<ObservableGCedTreeNodeForTest>(
              heap()->GetAllocationHandle()));
    }
  }

  void AddClutterToBack(ObservableGCedTreeNodeForTest* parent) {
    for (int i = 0; i < 4; ++i) {
      parent->AppendLastChild(
          cppgc::MakeGarbageCollected<ObservableGCedTreeNodeForTest>(
              heap()->GetAllocationHandle()));
    }
  }

 private:
  FXGCScopedHeap heap_;
};

cppgc::Persistent<ObservableGCedTreeNodeForTest>
    GCedTreeNodeMixinUnitTest::s_root;

TEST_F(GCedTreeNodeMixinUnitTest, OneRefence) {
  s_root = CreateNode();
  ObservedPtr<ObservableGCedTreeNodeForTest> watcher(s_root);
  ForceGCAndPump();
  EXPECT_TRUE(watcher);
}

TEST_F(GCedTreeNodeMixinUnitTest, NoReferences) {
  ObservedPtr<ObservableGCedTreeNodeForTest> watcher(CreateNode());
  ForceGCAndPump();
  EXPECT_FALSE(watcher);
}

TEST_F(GCedTreeNodeMixinUnitTest, FirstHasParent) {
  s_root = CreateNode();
  ObservedPtr<ObservableGCedTreeNodeForTest> watcher(CreateNode());
  s_root->AppendFirstChild(watcher.Get());
  ForceGCAndPump();
  ASSERT_TRUE(s_root);
  EXPECT_TRUE(watcher);
  s_root->RemoveChild(watcher.Get());
  ForceGCAndPump();
  ASSERT_TRUE(s_root);
  EXPECT_FALSE(watcher);

  // Now add some clutter.
  watcher.Reset(CreateNode());
  s_root->AppendFirstChild(watcher.Get());
  AddClutterToFront(s_root);
  AddClutterToBack(s_root);
  ForceGCAndPump();
  ASSERT_TRUE(s_root);
  EXPECT_TRUE(watcher);
  s_root->RemoveChild(watcher.Get());
  ForceGCAndPump();
  EXPECT_TRUE(s_root);
  EXPECT_FALSE(watcher);
}

TEST_F(GCedTreeNodeMixinUnitTest, RemoveSelf) {
  s_root = CreateNode();
  ObservedPtr<ObservableGCedTreeNodeForTest> watcher(CreateNode());
  s_root->AppendFirstChild(watcher.Get());
  ForceGCAndPump();
  EXPECT_TRUE(s_root);
  ASSERT_TRUE(watcher);
  watcher->RemoveSelfIfParented();
  ForceGCAndPump();
  EXPECT_TRUE(s_root);
  EXPECT_FALSE(watcher);
}

TEST_F(GCedTreeNodeMixinUnitTest, InsertBeforeAfter) {
  s_root = CreateNode();
  AddClutterToFront(s_root);
  ObservedPtr<ObservableGCedTreeNodeForTest> watcher(CreateNode());
  s_root->AppendFirstChild(watcher.Get());
  s_root->InsertBefore(s_root->GetFirstChild(), s_root->GetLastChild());
  s_root->InsertAfter(s_root->GetLastChild(), s_root->GetFirstChild());
  ForceGCAndPump();
  ASSERT_TRUE(s_root);
  EXPECT_TRUE(watcher);
  s_root->RemoveChild(watcher.Get());
  ForceGCAndPump();
  EXPECT_TRUE(s_root);
  EXPECT_FALSE(watcher);
}

TEST_F(GCedTreeNodeMixinUnitTest, AsMapKey) {
  std::map<cppgc::Persistent<ObservableGCedTreeNodeForTest>, int> score;
  ObservableGCedTreeNodeForTest* node = CreateNode();
  score[node] = 100;
  EXPECT_EQ(100, score[node]);
}
