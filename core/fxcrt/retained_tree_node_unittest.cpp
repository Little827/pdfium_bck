// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/retained_tree_node.h"

#include <utility>
#include <vector>

#include "core/fxcrt/observable.h"
#include "core/fxcrt/retain_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace fxcrt {
namespace {

class ObservableRetainedTreeNodeForTest
    : public RetainedTreeNode<ObservableRetainedTreeNodeForTest>,
      public Observable<ObservableRetainedTreeNodeForTest> {
 public:
  template <typename T, typename... Args>
  friend RetainPtr<T> pdfium::MakeRetain(Args&&... args);

 private:
  ObservableRetainedTreeNodeForTest() = default;
};

}  // namespace

TEST(RetainedTreeNode, NoParent) {
  ObservableRetainedTreeNodeForTest::ObservedPtr watcher;
  {
    RetainPtr<ObservableRetainedTreeNodeForTest> ptr =
        pdfium::MakeRetain<ObservableRetainedTreeNodeForTest>();
    watcher = ObservableRetainedTreeNodeForTest::ObservedPtr(ptr.Get());
    EXPECT_TRUE(watcher.Get());
  }
  EXPECT_FALSE(watcher.Get());
}

TEST(RetainedTreeNode, HasParent) {
  ObservableRetainedTreeNodeForTest::ObservedPtr watcher;
  RetainPtr<ObservableRetainedTreeNodeForTest> parent =
      pdfium::MakeRetain<ObservableRetainedTreeNodeForTest>();
  {
    RetainPtr<ObservableRetainedTreeNodeForTest> ptr =
        pdfium::MakeRetain<ObservableRetainedTreeNodeForTest>();
    watcher = ObservableRetainedTreeNodeForTest::ObservedPtr(ptr.Get());
    parent->AppendLastChild(std::move(ptr));
    EXPECT_TRUE(watcher.Get());
  }
  EXPECT_TRUE(watcher.Get());
  parent->RemoveChild(pdfium::WrapRetain(watcher.Get()));
  EXPECT_FALSE(watcher.Get());
}

}  // namespace fxcrt
