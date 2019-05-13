// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/tree_node.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/ptr_util.h"

namespace fxcrt {

class TestTreeNode : public TreeNode<TestTreeNode> {};

// NOTE: Successful cases are covered via RetainedTreeNode tests.
// These tests check that we trip CHECKS given bad calls.

TEST(TreeNode, SelfAppendFirstChild) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  EXPECT_DEATH(pNode->AppendFirstChild(pNode.get()), "");
}

TEST(TreeNode, SelfAppendLastChild) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  EXPECT_DEATH(pNode->AppendLastChild(pNode.get()), "");
}

TEST(TreeNode, SelfInsertBeforeOther) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  auto pOther = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendFirstChild(pOther.get());
  EXPECT_DEATH(pNode->InsertBefore(pNode.get(), pOther.get()), "");
}

TEST(TreeNode, InsertOtherBeforeSelf) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  auto pOther = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendFirstChild(pOther.get());
  EXPECT_DEATH(pNode->InsertBefore(pOther.get(), pNode.get()), "");
}

TEST(TreeNode, SelfInsertAfterOther) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  auto pOther = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendFirstChild(pOther.get());
  EXPECT_DEATH(pNode->InsertBefore(pNode.get(), pOther.get()), "");
}

TEST(TreeNode, InsertOtherAfterSelf) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  auto pOther = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendFirstChild(pOther.get());
  EXPECT_DEATH(pNode->InsertBefore(pOther.get(), pNode.get()), "");
}

TEST(TreeNode, RemoveParentless) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  EXPECT_DEATH(pNode->GetParent()->RemoveChild(pNode.get()), "");
}

TEST(TreeNode, RemoveFromWrongParent) {
  auto pGoodParent = pdfium::MakeUnique<TestTreeNode>();
  auto pBadParent = pdfium::MakeUnique<TestTreeNode>();
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  pGoodParent->AppendFirstChild(pNode.get());
  EXPECT_DEATH(pBadParent->RemoveChild(pNode.get()), "");
}

TEST(TreeNode, SafeRemove) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  auto pOther = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendFirstChild(pOther.get());
  pOther->RemoveSelfIfParented();
  EXPECT_EQ(nullptr, pNode->GetFirstChild());
  EXPECT_EQ(nullptr, pOther->GetParent());
}

TEST(TreeNode, SafeRemoveParentless) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  pNode->RemoveSelfIfParented();
  EXPECT_EQ(nullptr, pNode->GetParent());
}

TEST(TreeNode, RemoveAllChildren) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  pNode->RemoveAllChildren();
  EXPECT_EQ(nullptr, pNode->GetFirstChild());

  auto p0 = pdfium::MakeUnique<TestTreeNode>();
  auto p1 = pdfium::MakeUnique<TestTreeNode>();
  auto p2 = pdfium::MakeUnique<TestTreeNode>();
  auto p3 = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendLastChild(p0.get());
  pNode->AppendLastChild(p1.get());
  pNode->AppendLastChild(p2.get());
  pNode->AppendLastChild(p3.get());
  pNode->RemoveAllChildren();
  EXPECT_EQ(nullptr, pNode->GetFirstChild());
}

TEST(TreeNode, NthChild) {
  auto pNode = pdfium::MakeUnique<TestTreeNode>();
  EXPECT_EQ(nullptr, pNode->GetNthChild(0));

  auto p0 = pdfium::MakeUnique<TestTreeNode>();
  auto p1 = pdfium::MakeUnique<TestTreeNode>();
  auto p2 = pdfium::MakeUnique<TestTreeNode>();
  auto p3 = pdfium::MakeUnique<TestTreeNode>();
  pNode->AppendLastChild(p0.get());
  pNode->AppendLastChild(p1.get());
  pNode->AppendLastChild(p2.get());
  pNode->AppendLastChild(p3.get());
  EXPECT_EQ(p0.get(), pNode->GetNthChild(0));
  EXPECT_EQ(p1.get(), pNode->GetNthChild(1));
  EXPECT_EQ(p2.get(), pNode->GetNthChild(2));
  EXPECT_EQ(p3.get(), pNode->GetNthChild(3));
  EXPECT_EQ(nullptr, pNode->GetNthChild(4));
  pNode->RemoveAllChildren();
}

}  // namespace fxcrt
