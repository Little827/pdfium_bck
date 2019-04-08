// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_RETAINED_TREE_NODE_H_
#define CORE_FXCRT_RETAINED_TREE_NODE_H_

#include "core/fxcrt/retain_ptr.h"

namespace fxcrt {

// For DOM/XML-ish trees, where references outside the tree are RetainPtr<T>,
// and the parent node also "retains" its children but doesn't always have
// a direct pointer to them.
class RetainedTreeNode {
 public:
  template <typename T, typename... Args>
  friend RetainPtr<T> pdfium::MakeRetain(Args&&... args);

  RetainedTreeNode* GetParent() const { return m_pParent; }
  RetainedTreeNode* GetFirstChild() const { return m_pFirstChild; }
  RetainedTreeNode* GetLastChild() const { return m_pLastChild; }
  RetainedTreeNode* GetNextSibling() const { return m_pNextSibling; }
  RetainedTreeNode* GetPrevSibling() const { return m_pPrevSibling; }

  void AppendChild(RetainedTreeNode* child) { child->SetParent(this); }
  void InsertBefore(RetainedTreeNode* child, RetainedTreeNode* other_or_null) {}
  void InsertAfter(RetainedTreeNode* child, RetainedTreeNode* other_or_null) {}
  void RemoveChild(RetainedTreeNode* child) { child->SetParent(nullptr); }

 protected:
  RetainedTreeNode() = default;
  virtual ~RetainedTreeNode() = default;

 private:
  template <typename U>
  friend struct ReleaseDeleter;

  template <typename U>
  friend class RetainPtr;

  RetainedTreeNode(const RetainedTreeNode& that) = delete;
  RetainedTreeNode& operator=(const RetainedTreeNode& that) = delete;

  void SetParent(RetainedTreeNode* parent) {
    m_pParent = parent;
    if (m_nRefCount == 0 && !m_pParent)
      delete this;
  }

  void Retain() { ++m_nRefCount; }
  void Release() {
    ASSERT(m_nRefCount > 0);
    if (--m_nRefCount == 0 && !m_pParent)
      delete this;
  }

  intptr_t m_nRefCount = 0;
  RetainedTreeNode* m_pParent = nullptr;       // Raw, intra-tree pointer.
  RetainedTreeNode* m_pFirstChild = nullptr;   // Raw, intra-tree pointer.
  RetainedTreeNode* m_pLastChild = nullptr;    // Raw, intra-tree pointer.
  RetainedTreeNode* m_pNextSibling = nullptr;  // Raw, intra-tree pointer
  RetainedTreeNode* m_pPrevSibling = nullptr;  // Raw, intra-tree pointer
};

}  // namespace fxcrt

using fxcrt::RetainedTreeNode;

#endif  // CORE_FXCRT_RETAINED_TREE_NODE_H_
