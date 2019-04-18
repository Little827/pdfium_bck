// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_LAYOUT_CXFA_LAYOUTITEM_H_
#define XFA_FXFA_LAYOUT_CXFA_LAYOUTITEM_H_

#include "core/fxcrt/unowned_ptr.h"
#include "xfa/fxfa/parser/cxfa_document.h"

class CXFA_ContentLayoutItem;
class CXFA_LayoutProcessor;
class CXFA_ViewLayoutItem;

class CXFA_LayoutItem {
 public:
  virtual ~CXFA_LayoutItem();

  bool IsViewLayoutItem() const { return m_ItemType == kViewItem; }
  bool IsContentLayoutItem() const { return m_ItemType == kContentItem; }
  CXFA_ViewLayoutItem* AsViewLayoutItem();
  const CXFA_ViewLayoutItem* AsViewLayoutItem() const;
  CXFA_ContentLayoutItem* AsContentLayoutItem();
  const CXFA_ContentLayoutItem* AsContentLayoutItem() const;

  CXFA_ViewLayoutItem* GetPage() const;
  CXFA_Node* GetFormNode() const { return m_pFormNode.Get(); }
  void SetFormNode(CXFA_Node* pNode) { m_pFormNode = pNode; }

  // Scaffolding, to be replaced by retained version.
  CXFA_LayoutItem* GetParent() const { return m_pParent; }
  CXFA_LayoutItem* GetFirstChild() const { return m_pFirstChild; }
  CXFA_LayoutItem* GetLastChild() const { return m_pFirstChild; }
  CXFA_LayoutItem* GetNextSibling() const { return m_pNextSibling; }
  CXFA_LayoutItem* GetPrevSibling() const { return m_pNextSibling; }

  void AppendFirstChild(CXFA_LayoutItem* child) {
    BecomeParent(child);
    if (m_pFirstChild) {
      m_pFirstChild->m_pPrevSibling = child;
      child->m_pNextSibling = m_pFirstChild;
      m_pFirstChild = child;
    } else {
      m_pFirstChild = child;
      m_pLastChild = child;
    }
  }

  void AppendLastChild(CXFA_LayoutItem* child) {
    BecomeParent(child);
    if (m_pLastChild) {
      m_pLastChild->m_pNextSibling = child;
      child->m_pPrevSibling = m_pLastChild;
      m_pLastChild = child;
    } else {
      m_pFirstChild = child;
      m_pLastChild = child;
    }
  }

  void InsertBefore(CXFA_LayoutItem* child, CXFA_LayoutItem* other) {
    if (!other) {
      AppendLastChild(child);
      return;
    }
    CHECK(other->m_pParent == this);
    BecomeParent(child);
    child->m_pNextSibling = other;
    child->m_pPrevSibling = other->m_pPrevSibling;
    if (other->m_pPrevSibling)
      other->m_pPrevSibling->m_pNextSibling = child;
    else
      m_pFirstChild = child;
    other->m_pPrevSibling = child;
  }

  void InsertAfter(CXFA_LayoutItem* child, CXFA_LayoutItem* other) {
    if (!other) {
      AppendFirstChild(child);
      return;
    }
    CHECK(other->m_pParent == this);
    BecomeParent(child);
    child->m_pNextSibling = other->m_pNextSibling;
    child->m_pPrevSibling = other;
    if (other->m_pNextSibling)
      other->m_pNextSibling->m_pPrevSibling = child;
    else
      m_pLastChild = child;
    other->m_pNextSibling = child;
  }

  void RemoveChild(CXFA_LayoutItem* child) {
    CHECK(child->m_pParent == this);
    if (child->m_pNextSibling)
      child->m_pNextSibling->m_pPrevSibling = child->m_pPrevSibling;
    else
      m_pLastChild = child->m_pPrevSibling;

    if (child->m_pPrevSibling)
      child->m_pPrevSibling->m_pNextSibling = child->m_pNextSibling;
    else
      m_pFirstChild = child->m_pNextSibling;

    child->m_pParent = nullptr;
    child->m_pPrevSibling = nullptr;
    child->m_pNextSibling = nullptr;
  }

 protected:
  enum ItemType { kViewItem, kContentItem };
  CXFA_LayoutItem(CXFA_Node* pNode, ItemType type);

 private:
  void BecomeParent(CXFA_LayoutItem* child) {
    if (child->m_pParent)
      child->m_pParent->RemoveChild(child);
    child->m_pParent = static_cast<CXFA_LayoutItem*>(this);
    ASSERT(!child->m_pNextSibling);
    ASSERT(!child->m_pPrevSibling);
  }

  const ItemType m_ItemType;
  CXFA_LayoutItem* m_pParent = nullptr;       // Raw, intra-tree pointer.
  CXFA_LayoutItem* m_pFirstChild = nullptr;   // Raw, intra-tree pointer.
  CXFA_LayoutItem* m_pLastChild = nullptr;    // Raw, intra-tree pointer.
  CXFA_LayoutItem* m_pNextSibling = nullptr;  // Raw, intra-tree pointer.
  CXFA_LayoutItem* m_pPrevSibling = nullptr;  // Raw, intra-tree pointer.
  UnownedPtr<CXFA_Node> m_pFormNode;
};

inline CXFA_ViewLayoutItem* ToViewLayoutItem(CXFA_LayoutItem* item) {
  return item ? item->AsViewLayoutItem() : nullptr;
}

inline CXFA_ContentLayoutItem* ToContentLayoutItem(CXFA_LayoutItem* item) {
  return item ? item->AsContentLayoutItem() : nullptr;
}

void XFA_ReleaseLayoutItem(CXFA_LayoutItem* pLayoutItem);

#endif  // XFA_FXFA_LAYOUT_CXFA_LAYOUTITEM_H_
