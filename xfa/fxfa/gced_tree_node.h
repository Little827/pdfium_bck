// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef XFA_FXFA_GCED_TREE_NODE_H_
#define XFA_FXFA_GCED_TREE_NODE_H_

#include "third_party/base/logging.h"
#include "xfa/fxfa/heap.h"

// Implements DOM/XML-ish trees managed using GC.
template <typename T>
class GCedTreeNode : public cppgc::GarbageCollected<GCedTreeNode<T>> {
 public:
  GCedTreeNode() = default;
  virtual ~GCedTreeNode() = default;

  T* GetParent() const { return m_pParent; }
  T* GetFirstChild() const { return m_pFirstChild; }
  T* GetLastChild() const { return m_pLastChild; }
  T* GetNextSibling() const { return m_pNextSibling; }
  T* GetPrevSibling() const { return m_pPrevSibling; }

  bool HasChild(const T* child) const {
    return child != this && child->m_pParent == this;
  }

  T* GetNthChild(int32_t n) {
    if (n < 0)
      return nullptr;
    T* result = GetFirstChild();
    while (n-- && result) {
      result = result->GetNextSibling();
    }
    return result;
  }

  void AppendFirstChild(T* child) {
    BecomeParent(child);
    if (m_pFirstChild) {
      CHECK(m_pLastChild);
      m_pFirstChild->m_pPrevSibling = child;
      child->m_pNextSibling = m_pFirstChild;
      m_pFirstChild = child;
    } else {
      CHECK(!m_pLastChild);
      m_pFirstChild = child;
      m_pLastChild = child;
    }
  }

  void AppendLastChild(T* child) {
    BecomeParent(child);
    if (m_pLastChild) {
      CHECK(m_pFirstChild);
      m_pLastChild->m_pNextSibling = child;
      child->m_pPrevSibling = m_pLastChild;
      m_pLastChild = child;
    } else {
      CHECK(!m_pFirstChild);
      m_pFirstChild = child;
      m_pLastChild = child;
    }
  }

  void InsertBefore(T* child, T* other) {
    if (!other) {
      AppendLastChild(child);
      return;
    }
    BecomeParent(child);
    CHECK(HasChild(other));
    child->m_pNextSibling = other;
    child->m_pPrevSibling = other->m_pPrevSibling;
    if (m_pFirstChild == other) {
      CHECK(!other->m_pPrevSibling);
      m_pFirstChild = child;
    } else {
      other->m_pPrevSibling->m_pNextSibling = child;
    }
    other->m_pPrevSibling = child;
  }

  void InsertAfter(T* child, T* other) {
    if (!other) {
      AppendFirstChild(child);
      return;
    }
    BecomeParent(child);
    CHECK(HasChild(other));
    child->m_pNextSibling = other->m_pNextSibling;
    child->m_pPrevSibling = other;
    if (m_pLastChild == other) {
      CHECK(!other->m_pNextSibling);
      m_pLastChild = child;
    } else {
      other->m_pNextSibling->m_pPrevSibling = child;
    }
    other->m_pNextSibling = child;
  }

  void RemoveChild(T* child) {
    CHECK(HasChild(child));
    if (m_pLastChild == child) {
      CHECK(!child->m_pNextSibling);
      m_pLastChild = child->m_pPrevSibling;
    } else {
      child->m_pNextSibling->m_pPrevSibling = child->m_pPrevSibling;
    }
    if (m_pFirstChild == child) {
      CHECK(!child->m_pPrevSibling);
      m_pFirstChild = child->m_pNextSibling;
    } else {
      child->m_pPrevSibling->m_pNextSibling = child->m_pNextSibling;
    }
    child->m_pParent = nullptr;
    child->m_pPrevSibling = nullptr;
    child->m_pNextSibling = nullptr;
  }

  void RemoveAllChildren() {
    while (T* child = GetFirstChild())
      RemoveChild(child);
  }

  void RemoveSelfIfParented() {
    if (T* parent = GetParent())
      parent->RemoveChild(static_cast<T*>(this));
  }

  virtual void Trace(cppgc::Visitor* visitor) const {
    visitor->Trace(m_pParent);
    visitor->Trace(m_pFirstChild);
    visitor->Trace(m_pLastChild);
    visitor->Trace(m_pNextSibling);
    visitor->Trace(m_pPrevSibling);
  }

 private:
  // Child left in state where sibling members need subsequent adjustment.
  void BecomeParent(T* child) {
    CHECK(child != this);  // Detect attempts at self-insertion.
    if (child->m_pParent)
      child->m_pParent->GCedTreeNode<T>::RemoveChild(child);
    child->m_pParent = static_cast<T*>(this);
    CHECK(!child->m_pNextSibling);
    CHECK(!child->m_pPrevSibling);
  }

  cppgc::Member<T> m_pParent;
  cppgc::Member<T> m_pFirstChild;
  cppgc::Member<T> m_pLastChild;
  cppgc::Member<T> m_pNextSibling;
  cppgc::Member<T> m_pPrevSibling;
};

#endif  // XFA_FXFA_GCED_TREE_NODE_H_
