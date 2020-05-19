// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_TREE_NODE_H_
#define CORE_FXCRT_TREE_NODE_H_

#include "core/fxcrt/fx_system.h"
#include "third_party/base/logging.h"

namespace fxcrt {

// Implements the usual DOM/XML-ish trees.
template <typename T>
class TreeNode {
 public:
  TreeNode() = default;
  virtual ~TreeNode() = default;

  T* GetParent() const { return parent_; }
  T* GetFirstChild() const { return first_child_; }
  T* GetLastChild() const { return last_child_; }
  T* GetNextSibling() const { return next_sibling_; }
  T* GetPrevSibling() const { return prev_sibling_; }

  bool HasChild(const T* child) const {
    return child != this && child->parent_ == this;
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
    if (first_child_) {
      CHECK(last_child_);
      first_child_->prev_sibling_ = child;
      child->next_sibling_ = first_child_;
      first_child_ = child;
    } else {
      CHECK(!last_child_);
      first_child_ = child;
      last_child_ = child;
    }
  }

  void AppendLastChild(T* child) {
    BecomeParent(child);
    if (last_child_) {
      CHECK(first_child_);
      last_child_->next_sibling_ = child;
      child->prev_sibling_ = last_child_;
      last_child_ = child;
    } else {
      CHECK(!first_child_);
      first_child_ = child;
      last_child_ = child;
    }
  }

  void InsertBefore(T* child, T* other) {
    if (!other) {
      AppendLastChild(child);
      return;
    }
    BecomeParent(child);
    CHECK(HasChild(other));
    child->next_sibling_ = other;
    child->prev_sibling_ = other->prev_sibling_;
    if (first_child_ == other) {
      CHECK(!other->prev_sibling_);
      first_child_ = child;
    } else {
      other->prev_sibling_->next_sibling_ = child;
    }
    other->prev_sibling_ = child;
  }

  void InsertAfter(T* child, T* other) {
    if (!other) {
      AppendFirstChild(child);
      return;
    }
    BecomeParent(child);
    CHECK(HasChild(other));
    child->next_sibling_ = other->next_sibling_;
    child->prev_sibling_ = other;
    if (last_child_ == other) {
      CHECK(!other->next_sibling_);
      last_child_ = child;
    } else {
      other->next_sibling_->prev_sibling_ = child;
    }
    other->next_sibling_ = child;
  }

  void RemoveChild(T* child) {
    CHECK(HasChild(child));
    if (last_child_ == child) {
      CHECK(!child->next_sibling_);
      last_child_ = child->prev_sibling_;
    } else {
      child->next_sibling_->prev_sibling_ = child->prev_sibling_;
    }
    if (first_child_ == child) {
      CHECK(!child->prev_sibling_);
      first_child_ = child->next_sibling_;
    } else {
      child->prev_sibling_->next_sibling_ = child->next_sibling_;
    }
    child->parent_ = nullptr;
    child->prev_sibling_ = nullptr;
    child->next_sibling_ = nullptr;
  }

  void RemoveAllChildren() {
    while (T* child = GetFirstChild())
      RemoveChild(child);
  }

  void RemoveSelfIfParented() {
    if (T* parent = GetParent())
      parent->RemoveChild(static_cast<T*>(this));
  }

 private:
  // Child left in state where sibling members need subsequent adjustment.
  void BecomeParent(T* child) {
    CHECK(child != this);  // Detect attempts at self-insertion.
    if (child->parent_)
      child->parent_->TreeNode<T>::RemoveChild(child);
    child->parent_ = static_cast<T*>(this);
    CHECK(!child->next_sibling_);
    CHECK(!child->prev_sibling_);
  }

  T* parent_ = nullptr;        // Raw, intra-tree pointer.
  T* first_child_ = nullptr;   // Raw, intra-tree pointer.
  T* last_child_ = nullptr;    // Raw, intra-tree pointer.
  T* next_sibling_ = nullptr;  // Raw, intra-tree pointer
  T* prev_sibling_ = nullptr;  // Raw, intra-tree pointer
};

}  // namespace fxcrt

using fxcrt::TreeNode;

#endif  // CORE_FXCRT_TREE_NODE_H_
