// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/cxfa_nodeowner.h"

#include <utility>

#include "xfa/fxfa/parser/cxfa_node.h"

CXFA_NodeOwner::CXFA_NodeOwner() = default;

CXFA_NodeOwner::~CXFA_NodeOwner() {
  is_being_destroyed_ = true;
}

CXFA_Node* CXFA_NodeOwner::AddOwnedNode(CXFA_Node* node) {
  if (!node)
    return nullptr;

  // CXFA_Node* ret = node.get();
  nodes_.push_back(node);
  return node;
  // return ret;
}

void CXFA_NodeOwner::Trace(cppgc::Visitor* visitor) const {
  for (const auto& node : nodes_) {
    visitor->Trace(node);
  }
}
