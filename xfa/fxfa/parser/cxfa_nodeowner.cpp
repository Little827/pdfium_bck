// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/cxfa_nodeowner.h"

#include <utility>

#include "xfa/fxfa/parser/cxfa_node.h"

CXFA_NodeOwner::CXFA_NodeOwner() = default;

CXFA_NodeOwner::~CXFA_NodeOwner() = default;

CXFA_Node* CXFA_NodeOwner::AddOwnedNode(std::unique_ptr<CXFA_Node> node) {
  if (!node)
    return nullptr;

  nodes_.push_back(std::move(node));
  return nodes_.back().get();
}

void CXFA_NodeOwner::FreeOwnedNode(CXFA_Node* node) {
  if (!node)
    return;

  auto it = std::find_if(std::begin(nodes_), std::end(nodes_),
                         [node](const std::unique_ptr<CXFA_Node>& child) {
                           return child.get() == node;
                         });
  if (it == nodes_.end())
    return;

  nodes_.erase(it);
}
