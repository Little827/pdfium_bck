// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/xml/cfx_xmldocument.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/xml/cfx_xmlinstruction.h"
#include "third_party/base/ptr_util.h"

CFX_XMLDocument::CFX_XMLDocument() {
  root_ = CreateNode<CFX_XMLElement>(L"root");
}

CFX_XMLDocument::~CFX_XMLDocument() = default;

void CFX_XMLDocument::TransferNodesFrom(CFX_XMLDocument* other) {
  std::vector<std::unique_ptr<CFX_XMLNode>>* other_nodes = &(other->nodes_);
  size_t old_node_count = nodes_.size();
  nodes_.resize(old_node_count + other_nodes->size());

  for (size_t i = 0; i < other_nodes->size(); i++)
    nodes_[old_node_count + i].swap((*other_nodes)[i]);
  other_nodes->clear();
}
