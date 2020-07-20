// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/xml/cfx_xmldocument.h"

#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/xml/cfx_xmlinstruction.h"

// static
WideString CFX_XMLDocument::EncodeEntities(const WideString& value) {
  WideString ret = value;
  ret.Replace(L"&", L"&amp;");
  ret.Replace(L"<", L"&lt;");
  ret.Replace(L">", L"&gt;");
  ret.Replace(L"\'", L"&apos;");
  ret.Replace(L"\"", L"&quot;");
  return ret;
}

CFX_XMLDocument::CFX_XMLDocument() {
  root_ = CreateNode<CFX_XMLElement>(L"root");
}

CFX_XMLDocument::~CFX_XMLDocument() = default;

void CFX_XMLDocument::AppendNodesFrom(CFX_XMLDocument* other) {
  nodes_.reserve(nodes_.size() + other->nodes_.size());
  nodes_.insert(nodes_.end(), std::make_move_iterator(other->nodes_.begin()),
                std::make_move_iterator(other->nodes_.end()));
  other->nodes_.clear();
}
