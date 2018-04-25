// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_
#define CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_

#include <memory>
#include <utility>
#include <vector>

class CFX_XMLInstruction;
class CFX_XMLElement;
class CFX_XMLNode;

class CFX_XMLDocument {
 public:
  CFX_XMLDocument();
  ~CFX_XMLDocument();

  void SetRoot(CFX_XMLElement* root) { root_ = root; }
  CFX_XMLElement* GetRoot() const { return root_; }

  void SetInstruction(std::unique_ptr<CFX_XMLInstruction> instruction);
  CFX_XMLInstruction* GetInstruction() const { return instruction_; }

  void AddNode(std::unique_ptr<CFX_XMLNode> node) {
    nodes_.push_back(std::move(node));
  }

 private:
  std::vector<std::unique_ptr<CFX_XMLNode>> nodes_;
  CFX_XMLInstruction* instruction_ = nullptr;
  CFX_XMLElement* root_ = nullptr;
};

#endif  // CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_
