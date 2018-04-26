// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_
#define CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_

#include <memory>
#include <utility>
#include <vector>

#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/ptr_util.h"

class CFX_XMLInstruction;
class CFX_XMLElement;
class CFX_XMLNode;

class CFX_XMLDocument {
 public:
  CFX_XMLDocument();
  ~CFX_XMLDocument();

  void SetRoot(CFX_XMLElement* root) { root_ = root; }
  CFX_XMLElement* GetRoot() const { return root_.Get(); }

  void SetInstruction(CFX_XMLInstruction* instruction);
  CFX_XMLInstruction* GetInstruction() const { return instruction_.Get(); }

  template <typename T, typename... Args>
  T* CreateNode(Args&&... args) {
    nodes_.push_back(pdfium::MakeUnique<T>(std::forward<Args>(args)...));
    return static_cast<T*>(nodes_.back().get());
  }

 private:
  std::vector<std::unique_ptr<CFX_XMLNode>> nodes_;
  UnownedPtr<CFX_XMLInstruction> instruction_;
  UnownedPtr<CFX_XMLElement> root_;
};

#endif  // CORE_FXCRT_XML_CFX_XMLDOCUMENT_H_
