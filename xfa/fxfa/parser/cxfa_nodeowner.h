// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_PARSER_CXFA_NODEOWNER_H_
#define XFA_FXFA_PARSER_CXFA_NODEOWNER_H_

#include <memory>
#include <vector>

#include "v8/include/cppgc/persistent.h"

class CXFA_List;
class CXFA_Node;

class CXFA_NodeOwner {
 public:
  virtual ~CXFA_NodeOwner();

  void PersistNode(CXFA_Node* node);
  void PersistList(CXFA_List* list);

 protected:
  CXFA_NodeOwner();

  std::vector<cppgc::Persistent<CXFA_Node>> nodes_;
  std::vector<cppgc::Persistent<CXFA_List>> lists_;
};

#endif  // XFA_FXFA_PARSER_CXFA_NODEOWNER_H_
