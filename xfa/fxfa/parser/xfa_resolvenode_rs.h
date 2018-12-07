// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_PARSER_XFA_RESOLVENODE_RS_H_
#define XFA_FXFA_PARSER_XFA_RESOLVENODE_RS_H_

#include <vector>

#include "core/fxcrt/unowned_ptr.h"
#include "fxjs/xfa/cjx_object.h"
#include "xfa/fxfa/fxfa_basic.h"

class CXFA_Object;

enum class XFA_ResolveNode_RSType : uint8_t {
  Nodes,
  Attribute,
  CreateNodeOne,
  CreateNodeAll,
  CreateNodeMidAll,
  ExistNodes,
};

struct XFA_RESOLVENODE_RS {
  XFA_RESOLVENODE_RS();
  ~XFA_RESOLVENODE_RS();

  XFA_ResolveNode_RSType eRSType = XFA_ResolveNode_RSType::Nodes;
  XFA_Attribute eAttribute = XFA_Attribute::Unknown;
  XFA_ScriptType eScriptType = XFA_ScriptType::Basic;
  XFA_ATTRIBUTE_CALLBACK pCallback = nullptr;
  std::vector<UnownedPtr<CXFA_Object>> objects;
};

inline XFA_RESOLVENODE_RS::XFA_RESOLVENODE_RS() = default;

inline XFA_RESOLVENODE_RS::~XFA_RESOLVENODE_RS() = default;

#endif  // XFA_FXFA_PARSER_XFA_RESOLVENODE_RS_H_
