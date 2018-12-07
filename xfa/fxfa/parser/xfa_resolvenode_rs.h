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

#define XFA_RESOLVENODE_Children 0x0001
#define XFA_RESOLVENODE_TagName 0x0002
#define XFA_RESOLVENODE_Attributes 0x0004
#define XFA_RESOLVENODE_Properties 0x0008
#define XFA_RESOLVENODE_Siblings 0x0020
#define XFA_RESOLVENODE_Parent 0x0040
#define XFA_RESOLVENODE_AnyChild 0x0080
#define XFA_RESOLVENODE_ALL 0x0100
#define XFA_RESOLVENODE_CreateNode 0x0400
#define XFA_RESOLVENODE_Bind 0x0800
#define XFA_RESOLVENODE_BindNew 0x1000

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
