// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_textnode.h"

#include "xfa/fxfa/parser/cxfa_node.h"

CJX_TextNode::CJX_TextNode(CXFA_Node* node) : CJX_Node(node) {}

CJX_TextNode::~CJX_TextNode() = default;

bool CJX_TextNode::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_TextNode::defaultValueGetter(v8::Isolate* pIsolate,
                                                      XFA_Attribute attr) {
  return ScriptSomDefaultValueGetter(pIsolate, attr);
}

void CJX_TextNode::defaultValueSetter(v8::Isolate* pIsolate,
                                      XFA_Attribute attr,
                                      v8::Local<v8::Value> pValue) {
  ScriptSomDefaultValueSetter(pIsolate, attr, pValue);
}

v8::Local<v8::Value> CJX_TextNode::valueGetter(v8::Isolate* pIsolate,
                                               XFA_Attribute attr) {
  return ScriptSomDefaultValueGetter(pIsolate, attr);
}

void CJX_TextNode::valueSetter(v8::Isolate* pIsolate,
                               XFA_Attribute attr,
                               v8::Local<v8::Value> pValue) {
  ScriptSomDefaultValueSetter(pIsolate, attr, pValue);
}
