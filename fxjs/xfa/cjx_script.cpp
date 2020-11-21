// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_script.h"

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cxfa_script.h"

CJX_Script::CJX_Script(CXFA_Script* node) : CJX_Node(node) {}

CJX_Script::~CJX_Script() = default;

bool CJX_Script::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Script::statelessGetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute) {
  return fxv8::NewStringHelper(pIsolate, "0");
}

void CJX_Script::statelessSetter(v8::Isolate* pIsolate,
                                 XFA_Attribute eAttribute,
                                 v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}
