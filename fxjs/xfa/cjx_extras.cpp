// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_extras.h"

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cxfa_extras.h"

CJX_Extras::CJX_Extras(CXFA_Extras* node) : CJX_Node(node) {}

CJX_Extras::~CJX_Extras() = default;

bool CJX_Extras::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Extras::typeGetter(v8::Isolate* pIsolate,
                                            XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_Extras::typeSetter(v8::Isolate* pIsolate,
                            XFA_Attribute eAttribute,
                            v8::Local<v8::Value> pValue) {}
