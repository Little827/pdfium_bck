// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_occur.h"

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cxfa_occur.h"

CJX_Occur::CJX_Occur(CXFA_Occur* node) : CJX_Node(node) {}

CJX_Occur::~CJX_Occur() = default;

bool CJX_Occur::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Occur::maxGetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute) {
  CXFA_Occur* occur = static_cast<CXFA_Occur*>(GetXFANode());
  return fxv8::NewNumberHelper(pIsolate, occur->GetMax());
}

void CJX_Occur::maxSetter(v8::Isolate* pIsolate,
                          XFA_Attribute eAttribute,
                          v8::Local<v8::Value> pValue) {
  CXFA_Occur* occur = static_cast<CXFA_Occur*>(GetXFANode());
  occur->SetMax(fxv8::ReentrantToInt32Helper(pIsolate, pValue));
}

v8::Local<v8::Value> CJX_Occur::minGetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute) {
  CXFA_Occur* occur = static_cast<CXFA_Occur*>(GetXFANode());
  return fxv8::NewNumberHelper(pIsolate, occur->GetMin());
}

void CJX_Occur::minSetter(v8::Isolate* pIsolate,
                          XFA_Attribute eAttribute,
                          v8::Local<v8::Value> pValue) {
  CXFA_Occur* occur = static_cast<CXFA_Occur*>(GetXFANode());
  occur->SetMin(fxv8::ReentrantToInt32Helper(pIsolate, pValue));
}
