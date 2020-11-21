// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_boolean.h"

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cxfa_boolean.h"

CJX_Boolean::CJX_Boolean(CXFA_Boolean* node) : CJX_Object(node) {}

CJX_Boolean::~CJX_Boolean() = default;

bool CJX_Boolean::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Boolean::defaultValueGetter(v8::Isolate* pIsolate,
                                                     XFA_Attribute eAttribute) {
  return fxv8::NewBooleanHelper(pIsolate, GetContent(true).EqualsASCII("1"));
}

void CJX_Boolean::defaultValueSetter(v8::Isolate* pIsolate,
                                     XFA_Attribute eAttribute,
                                     v8::Local<v8::Value> pValue) {
  ByteString newValue;
  if (!(fxv8::IsNull(pValue) || fxv8::IsUndefined(pValue)))
    newValue = fxv8::ReentrantToByteStringHelper(pIsolate, pValue);

  int32_t iValue = FXSYS_atoi(newValue.c_str());
  WideString wsNewValue(iValue == 0 ? L"0" : L"1");
  WideString wsFormatValue(wsNewValue);
  CXFA_Node* pContainerNode = GetXFANode()->GetContainerNode();
  if (pContainerNode)
    wsFormatValue = pContainerNode->GetFormatDataValue(wsNewValue);

  SetContent(wsNewValue, wsFormatValue, true, true, true);
}

v8::Local<v8::Value> CJX_Boolean::valueGetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute) {
  return defaultValueGetter(pIsolate, eAttribute);
}

void CJX_Boolean::valueSetter(v8::Isolate* pIsolate,
                              XFA_Attribute eAttribute,
                              v8::Local<v8::Value> pValue) {
  defaultValueSetter(pIsolate, eAttribute, pValue);
}
