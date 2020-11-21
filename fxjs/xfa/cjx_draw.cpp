// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_draw.h"

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cxfa_draw.h"

CJX_Draw::CJX_Draw(CXFA_Draw* node) : CJX_Container(node) {}

CJX_Draw::~CJX_Draw() = default;

bool CJX_Draw::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Draw::rawValueGetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute) {
  return defaultValueGetter(pIsolate, eAttribute);
}

void CJX_Draw::rawValueSetter(v8::Isolate* pIsolate,
                              XFA_Attribute eAttribute,
                              v8::Local<v8::Value> pValue) {
  defaultValueSetter(pIsolate, eAttribute, pValue);
}

v8::Local<v8::Value> CJX_Draw::defaultValueGetter(v8::Isolate* pIsolate,
                                                  XFA_Attribute eAttribute) {
  ByteString content = GetContent(true).ToUTF8();
  if (content.IsEmpty())
    return fxv8::NewNullHelper(pIsolate);

  return fxv8::NewStringHelper(pIsolate, content.AsStringView());
}

void CJX_Draw::defaultValueSetter(v8::Isolate* pIsolate,
                                  XFA_Attribute eAttribute,
                                  v8::Local<v8::Value> pValue) {
  if (!fxv8::IsString(pValue))
    return;

  ASSERT(GetXFANode()->IsWidgetReady());
  if (GetXFANode()->GetFFWidgetType() != XFA_FFWidgetType::kText)
    return;

  WideString wsNewValue = fxv8::ReentrantToWideStringHelper(pIsolate, pValue);
  SetContent(wsNewValue, wsNewValue, true, true, true);
}
