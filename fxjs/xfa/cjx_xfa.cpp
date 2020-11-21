// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_xfa.h"

#include "fxjs/fxv8.h"
#include "fxjs/xfa/cfxjse_engine.h"
#include "xfa/fxfa/parser/cxfa_document.h"
#include "xfa/fxfa/parser/cxfa_xfa.h"

CJX_Xfa::CJX_Xfa(CXFA_Xfa* node) : CJX_Model(node) {}

CJX_Xfa::~CJX_Xfa() = default;

bool CJX_Xfa::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_Xfa::thisValueGetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute) {
  auto* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_Object* pThis = pScriptContext->GetThisObject();
  if (!pThis)
    return fxv8::NewNullHelper(pIsolate);

  return pScriptContext->GetOrCreateJSBindingFromMap(pThis);
}

void CJX_Xfa::thisValueSetter(v8::Isolate* pIsolate,
                              XFA_Attribute eAttribute,
                              v8::Local<v8::Value> pValue) {}
