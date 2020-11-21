// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_delta.h"

#include <vector>

#include "fxjs/fxv8.h"
#include "fxjs/js_resources.h"
#include "xfa/fxfa/parser/cxfa_delta.h"

const CJX_MethodSpec CJX_Delta::MethodSpecs[] = {{"restore", restore_static}};

CJX_Delta::CJX_Delta(CXFA_Delta* delta) : CJX_Object(delta) {
  DefineMethods(MethodSpecs);
}

CJX_Delta::~CJX_Delta() = default;

bool CJX_Delta::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

CJS_Result CJX_Delta::restore(CFX_V8* runtime,
                              const std::vector<v8::Local<v8::Value>>& params) {
  if (!params.empty())
    return CJS_Result::Failure(JSMessage::kParamError);

  return CJS_Result::Success();
}

v8::Local<v8::Value> CJX_Delta::currentValueGetter(v8::Isolate* pIsolate,
                                                   XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_Delta::currentValueSetter(v8::Isolate* pIsolate,
                                   XFA_Attribute eAttribute,
                                   v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_Delta::savedValueGetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_Delta::savedValueSetter(v8::Isolate* pIsolate,
                                 XFA_Attribute eAttribute,
                                 v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_Delta::targetGetter(v8::Isolate* pIsolate,
                                             XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_Delta::targetSetter(v8::Isolate* pIsolate,
                             XFA_Attribute eAttribute,
                             v8::Local<v8::Value> pValue) {}
