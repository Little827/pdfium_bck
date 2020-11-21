// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_subform.h"

#include <vector>

#include "fxjs/cfx_v8.h"
#include "fxjs/fxv8.h"
#include "fxjs/js_resources.h"
#include "fxjs/xfa/cfxjse_engine.h"
#include "xfa/fxfa/cxfa_eventparam.h"
#include "xfa/fxfa/cxfa_ffnotify.h"
#include "xfa/fxfa/fxfa.h"
#include "xfa/fxfa/parser/cxfa_delta.h"
#include "xfa/fxfa/parser/cxfa_document.h"

const CJX_MethodSpec CJX_Subform::MethodSpecs[] = {
    {"execCalculate", execCalculate_static},
    {"execEvent", execEvent_static},
    {"execInitialize", execInitialize_static},
    {"execValidate", execValidate_static}};

CJX_Subform::CJX_Subform(CXFA_Node* node) : CJX_Container(node) {
  DefineMethods(MethodSpecs);
}

CJX_Subform::~CJX_Subform() = default;

bool CJX_Subform::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

CJS_Result CJX_Subform::execEvent(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 1)
    return CJS_Result::Failure(JSMessage::kParamError);

  execSingleEventByName(runtime->ToWideString(params[0]).AsStringView(),
                        XFA_Element::Subform);
  return CJS_Result::Success();
}

CJS_Result CJX_Subform::execInitialize(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (!params.empty())
    return CJS_Result::Failure(JSMessage::kParamError);

  CXFA_FFNotify* pNotify = GetDocument()->GetNotify();
  if (pNotify)
    pNotify->ExecEventByDeepFirst(GetXFANode(), XFA_EVENT_Initialize, false,
                                  true);
  return CJS_Result::Success();
}

CJS_Result CJX_Subform::execCalculate(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (!params.empty())
    return CJS_Result::Failure(JSMessage::kParamError);

  CXFA_FFNotify* pNotify = GetDocument()->GetNotify();
  if (pNotify)
    pNotify->ExecEventByDeepFirst(GetXFANode(), XFA_EVENT_Calculate, false,
                                  true);
  return CJS_Result::Success();
}

CJS_Result CJX_Subform::execValidate(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (!params.empty())
    return CJS_Result::Failure(JSMessage::kParamError);

  CXFA_FFNotify* pNotify = GetDocument()->GetNotify();
  if (!pNotify)
    return CJS_Result::Success(runtime->NewBoolean(false));

  XFA_EventError iRet = pNotify->ExecEventByDeepFirst(
      GetXFANode(), XFA_EVENT_Validate, false, true);
  return CJS_Result::Success(
      runtime->NewBoolean(iRet != XFA_EventError::kError));
}

v8::Local<v8::Value> CJX_Subform::localeGetter(v8::Isolate* pIsolate,
                                               XFA_Attribute eAttribute) {
  WideString wsLocaleName = GetXFANode()->GetLocaleName().value_or(L"");
  return fxv8::NewStringHelper(pIsolate, wsLocaleName.ToUTF8().AsStringView());
}

void CJX_Subform::localeSetter(v8::Isolate* pIsolate,
                               XFA_Attribute eAttribute,
                               v8::Local<v8::Value> pValue) {
  WideString wsValue = fxv8::ReentrantToWideStringHelper(pIsolate, pValue);
  SetCDataImpl(XFA_Attribute::Locale, std::move(wsValue), true, true);
}

v8::Local<v8::Value> CJX_Subform::instanceManagerGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  WideString wsName = GetCData(XFA_Attribute::Name);
  CXFA_Node* pInstanceMgr = nullptr;
  for (CXFA_Node* pNode = GetXFANode()->GetPrevSibling(); pNode;
       pNode = pNode->GetPrevSibling()) {
    if (pNode->GetElementType() == XFA_Element::InstanceManager) {
      WideString wsInstMgrName =
          pNode->JSObject()->GetCData(XFA_Attribute::Name);
      if (wsInstMgrName.GetLength() >= 1 && wsInstMgrName[0] == '_' &&
          wsInstMgrName.Last(wsInstMgrName.GetLength() - 1) == wsName) {
        pInstanceMgr = pNode;
      }
      break;
    }
  }
  if (!pInstanceMgr)
    return fxv8::NewNullHelper(pIsolate);

  return GetDocument()->GetScriptContext()->GetOrCreateJSBindingFromMap(
      pInstanceMgr);
}

void CJX_Subform::instanceManagerSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}
