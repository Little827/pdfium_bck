// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_eventpseudomodel.h"

#include <algorithm>
#include <vector>

#include "fxjs/fxv8.h"
#include "fxjs/xfa/cfxjse_engine.h"
#include "third_party/base/notreached.h"
#include "xfa/fxfa/cxfa_eventparam.h"
#include "xfa/fxfa/cxfa_ffnotify.h"
#include "xfa/fxfa/cxfa_ffwidgethandler.h"
#include "xfa/fxfa/parser/cscript_eventpseudomodel.h"

namespace {

void AdjustSelectionEnd(CXFA_EventParam* pEventParam) {
  pEventParam->m_iSelEnd = std::max(0, pEventParam->m_iSelEnd);
  pEventParam->m_iSelEnd = std::min<size_t>(
      pEventParam->m_iSelEnd, pEventParam->m_wsPrevText.GetLength());
  pEventParam->m_iSelStart =
      std::min(pEventParam->m_iSelStart, pEventParam->m_iSelEnd);
}

void AdjustSelectionStart(CXFA_EventParam* pEventParam) {
  pEventParam->m_iSelStart = std::max(0, pEventParam->m_iSelStart);
  pEventParam->m_iSelStart = std::min<size_t>(
      pEventParam->m_iSelStart, pEventParam->m_wsPrevText.GetLength());
  pEventParam->m_iSelEnd =
      std::max(pEventParam->m_iSelStart, pEventParam->m_iSelEnd);
}

}  // namespace

const CJX_MethodSpec CJX_EventPseudoModel::MethodSpecs[] = {
    {"emit", emit_static},
    {"reset", reset_static}};

CJX_EventPseudoModel::CJX_EventPseudoModel(CScript_EventPseudoModel* model)
    : CJX_Object(model) {
  DefineMethods(MethodSpecs);
}

CJX_EventPseudoModel::~CJX_EventPseudoModel() = default;

bool CJX_EventPseudoModel::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

v8::Local<v8::Value> CJX_EventPseudoModel::cancelActionGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewBooleanHelper(pIsolate, pEventParam->m_bCancelAction);
}

void CJX_EventPseudoModel::cancelActionSetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute,
                                              v8::Local<v8::Value> pValue) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return;

  pEventParam->m_bCancelAction =
      fxv8::ReentrantToBooleanHelper(pIsolate, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::changeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsChange.AsStringView());
}

void CJX_EventPseudoModel::changeSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return;

  pEventParam->m_wsChange = fxv8::ReentrantToWideStringHelper(pIsolate, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::commitKeyGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewNumberHelper(pIsolate, pEventParam->m_iCommitKey);
}

void CJX_EventPseudoModel::commitKeySetter(v8::Isolate* pIsolate,
                                           XFA_Attribute eAttribute,
                                           v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::fullTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsFullText.AsStringView());
}

void CJX_EventPseudoModel::fullTextSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::keyDownGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewBooleanHelper(pIsolate, pEventParam->m_bKeyDown);
}

void CJX_EventPseudoModel::keyDownSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::modifierGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewBooleanHelper(pIsolate, pEventParam->m_bModifier);
}

void CJX_EventPseudoModel::modifierSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::newContentTypeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsNewContentType.AsStringView());
}

void CJX_EventPseudoModel::newContentTypeSetter(v8::Isolate* pIsolate,
                                                XFA_Attribute eAttribute,
                                                v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::newTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return fxv8::NewUndefinedHelper(pIsolate);

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->GetNewText().AsStringView());
}

void CJX_EventPseudoModel::newTextSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_EventPseudoModel::prevContentTypeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsPrevContentType.AsStringView());
}

void CJX_EventPseudoModel::prevContentTypeSetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute,
                                                 v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::prevTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsPrevText.AsStringView());
}

void CJX_EventPseudoModel::prevTextSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::reenterGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewBooleanHelper(pIsolate, pEventParam->m_bReenter);
}

void CJX_EventPseudoModel::reenterSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::selEndGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  v8::Local<v8::Value> result =
      fxv8::NewNumberHelper(pIsolate, pEventParam->m_iSelEnd);
  AdjustSelectionEnd(pEventParam);
  return result;
}

void CJX_EventPseudoModel::selEndSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return;

  pEventParam->m_iSelEnd = fxv8::ReentrantToInt32Helper(pIsolate, pValue);
  AdjustSelectionEnd(pEventParam);
}

v8::Local<v8::Value> CJX_EventPseudoModel::selStartGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  v8::Local<v8::Value> result =
      fxv8::NewNumberHelper(pIsolate, pEventParam->m_iSelStart);
  AdjustSelectionStart(pEventParam);
  return result;
}

void CJX_EventPseudoModel::selStartSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return;

  pEventParam->m_iSelStart = fxv8::ReentrantToInt32Helper(pIsolate, pValue);
  AdjustSelectionStart(pEventParam);
}

v8::Local<v8::Value> CJX_EventPseudoModel::shiftGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewBooleanHelper(pIsolate, pEventParam->m_bShift);
}

void CJX_EventPseudoModel::shiftSetter(v8::Isolate* pIsolate,
                                       XFA_Attribute eAttribute,
                                       v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::soapFaultCodeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsSoapFaultCode.AsStringView());
}

void CJX_EventPseudoModel::soapFaultCodeSetter(v8::Isolate* pIsolate,
                                               XFA_Attribute eAttribute,
                                               v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::soapFaultStringGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CXFA_EventParam* pEventParam =
      GetDocument()->GetScriptContext()->GetEventParam();
  if (!pEventParam)
    return v8::Local<v8::Value>();

  return fxv8::NewStringHelper(pIsolate,
                               pEventParam->m_wsSoapFaultString.AsStringView());
}

void CJX_EventPseudoModel::soapFaultStringSetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute,
                                                 v8::Local<v8::Value> pValue) {
  // Not writeable.
}

v8::Local<v8::Value> CJX_EventPseudoModel::targetGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  // Not readable.
  return v8::Local<v8::Value>();
}

void CJX_EventPseudoModel::targetSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  // Not writeable.
}

CJS_Result CJX_EventPseudoModel::emit(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_EventParam* pEventParam = pScriptContext->GetEventParam();
  if (!pEventParam)
    return CJS_Result::Success();

  CXFA_FFNotify* pNotify = GetDocument()->GetNotify();
  if (!pNotify)
    return CJS_Result::Success();

  CXFA_FFWidgetHandler* pWidgetHandler = pNotify->GetWidgetHandler();
  if (!pWidgetHandler)
    return CJS_Result::Success();

  pWidgetHandler->ProcessEvent(pEventParam->m_pTarget, pEventParam);
  return CJS_Result::Success();
}

CJS_Result CJX_EventPseudoModel::reset(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_EventParam* pEventParam = pScriptContext->GetEventParam();
  if (pEventParam)
    *pEventParam = CXFA_EventParam();

  return CJS_Result::Success();
}
