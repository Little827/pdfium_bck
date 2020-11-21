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

void StringProperty(v8::Isolate* pIsolate,
                    v8::Local<v8::Value>* pReturn,
                    WideString* wsValue,
                    bool bSetting) {
  if (bSetting) {
    *wsValue = fxv8::ReentrantToWideStringHelper(pIsolate, *pReturn);
    return;
  }
  *pReturn = fxv8::NewStringHelper(pIsolate, wsValue->ToUTF8().AsStringView());
}

void IntegerProperty(v8::Isolate* pIsolate,
                     v8::Local<v8::Value>* pReturn,
                     int32_t* iValue,
                     bool bSetting) {
  if (bSetting) {
    *iValue = fxv8::ReentrantToInt32Helper(pIsolate, *pReturn);
    return;
  }
  *pReturn = fxv8::NewNumberHelper(pIsolate, *iValue);
}

void BooleanProperty(v8::Isolate* pIsolate,
                     v8::Local<v8::Value>* pReturn,
                     bool* bValue,
                     bool bSetting) {
  if (bSetting) {
    *bValue = fxv8::ReentrantToBooleanHelper(pIsolate, *pReturn);
    return;
  }
  *pReturn = fxv8::NewBooleanHelper(pIsolate, *bValue);
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
  return PropertyGetter(pIsolate, XFA_Event::CancelAction);
}

void CJX_EventPseudoModel::cancelActionSetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute,
                                              v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::CancelAction, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::changeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Change);
}

void CJX_EventPseudoModel::changeSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Change, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::commitKeyGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::CommitKey);
}

void CJX_EventPseudoModel::commitKeySetter(v8::Isolate* pIsolate,
                                           XFA_Attribute eAttribute,
                                           v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::CommitKey, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::fullTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::FullText);
}

void CJX_EventPseudoModel::fullTextSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::FullText, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::keyDownGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Keydown);
}

void CJX_EventPseudoModel::keyDownSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Keydown, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::modifierGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Modifier);
}

void CJX_EventPseudoModel::modifierSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Modifier, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::newContentTypeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::NewContentType);
}

void CJX_EventPseudoModel::newContentTypeSetter(v8::Isolate* pIsolate,
                                                XFA_Attribute eAttribute,
                                                v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::NewContentType, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::newTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_EventParam* pEventParam = pScriptContext->GetEventParam();
  if (!pEventParam)
    return fxv8::NewUndefinedHelper(pIsolate);

  return fxv8::NewStringHelper(
      pIsolate, pEventParam->GetNewText().ToUTF8().AsStringView());
}

void CJX_EventPseudoModel::newTextSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_EventPseudoModel::prevContentTypeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::PreviousContentType);
}

void CJX_EventPseudoModel::prevContentTypeSetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute,
                                                 v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::PreviousContentType, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::prevTextGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::PreviousText);
}

void CJX_EventPseudoModel::prevTextSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::PreviousText, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::reenterGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Reenter);
}

void CJX_EventPseudoModel::reenterSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Reenter, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::selEndGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::SelectionEnd);
}

void CJX_EventPseudoModel::selEndSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::SelectionEnd, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::selStartGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::SelectionStart);
}

void CJX_EventPseudoModel::selStartSetter(v8::Isolate* pIsolate,
                                          XFA_Attribute eAttribute,
                                          v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::SelectionStart, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::shiftGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Shift);
}

void CJX_EventPseudoModel::shiftSetter(v8::Isolate* pIsolate,
                                       XFA_Attribute eAttribute,
                                       v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Shift, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::soapFaultCodeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::SoapFaultCode);
}

void CJX_EventPseudoModel::soapFaultCodeSetter(v8::Isolate* pIsolate,
                                               XFA_Attribute eAttribute,
                                               v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::SoapFaultCode, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::soapFaultStringGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::SoapFaultString);
}

void CJX_EventPseudoModel::soapFaultStringSetter(v8::Isolate* pIsolate,
                                                 XFA_Attribute eAttribute,
                                                 v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::SoapFaultString, pValue);
}

v8::Local<v8::Value> CJX_EventPseudoModel::targetGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return PropertyGetter(pIsolate, XFA_Event::Target);
}

void CJX_EventPseudoModel::targetSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {
  PropertySetter(pIsolate, XFA_Event::Target, pValue);
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

v8::Local<v8::Value> CJX_EventPseudoModel::PropertyGetter(v8::Isolate* pIsolate,
                                                          XFA_Event dwFlag) {
  v8::Local<v8::Value> result;
  Property(pIsolate, dwFlag, &result, false);
  return result;
}

void CJX_EventPseudoModel::PropertySetter(v8::Isolate* pIsolate,
                                          XFA_Event dwFlag,
                                          v8::Local<v8::Value> pValue) {
  Property(pIsolate, dwFlag, &pValue, true);
}

void CJX_EventPseudoModel::Property(v8::Isolate* pIsolate,
                                    XFA_Event dwFlag,
                                    v8::Local<v8::Value>* pValue,
                                    bool bSetting) {
  // Only the cancelAction, selStart, selEnd and change properties are writable.
  if (bSetting && dwFlag != XFA_Event::CancelAction &&
      dwFlag != XFA_Event::SelectionStart &&
      dwFlag != XFA_Event::SelectionEnd && dwFlag != XFA_Event::Change) {
    return;
  }

  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_EventParam* pEventParam = pScriptContext->GetEventParam();
  if (!pEventParam)
    return;

  switch (dwFlag) {
    case XFA_Event::CancelAction:
      BooleanProperty(pIsolate, pValue, &pEventParam->m_bCancelAction,
                      bSetting);
      break;
    case XFA_Event::Change:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsChange, bSetting);
      break;
    case XFA_Event::CommitKey:
      IntegerProperty(pIsolate, pValue, &pEventParam->m_iCommitKey, bSetting);
      break;
    case XFA_Event::FullText:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsFullText, bSetting);
      break;
    case XFA_Event::Keydown:
      BooleanProperty(pIsolate, pValue, &pEventParam->m_bKeyDown, bSetting);
      break;
    case XFA_Event::Modifier:
      BooleanProperty(pIsolate, pValue, &pEventParam->m_bModifier, bSetting);
      break;
    case XFA_Event::NewContentType:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsNewContentType,
                     bSetting);
      break;
    case XFA_Event::NewText:
      NOTREACHED();
      break;
    case XFA_Event::PreviousContentType:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsPrevContentType,
                     bSetting);
      break;
    case XFA_Event::PreviousText:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsPrevText, bSetting);
      break;
    case XFA_Event::Reenter:
      BooleanProperty(pIsolate, pValue, &pEventParam->m_bReenter, bSetting);
      break;
    case XFA_Event::SelectionEnd:
      IntegerProperty(pIsolate, pValue, &pEventParam->m_iSelEnd, bSetting);

      pEventParam->m_iSelEnd = std::max(0, pEventParam->m_iSelEnd);
      pEventParam->m_iSelEnd =
          std::min(static_cast<size_t>(pEventParam->m_iSelEnd),
                   pEventParam->m_wsPrevText.GetLength());
      pEventParam->m_iSelStart =
          std::min(pEventParam->m_iSelStart, pEventParam->m_iSelEnd);
      break;
    case XFA_Event::SelectionStart:
      IntegerProperty(pIsolate, pValue, &pEventParam->m_iSelStart, bSetting);
      pEventParam->m_iSelStart = std::max(0, pEventParam->m_iSelStart);
      pEventParam->m_iSelStart =
          std::min(static_cast<size_t>(pEventParam->m_iSelStart),
                   pEventParam->m_wsPrevText.GetLength());
      pEventParam->m_iSelEnd =
          std::max(pEventParam->m_iSelStart, pEventParam->m_iSelEnd);
      break;
    case XFA_Event::Shift:
      BooleanProperty(pIsolate, pValue, &pEventParam->m_bShift, bSetting);
      break;
    case XFA_Event::SoapFaultCode:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsSoapFaultCode,
                     bSetting);
      break;
    case XFA_Event::SoapFaultString:
      StringProperty(pIsolate, pValue, &pEventParam->m_wsSoapFaultString,
                     bSetting);
      break;
    case XFA_Event::Target:
    default:
      break;
  }
}
