// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cjs_global.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "core/fxcrt/fx_extension.h"
#include "fxjs/cfx_globaldata.h"
#include "fxjs/cfx_keyvalue.h"
#include "fxjs/cjs_event_context.h"
#include "fxjs/cjs_eventhandler.h"
#include "fxjs/cjs_object.h"
#include "fxjs/js_define.h"
#include "fxjs/js_resources.h"
#include "third_party/base/ptr_util.h"

namespace {

WideString PropFromV8Prop(v8::Isolate* pIsolate,
                          v8::Local<v8::String> property) {
  v8::String::Utf8Value utf8_value(pIsolate, property);
  return WideString::FromUTF8(ByteStringView(*utf8_value, utf8_value.length()));
}

template <class Alt>
void JSSpecialPropQuery(const char*,
                        v8::Local<v8::String> property,
                        const v8::PropertyCallbackInfo<v8::Integer>& info) {
  auto pObj = JSGetObject<Alt>(info.Holder());
  if (!pObj)
    return;

  CJS_Runtime* pRuntime = pObj->GetRuntime();
  if (!pRuntime)
    return;

  CJS_Result result =
      pObj->QueryProperty(PropFromV8Prop(info.GetIsolate(), property).c_str());

  info.GetReturnValue().Set(!result.HasError() ? 4 : 0);
}

template <class Alt>
void JSSpecialPropGet(const char* class_name,
                      v8::Local<v8::String> property,
                      const v8::PropertyCallbackInfo<v8::Value>& info) {
  auto pObj = JSGetObject<Alt>(info.Holder());
  if (!pObj)
    return;

  CJS_Runtime* pRuntime = pObj->GetRuntime();
  if (!pRuntime)
    return;

  CJS_Result result = pObj->GetProperty(
      pRuntime, PropFromV8Prop(info.GetIsolate(), property).c_str());

  if (result.HasError()) {
    pRuntime->Error(
        JSFormatErrorString(class_name, "GetProperty", result.Error()));
    return;
  }
  if (result.HasReturn())
    info.GetReturnValue().Set(result.Return());
}

template <class Alt>
void JSSpecialPropPut(const char* class_name,
                      v8::Local<v8::String> property,
                      v8::Local<v8::Value> value,
                      const v8::PropertyCallbackInfo<v8::Value>& info) {
  auto pObj = JSGetObject<Alt>(info.Holder());
  if (!pObj)
    return;

  CJS_Runtime* pRuntime = pObj->GetRuntime();
  if (!pRuntime)
    return;

  CJS_Result result = pObj->SetProperty(
      pRuntime, PropFromV8Prop(info.GetIsolate(), property).c_str(), value);

  if (result.HasError()) {
    pRuntime->Error(
        JSFormatErrorString(class_name, "PutProperty", result.Error()));
  }
}

template <class Alt>
void JSSpecialPropDel(const char* class_name,
                      v8::Local<v8::String> property,
                      const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  auto pObj = JSGetObject<Alt>(info.Holder());
  if (!pObj)
    return;

  CJS_Runtime* pRuntime = pObj->GetRuntime();
  if (!pRuntime)
    return;

  CJS_Result result = pObj->DelProperty(
      pRuntime, PropFromV8Prop(info.GetIsolate(), property).c_str());
  if (result.HasError()) {
    // TODO(dsinclair): Should this set the pRuntime->Error result?
    // ByteString cbName =
    //     ByteString::Format("%s.%s", class_name, "DelProperty");
  }
}

template <class T>
v8::Local<v8::String> GetV8StringFromProperty(v8::Local<v8::Name> property,
                                              const T& info) {
  return property->ToString(info.GetIsolate()->GetCurrentContext())
      .ToLocalChecked();
}

}  // namespace

CJS_Global::JSGlobalData::JSGlobalData() = default;

CJS_Global::JSGlobalData::JSGlobalData(v8::Isolate* pIsolate,
                                       v8::Local<v8::Value> vp) {
  pV8Value.Reset(pIsolate, vp);
}

CJS_Global::JSGlobalData::~JSGlobalData() = default;

const JSMethodSpec CJS_Global::MethodSpecs[] = {
    {"setPersistent", setPersistent_static}};

int CJS_Global::ObjDefnID = -1;

// static
void CJS_Global::setPersistent_static(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  JSMethod<CJS_Global, &CJS_Global::setPersistent>("setPersistent", "global",
                                                   info);
}

// static
void CJS_Global::queryprop_static(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Integer>& info) {
  ASSERT(property->IsString());
  JSSpecialPropQuery<CJS_Global>(
      "global",
      v8::Local<v8::String>::New(info.GetIsolate(),
                                 GetV8StringFromProperty(property, info)),
      info);
}

// static
void CJS_Global::getprop_static(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  ASSERT(property->IsString());
  JSSpecialPropGet<CJS_Global>(
      "global",
      v8::Local<v8::String>::New(info.GetIsolate(),
                                 GetV8StringFromProperty(property, info)),
      info);
}

// static
void CJS_Global::putprop_static(
    v8::Local<v8::Name> property,
    v8::Local<v8::Value> value,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  ASSERT(property->IsString());
  JSSpecialPropPut<CJS_Global>(
      "global",
      v8::Local<v8::String>::New(info.GetIsolate(),
                                 GetV8StringFromProperty(property, info)),
      value, info);
}

// static
void CJS_Global::delprop_static(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  ASSERT(property->IsString());
  JSSpecialPropDel<CJS_Global>(
      "global",
      v8::Local<v8::String>::New(info.GetIsolate(),
                                 GetV8StringFromProperty(property, info)),
      info);
}

// static
void CJS_Global::DefineAllProperties(CFXJS_Engine* pEngine) {
  pEngine->DefineObjAllProperties(
      ObjDefnID, CJS_Global::queryprop_static, CJS_Global::getprop_static,
      CJS_Global::putprop_static, CJS_Global::delprop_static);
}

// static
int CJS_Global::GetObjDefnID() {
  return ObjDefnID;
}

// static
void CJS_Global::DefineJSObjects(CFXJS_Engine* pEngine) {
  ObjDefnID = pEngine->DefineObj("global", FXJSOBJTYPE_STATIC,
                                 JSConstructor<CJS_Global>, JSDestructor);
  DefineMethods(pEngine, ObjDefnID, MethodSpecs);
  DefineAllProperties(pEngine);
}

CJS_Global::CJS_Global(v8::Local<v8::Object> pObject, CJS_Runtime* pRuntime)
    : CJS_Object(pObject, pRuntime) {
  CPDFSDK_FormFillEnvironment* pFormFillEnv = GetRuntime()->GetFormFillEnv();
  m_pFormFillEnv.Reset(pFormFillEnv);
  m_pGlobalData = CFX_GlobalData::GetRetainedInstance(nullptr);
  UpdateGlobalVariablesFromShared();
}

CJS_Global::~CJS_Global() {
  // TODO(tsepez): is order really important here?
  m_MapGlobal.clear();
  m_pGlobalData->Release();
}

CJS_Result CJS_Global::QueryProperty(const wchar_t* propname) {
  if (WideString(propname) != L"setPersistent")
    return CJS_Result::Failure(JSMessage::kUnknownProperty);
  return CJS_Result::Success();
}

CJS_Result CJS_Global::DelProperty(CJS_Runtime* pRuntime,
                                   const wchar_t* propname) {
  auto it = m_MapGlobal.find(WideString(propname).ToDefANSI());
  if (it == m_MapGlobal.end())
    return CJS_Result::Failure(JSMessage::kUnknownProperty);

  it->second->bDeleted = true;
  return CJS_Result::Success();
}

CJS_Result CJS_Global::GetProperty(CJS_Runtime* pRuntime,
                                   const wchar_t* propname) {
  auto it = m_MapGlobal.find(WideString(propname).ToDefANSI());
  if (it == m_MapGlobal.end())
    return CJS_Result::Success();

  JSGlobalData* pData = it->second.get();
  if (pData->bDeleted)
    return CJS_Result::Success();

  return CJS_Result::Success(
      v8::Local<v8::Value>::New(pRuntime->GetIsolate(), pData->pV8Value));
}

CJS_Result CJS_Global::SetProperty(CJS_Runtime* pRuntime,
                                   const wchar_t* propname,
                                   v8::Local<v8::Value> vp) {
  ByteString sPropName = WideString(propname).ToDefANSI();
  if (vp->IsNumber() || vp->IsBoolean() || vp->IsString() || vp->IsObject() ||
      vp->IsNull()) {
    m_MapGlobal[sPropName] =
        pdfium::MakeUnique<JSGlobalData>(pRuntime->GetIsolate(), vp);
    return CJS_Result::Success(vp);
  }
  if (vp->IsUndefined()) {
    DelProperty(pRuntime, propname);
    return CJS_Result::Success();
  }
  return CJS_Result::Failure(JSMessage::kObjectTypeError);
}

CJS_Result CJS_Global::setPersistent(
    CJS_Runtime* pRuntime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 2)
    return CJS_Result::Failure(JSMessage::kParamError);

  auto it = m_MapGlobal.find(pRuntime->ToWideString(params[0]).ToDefANSI());
  if (it == m_MapGlobal.end() || it->second->bDeleted)
    return CJS_Result::Failure(JSMessage::kGlobalNotFoundError);

  it->second->bPersistent = pRuntime->ToBoolean(params[1]);
  return CJS_Result::Success();
}

void CJS_Global::UpdateGlobalVariablesFromShared() {
  CJS_Runtime* pRuntime = GetRuntime();
  if (!pRuntime)
    return;

  for (int i = 0; i < m_pGlobalData->GetSize(); i++) {
    CFX_GlobalData::Element* pData = m_pGlobalData->GetAt(i);
    std::unique_ptr<JSGlobalData> pValue = FromCFXValue(&pData->data);
    if (pValue)
      m_MapGlobal[pData->data.sKey] = std::move(pValue);
  }
}

void CJS_Global::CommitGlobalVariablesToShared() {
  CJS_Runtime* pRuntime = GetRuntime();
  if (!pRuntime)
    return;

  for (const auto& iter : m_MapGlobal) {
    ByteString name = iter.first;
    JSGlobalData* pData = iter.second.get();
    if (pData->bDeleted) {
      m_pGlobalData->DeleteGlobalVariable(name);
      continue;
    }
    std::unique_ptr<CFX_Value> pValue = ToCFXValue(pData);
    if (!pValue)
      continue;

    m_pGlobalData->SetGlobalVariable(name, std::move(pValue));
    m_pGlobalData->SetGlobalVariablePersistent(name, pData->bPersistent);
  }
}

std::unique_ptr<CFX_Value> CJS_Global::ToCFXValue(JSGlobalData* pData) {
  return nullptr;
}

std::unique_ptr<CJS_Global::JSGlobalData> CJS_Global::FromCFXValue(
    CFX_Value* pValue) {
  return nullptr;
}
