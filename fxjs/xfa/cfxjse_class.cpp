// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cfxjse_class.h"

#include <memory>
#include <utility>

#include "fxjs/cfx_v8.h"
#include "fxjs/cjs_result.h"
#include "fxjs/fxv8.h"
#include "fxjs/js_resources.h"
#include "fxjs/xfa/cfxjse_context.h"
#include "fxjs/xfa/cfxjse_isolatetracker.h"
#include "fxjs/xfa/cfxjse_value.h"

using pdfium::fxjse::kClassTag;
using pdfium::fxjse::kFuncTag;

namespace {

FXJSE_FUNCTION_DESCRIPTOR* AsFunctionDescriptor(void* ptr) {
  auto* result = static_cast<FXJSE_FUNCTION_DESCRIPTOR*>(ptr);
  return result && result->tag == kFuncTag ? result : nullptr;
}

FXJSE_CLASS_DESCRIPTOR* AsClassDescriptor(void* ptr) {
  auto* result = static_cast<FXJSE_CLASS_DESCRIPTOR*>(ptr);
  return result && result->tag == kClassTag ? result : nullptr;
}

void V8FunctionCallback_Wrapper(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  const FXJSE_FUNCTION_DESCRIPTOR* pFunctionInfo =
      AsFunctionDescriptor(info.Data().As<v8::External>()->Value());
  if (!pFunctionInfo)
    return;

  pFunctionInfo->callbackProc(CFXJSE_HostObject::FromV8(info.Holder()), info);
}

void V8ConstructorCallback_Wrapper(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (!info.IsConstructCall())
    return;

  const FXJSE_CLASS_DESCRIPTOR* pClassDefinition =
      AsClassDescriptor(info.Data().As<v8::External>()->Value());
  if (!pClassDefinition)
    return;

  ASSERT(info.Holder()->InternalFieldCount() == 2);
  info.Holder()->SetAlignedPointerInInternalField(0, nullptr);
  info.Holder()->SetAlignedPointerInInternalField(1, nullptr);
}

void Context_GlobalObjToString(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  const FXJSE_CLASS_DESCRIPTOR* pClass =
      AsClassDescriptor(info.Data().As<v8::External>()->Value());
  if (!pClass)
    return;

  if (info.This() == info.Holder() && pClass->name) {
    ByteString szStringVal = ByteString::Format("[object %s]", pClass->name);
    info.GetReturnValue().Set(
        fxv8::NewStringHelper(info.GetIsolate(), szStringVal.AsStringView()));
    return;
  }
  v8::Local<v8::String> local_str =
      info.Holder()
          ->ObjectProtoToString(info.GetIsolate()->GetCurrentContext())
          .FromMaybe(v8::Local<v8::String>());
  info.GetReturnValue().Set(local_str);
}

void DynPropGetterAdapter_MethodCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Object> hCallBackInfo = info.Data().As<v8::Object>();
  if (hCallBackInfo->InternalFieldCount() != 2)
    return;

  auto* pClassDescriptor = static_cast<const FXJSE_CLASS_DESCRIPTOR*>(
      hCallBackInfo->GetAlignedPointerFromInternalField(0));
  if (pClassDescriptor != &GlobalClassDescriptor &&
      pClassDescriptor != &NormalClassDescriptor &&
      pClassDescriptor != &VariablesClassDescriptor &&
      pClassDescriptor != &kFormCalcFM2JSDescriptor) {
    return;
  }

  v8::Local<v8::String> hPropName =
      hCallBackInfo->GetInternalField(1).As<v8::String>();
  if (hPropName.IsEmpty())
    return;

  v8::String::Utf8Value szPropName(info.GetIsolate(), hPropName);
  CJS_Result result =
      pClassDescriptor->dynMethodCall(info, WideString::FromUTF8(*szPropName));

  if (result.HasError()) {
    WideString err = JSFormatErrorString(pClassDescriptor->name, *szPropName,
                                         result.Error());
    fxv8::ThrowExceptionHelper(info.GetIsolate(), err.AsStringView());
    return;
  }

  if (result.HasReturn())
    info.GetReturnValue().Set(result.Return());
}

v8::Local<v8::Value> DynPropGetterAdapter(v8::Isolate* pIsolate,
                                          const FXJSE_CLASS_DESCRIPTOR* pClass,
                                          v8::Local<v8::Object> pThisObject,
                                          ByteStringView szPropName) {
  ASSERT(pClass);
  auto pObject = std::make_unique<CFXJSE_Value>(pIsolate, pThisObject);
  int32_t nPropType =
      pClass->dynPropTypeGetter
          ? pClass->dynPropTypeGetter(pObject.get(), szPropName, false)
          : FXJSE_ClassPropType_Property;
  if (nPropType == FXJSE_ClassPropType_Property) {
    auto pValue = std::make_unique<CFXJSE_Value>(pIsolate);
    if (pClass->dynPropGetter)
      pClass->dynPropGetter(pObject.get(), szPropName, pValue.get());
    return pValue->GetValue();
  }
  if (nPropType == FXJSE_ClassPropType_Method) {
    if (pClass->dynMethodCall) {
      v8::HandleScope hscope(pIsolate);
      v8::Local<v8::ObjectTemplate> hCallBackInfoTemplate =
          v8::ObjectTemplate::New(pIsolate);
      hCallBackInfoTemplate->SetInternalFieldCount(2);
      v8::Local<v8::Object> hCallBackInfo =
          hCallBackInfoTemplate->NewInstance(pIsolate->GetCurrentContext())
              .ToLocalChecked();
      hCallBackInfo->SetAlignedPointerInInternalField(
          0, const_cast<FXJSE_CLASS_DESCRIPTOR*>(pClass));
      hCallBackInfo->SetInternalField(
          1, fxv8::NewStringHelper(pIsolate, szPropName));
      return v8::Function::New(pIsolate->GetCurrentContext(),
                               DynPropGetterAdapter_MethodCallback,
                               hCallBackInfo, 0,
                               v8::ConstructorBehavior::kThrow)
          .ToLocalChecked();
    }
  }
  return v8::Local<v8::Value>();
}

v8::Local<v8::Value> DynPropSetterAdapter(v8::Isolate* pIsolate,
                                          const FXJSE_CLASS_DESCRIPTOR* pClass,
                                          v8::Local<v8::Object> thisObject,
                                          ByteStringView szPropName,
                                          v8::Local<v8::Value> value) {
  auto pThisValue = std::make_unique<CFXJSE_Value>(pIsolate, thisObject);
  int32_t nPropType =
      pClass->dynPropTypeGetter
          ? pClass->dynPropTypeGetter(pThisValue.get(), szPropName, false)
          : FXJSE_ClassPropType_Property;
  if (nPropType != FXJSE_ClassPropType_Method) {
    if (pClass->dynPropSetter) {
      auto pNewValue = std::make_unique<CFXJSE_Value>(pIsolate, value);
      pClass->dynPropSetter(pThisValue.get(), szPropName, pNewValue.get());
    }
  }
  // TODO(tsepez): Could the V8 object modify it? We don't update.
  return value;
}

bool DynPropQueryAdapter(v8::Isolate* pIsolate,
                         const FXJSE_CLASS_DESCRIPTOR* pClass,
                         v8::Local<v8::Object> thisObject,
                         ByteStringView szPropName) {
  if (!pClass->dynPropTypeGetter)
    return false;

  auto pObject = std::make_unique<CFXJSE_Value>(pIsolate, thisObject);
  return pClass->dynPropTypeGetter(pObject.get(), szPropName, true) !=
         FXJSE_ClassPropType_None;
}

void NamedPropertyQueryCallback(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Integer>& info) {
  const FXJSE_CLASS_DESCRIPTOR* pClass =
      AsClassDescriptor(info.Data().As<v8::External>()->Value());
  if (!pClass)
    return;

  v8::HandleScope scope(info.GetIsolate());
  v8::String::Utf8Value szPropName(info.GetIsolate(), property);
  ByteStringView szFxPropName(*szPropName, szPropName.length());
  if (DynPropQueryAdapter(info.GetIsolate(), pClass, info.Holder(),
                          szFxPropName)) {
    info.GetReturnValue().Set(v8::DontDelete);
    return;
  }
  const int32_t iV8Absent = 64;
  info.GetReturnValue().Set(iV8Absent);
}

void NamedPropertyGetterCallback(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  const FXJSE_CLASS_DESCRIPTOR* pClass =
      AsClassDescriptor(info.Data().As<v8::External>()->Value());
  if (!pClass)
    return;

  v8::String::Utf8Value szPropName(info.GetIsolate(), property);
  ByteStringView szFxPropName(*szPropName, szPropName.length());
  info.GetReturnValue().Set(DynPropGetterAdapter(info.GetIsolate(), pClass,
                                                 info.Holder(), szFxPropName));
}

void NamedPropertySetterCallback(
    v8::Local<v8::Name> property,
    v8::Local<v8::Value> value,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  const FXJSE_CLASS_DESCRIPTOR* pClass =
      AsClassDescriptor(info.Data().As<v8::External>()->Value());
  if (!pClass)
    return;

  v8::String::Utf8Value szPropName(info.GetIsolate(), property);
  ByteStringView szFxPropName(*szPropName, szPropName.length());
  info.GetReturnValue().Set(DynPropSetterAdapter(
      info.GetIsolate(), pClass, info.Holder(), szFxPropName, value));
}

void NamedPropertyEnumeratorCallback(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  info.GetReturnValue().Set(v8::Array::New(info.GetIsolate()));
}

void SetUpNamedPropHandler(v8::Isolate* pIsolate,
                           v8::Local<v8::ObjectTemplate>* pObjectTemplate,
                           const FXJSE_CLASS_DESCRIPTOR* pClassDefinition) {
  v8::NamedPropertyHandlerConfiguration configuration(
      pClassDefinition->dynPropGetter ? NamedPropertyGetterCallback : nullptr,
      pClassDefinition->dynPropSetter ? NamedPropertySetterCallback : nullptr,
      pClassDefinition->dynPropTypeGetter ? NamedPropertyQueryCallback
                                          : nullptr,
      nullptr, NamedPropertyEnumeratorCallback,
      v8::External::New(pIsolate,
                        const_cast<FXJSE_CLASS_DESCRIPTOR*>(pClassDefinition)),
      v8::PropertyHandlerFlags::kNonMasking);
  (*pObjectTemplate)->SetHandler(configuration);
}

}  // namespace

// static
CFXJSE_Class* CFXJSE_Class::Create(
    CFXJSE_Context* pContext,
    const FXJSE_CLASS_DESCRIPTOR* pClassDefinition,
    bool bIsJSGlobal) {
  if (!pContext || !pClassDefinition)
    return nullptr;

  CFXJSE_Class* pExistingClass =
      pContext->GetClassByName(pClassDefinition->name);
  if (pExistingClass)
    return pExistingClass;

  v8::Isolate* pIsolate = pContext->GetIsolate();
  auto pClass = std::make_unique<CFXJSE_Class>(pContext);
  pClass->m_szClassName = pClassDefinition->name;
  pClass->m_pClassDefinition = pClassDefinition;
  CFXJSE_ScopeUtil_IsolateHandleRootContext scope(pIsolate);
  v8::Local<v8::FunctionTemplate> hFunctionTemplate = v8::FunctionTemplate::New(
      pIsolate, bIsJSGlobal ? 0 : V8ConstructorCallback_Wrapper,
      v8::External::New(pIsolate,
                        const_cast<FXJSE_CLASS_DESCRIPTOR*>(pClassDefinition)));
  v8::Local<v8::String> classname =
      fxv8::NewStringHelper(pIsolate, pClassDefinition->name);
  hFunctionTemplate->SetClassName(classname);
  hFunctionTemplate->PrototypeTemplate()->Set(
      v8::Symbol::GetToStringTag(pIsolate), classname,
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
  hFunctionTemplate->InstanceTemplate()->SetInternalFieldCount(2);
  v8::Local<v8::ObjectTemplate> hObjectTemplate =
      hFunctionTemplate->InstanceTemplate();
  SetUpNamedPropHandler(pIsolate, &hObjectTemplate, pClassDefinition);

  if (pClassDefinition->methNum) {
    for (int32_t i = 0; i < pClassDefinition->methNum; i++) {
      v8::Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(
          pIsolate, V8FunctionCallback_Wrapper,
          v8::External::New(pIsolate, const_cast<FXJSE_FUNCTION_DESCRIPTOR*>(
                                          pClassDefinition->methods + i)));
      fun->RemovePrototype();
      hObjectTemplate->Set(
          fxv8::NewStringHelper(pIsolate, pClassDefinition->methods[i].name),
          fun,
          static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontDelete));
    }
  }

  if (bIsJSGlobal) {
    v8::Local<v8::FunctionTemplate> fn = v8::FunctionTemplate::New(
        pIsolate, Context_GlobalObjToString,
        v8::External::New(
            pIsolate, const_cast<FXJSE_CLASS_DESCRIPTOR*>(pClassDefinition)));
    fn->RemovePrototype();
    hObjectTemplate->Set(fxv8::NewStringHelper(pIsolate, "toString"), fn);
  }
  pClass->m_hTemplate.Reset(pContext->GetIsolate(), hFunctionTemplate);
  CFXJSE_Class* pResult = pClass.get();
  pContext->AddClass(std::move(pClass));
  return pResult;
}

CFXJSE_Class::CFXJSE_Class(CFXJSE_Context* pContext) : m_pContext(pContext) {}

CFXJSE_Class::~CFXJSE_Class() = default;
