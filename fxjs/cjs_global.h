// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_CJS_GLOBAL_H_
#define FXJS_CJS_GLOBAL_H_

#include <map>
#include <memory>
#include <vector>

#include "fxjs/cfx_keyvalue.h"
#include "fxjs/cjs_object.h"
#include "fxjs/cjs_result.h"

class CFX_GlobalData;

class CJS_Global final : public CJS_Object {
 public:
  static int GetObjDefnID();
  static void DefineJSObjects(CFXJS_Engine* pEngine);
  static void DefineAllProperties(CFXJS_Engine* pEngine);

  static void queryprop_static(
      v8::Local<v8::Name> property,
      const v8::PropertyCallbackInfo<v8::Integer>& info);
  static void getprop_static(v8::Local<v8::Name> property,
                             const v8::PropertyCallbackInfo<v8::Value>& info);
  static void putprop_static(v8::Local<v8::Name> property,
                             v8::Local<v8::Value> value,
                             const v8::PropertyCallbackInfo<v8::Value>& info);
  static void delprop_static(v8::Local<v8::Name> property,
                             const v8::PropertyCallbackInfo<v8::Boolean>& info);

  static void setPersistent_static(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  CJS_Global(v8::Local<v8::Object> pObject, CJS_Runtime* pRuntime);
  ~CJS_Global() override;

  CJS_Result DelProperty(CJS_Runtime* pRuntime, const wchar_t* propname);

  CJS_Result setPersistent(CJS_Runtime* pRuntime,
                           const std::vector<v8::Local<v8::Value>>& params);
  CJS_Result QueryProperty(const wchar_t* propname);
  CJS_Result GetProperty(CJS_Runtime* pRuntime, const wchar_t* propname);
  CJS_Result SetProperty(CJS_Runtime* pRuntime,
                         const wchar_t* propname,
                         v8::Local<v8::Value> vp);

 private:
  struct JSGlobalData {
   public:
    JSGlobalData();
    JSGlobalData(v8::Isolate* pIsolate, v8::Local<v8::Value> vp);
    ~JSGlobalData();

    v8::Global<v8::Value> pV8Value;
    bool bPersistent = false;
    bool bDeleted = false;
  };

  static int ObjDefnID;
  static const JSMethodSpec MethodSpecs[];

  void UpdateGlobalVariablesFromShared();
  void CommitGlobalVariablesToShared();
  std::unique_ptr<CFX_Value> ToCFXValue(JSGlobalData* pData);
  std::unique_ptr<JSGlobalData> FromCFXValue(CFX_Value* value);

  CFX_GlobalData* m_pGlobalData;
  CPDFSDK_FormFillEnvironment::ObservedPtr m_pFormFillEnv;
  std::map<ByteString, std::unique_ptr<JSGlobalData>> m_MapGlobal;
};

#endif  // FXJS_CJS_GLOBAL_H_
