// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cjs_runtime.h"

#include <algorithm>
#include <iostream>

#include "fpdfsdk/cpdfsdk_formfillenvironment.h"
#include "fxjs/JS_Define.h"
#include "fxjs/cjs_annot.h"
#include "fxjs/cjs_app.h"
#include "fxjs/cjs_border.h"
#include "fxjs/cjs_color.h"
#include "fxjs/cjs_console.h"
#include "fxjs/cjs_display.h"
#include "fxjs/cjs_document.h"
#include "fxjs/cjs_event.h"
#include "fxjs/cjs_event_context.h"
#include "fxjs/cjs_eventhandler.h"
#include "fxjs/cjs_field.h"
#include "fxjs/cjs_font.h"
#include "fxjs/cjs_global.h"
#include "fxjs/cjs_globalarrays.h"
#include "fxjs/cjs_globalconsts.h"
#include "fxjs/cjs_globaldata.h"
#include "fxjs/cjs_highlight.h"
#include "fxjs/cjs_icon.h"
#include "fxjs/cjs_object.h"
#include "fxjs/cjs_position.h"
#include "fxjs/cjs_printparamsobj.h"
#include "fxjs/cjs_publicmethods.h"
#include "fxjs/cjs_report.h"
#include "fxjs/cjs_scalehow.h"
#include "fxjs/cjs_scalewhen.h"
#include "fxjs/cjs_style.h"
#include "fxjs/cjs_timerobj.h"
#include "fxjs/cjs_util.h"
#include "fxjs/cjs_zoomtype.h"
#include "public/fpdf_formfill.h"
#include "third_party/base/stl_util.h"
#include "fxjs/cjs_event_context_stub.h"

#ifdef PDF_ENABLE_XFA
#include "fxjs/cfxjse_value.h"
#endif  // PDF_ENABLE_XFA

// static
CJS_Runtime* CJS_Runtime::RuntimeFromIsolateCurrentContext(
    v8::Isolate* pIsolate) {
  return static_cast<CJS_Runtime*>(
      CFXJS_Engine::EngineFromIsolateCurrentContext(pIsolate));
}

CJS_Runtime::CJS_Runtime(CPDFSDK_FormFillEnvironment* pFormFillEnv)
    : m_pFormFillEnv(pFormFillEnv),
      m_bBlocking(false),
      m_isolateManaged(false) {
  std::cerr << "CJS_Runtime::CJS_Runtime" << std::endl;
  v8::Isolate* pIsolate = nullptr;

  IPDF_JSPLATFORM* pPlatform = m_pFormFillEnv->GetFormFillInfo()->m_pJsPlatform;
  if (pPlatform->version <= 2) {
    unsigned int embedderDataSlot = 0;
    v8::Isolate* pExternalIsolate = nullptr;
    if (pPlatform->version == 2) {
      pExternalIsolate = static_cast<v8::Isolate*>(pPlatform->m_isolate);
      embedderDataSlot = pPlatform->m_v8EmbedderSlot;
    }
    FXJS_Initialize(embedderDataSlot, pExternalIsolate);
  }
  m_isolateManaged = FXJS_GetIsolate(&pIsolate);
  SetIsolate(pIsolate);

#ifdef PDF_ENABLE_XFA
  v8::Isolate::Scope isolate_scope(pIsolate);
  v8::HandleScope handle_scope(pIsolate);
#endif

  if (m_isolateManaged || FXJS_GlobalIsolateRefCount() == 0)
    DefineJSObjects();

  IJS_EventContext* pContext = NewEventContext();
  InitializeEngine();
  ReleaseEventContext(pContext);
  SetFormFillEnvToDocument();
}

CJS_Runtime::~CJS_Runtime() {
  std::cerr << "CJS_Runtime::~CJS_Runtime" << std::endl;
  NotifyObservedPtrs();
  ReleaseEngine();
  if (m_isolateManaged) {
    GetIsolate()->Dispose();
    SetIsolate(nullptr);
  }
}

void CJS_Runtime::DefineJSObjects() {
  std::cerr << "CJS_Runtime::DefineJSObjects" << std::endl;

  v8::Isolate::Scope isolate_scope(GetIsolate());
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Context> context = v8::Context::New(GetIsolate());
  v8::Context::Scope context_scope(context);

  // The call order determines the "ObjDefID" assigned to each class.
  // ObjDefIDs 0 - 2
  CJS_Border::DefineJSObjects(this);
  CJS_Display::DefineJSObjects(this);
  CJS_Font::DefineJSObjects(this);

  // ObjDefIDs 3 - 5
  CJS_Highlight::DefineJSObjects(this);
  CJS_Position::DefineJSObjects(this);
  CJS_ScaleHow::DefineJSObjects(this);

  // ObjDefIDs 6 - 8
  CJS_ScaleWhen::DefineJSObjects(this);
  CJS_Style::DefineJSObjects(this);
  CJS_Zoomtype::DefineJSObjects(this);

  // ObjDefIDs 9 - 11
  CJS_App::DefineJSObjects(this);
  CJS_Color::DefineJSObjects(this);
  CJS_Console::DefineJSObjects(this);

  // ObjDefIDs 12 - 14
  CJS_Document::DefineJSObjects(this);
  CJS_Event::DefineJSObjects(this);
  CJS_Field::DefineJSObjects(this);

  // ObjDefIDs 15 - 17
  CJS_Global::DefineJSObjects(this);
  CJS_Icon::DefineJSObjects(this);
  CJS_Util::DefineJSObjects(this);

  // ObjDefIDs 18 - 20 (these can't fail, return void).
  CJS_PublicMethods::DefineJSObjects(this);
  CJS_GlobalConsts::DefineJSObjects(this);
  CJS_GlobalArrays::DefineJSObjects(this);

  // ObjDefIDs 21 - 23.
  CJS_TimerObj::DefineJSObjects(this);
  CJS_PrintParamsObj::DefineJSObjects(this);
  CJS_Annot::DefineJSObjects(this);
}

CJS_Runtime* CJS_Runtime::AsCJSRuntime() {
  std::cerr << "CJS_Runtime::AsCJSRuntime" << std::endl;
  return this;
  // return nullptr;
}

IJS_EventContext* CJS_Runtime::NewEventContext() {
  std::cerr << "CJS_Runtime::NewEventContext" << std::endl;

  // m_EventContextArray.push_back(pdfium::MakeUnique<CJS_EventContext>(this));
  // return m_EventContextArray.back().get();

  if (!m_pContext)
    m_pContext = pdfium::MakeUnique<CJS_EventContextStub>();
  return m_pContext.get();
}

void CJS_Runtime::ReleaseEventContext(IJS_EventContext* pContext) {
  std::cerr << "CJS_Runtime::ReleaseEventContext" << std::endl;

  auto it = std::find(m_EventContextArray.begin(), m_EventContextArray.end(),
                      pdfium::FakeUniquePtr<CJS_EventContext>(
                          static_cast<CJS_EventContext*>(pContext)));
  if (it != m_EventContextArray.end())
    m_EventContextArray.erase(it);

  // Do nothing
}

CJS_EventContext* CJS_Runtime::GetCurrentEventContext() const {
  std::cerr << "CJS_Runtime::GetCurrentEventContext" << std::endl;
  return m_EventContextArray.empty() ? nullptr
                                     : m_EventContextArray.back().get();
}

void CJS_Runtime::SetFormFillEnvToDocument() {
  std::cerr << "CJS_Runtime::SetFormFillEnvToDocument" << std::endl;
  v8::Isolate::Scope isolate_scope(GetIsolate());
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Context> context = GetV8Context();
  v8::Context::Scope context_scope(context);

  v8::Local<v8::Object> pThis = GetThisObj();
  if (pThis.IsEmpty())
    return;

  if (CFXJS_Engine::GetObjDefnID(pThis) != CJS_Document::GetObjDefnID())
    return;

  CJS_Document* pJSDocument =
      static_cast<CJS_Document*>(GetObjectPrivate(pThis));
  if (!pJSDocument)
    return;

  pJSDocument->SetFormFillEnv(m_pFormFillEnv.Get());
}

CPDFSDK_FormFillEnvironment* CJS_Runtime::GetFormFillEnv() const {
  std::cerr << "CJS_Runtime::GetFormFillEnv" << std::endl;
  return m_pFormFillEnv.Get();
}

Optional<IJS_Runtime::JS_Error> CJS_Runtime::ExecuteScript(
    const WideString& script) {
  std::cerr << "CJS_Runtime::ExecuteScript" << std::endl;
  // return Execute(script);
  return {};
}

bool CJS_Runtime::AddEventToSet(const FieldEvent& event) {
  std::cerr << "CJS_Runtime::AddEventToSet" << std::endl;
  return m_FieldEventSet.insert(event).second;
}

void CJS_Runtime::RemoveEventFromSet(const FieldEvent& event) {
  std::cerr << "CJS_Runtime::RemoveEventFromSet" << std::endl;
  m_FieldEventSet.erase(event);
}

#ifdef PDF_ENABLE_XFA
WideString ChangeObjName(const WideString& str) {
  std::cerr << "CJS_Runtime::ChangeObjName" << std::endl;
  WideString sRet = str;
  sRet.Replace(L"_", L".");
  return sRet;
}

bool CJS_Runtime::GetValueByNameFromGlobalObject(const ByteStringView& utf8Name,
                                                 CFXJSE_Value* pValue) {
  std::cerr << "CJS_Runtime::GetValueByNameFromGlobalObject" << std::endl;
  v8::Isolate::Scope isolate_scope(GetIsolate());
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Context> context = GetV8Context();
  v8::Context::Scope context_scope(context);
  v8::Local<v8::Value> propvalue = context->Global()->Get(
      v8::String::NewFromUtf8(GetIsolate(), utf8Name.unterminated_c_str(),
                              v8::String::kNormalString, utf8Name.GetLength()));
  if (propvalue.IsEmpty()) {
    pValue->SetUndefined();
    return false;
  }
  pValue->ForceSetValue(propvalue);
  return true;
}

bool CJS_Runtime::SetValueByNameInGlobalObject(const ByteStringView& utf8Name,
                                               CFXJSE_Value* pValue) {
  std::cerr << "CJS_Runtime::SetValueByNameInGlobalObject" << std::endl;
  if (utf8Name.IsEmpty() || !pValue)
    return false;

  v8::Isolate* pIsolate = GetIsolate();
  v8::Isolate::Scope isolate_scope(pIsolate);
  v8::HandleScope handle_scope(pIsolate);
  v8::Local<v8::Context> context = GetV8Context();
  v8::Context::Scope context_scope(context);
  v8::Local<v8::Value> propvalue =
      v8::Local<v8::Value>::New(pIsolate, pValue->DirectGetValue());
  context->Global()->Set(
      v8::String::NewFromUtf8(pIsolate, utf8Name.unterminated_c_str(),
                              v8::String::kNormalString, utf8Name.GetLength()),
      propvalue);
  return true;
}
#endif

v8::Local<v8::Value> CJS_Runtime::MaybeCoerceToNumber(
    v8::Local<v8::Value> value) {
  std::cerr << "CJS_Runtime::MaybeCoerceToNumber" << std::endl;
  bool bAllowNaN = false;
  if (value->IsString()) {
    ByteString bstr = ByteString::FromUnicode(ToWideString(value));
    if (bstr.GetLength() == 0)
      return value;
    if (bstr == "NaN")
      bAllowNaN = true;
  }

  v8::Isolate* pIsolate = GetIsolate();
  v8::TryCatch try_catch(pIsolate);
  v8::MaybeLocal<v8::Number> maybeNum =
      value->ToNumber(pIsolate->GetCurrentContext());
  if (maybeNum.IsEmpty())
    return value;

  v8::Local<v8::Number> num = maybeNum.ToLocalChecked();
  if (std::isnan(num->Value()) && !bAllowNaN)
    return value;

  return num;
}
