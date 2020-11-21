// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_datawindow.h"

#include <vector>

#include "fxjs/fxv8.h"
#include "xfa/fxfa/parser/cscript_datawindow.h"

const CJX_MethodSpec CJX_DataWindow::MethodSpecs[] = {
    {"gotoRecord", gotoRecord_static},
    {"isRecordGroup", isRecordGroup_static},
    {"moveCurrentRecord", moveCurrentRecord_static},
    {"record", record_static}};

CJX_DataWindow::CJX_DataWindow(CScript_DataWindow* window)
    : CJX_Object(window) {
  DefineMethods(MethodSpecs);
}

CJX_DataWindow::~CJX_DataWindow() = default;

bool CJX_DataWindow::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

CJS_Result CJX_DataWindow::moveCurrentRecord(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  return CJS_Result::Success();
}

CJS_Result CJX_DataWindow::record(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  return CJS_Result::Success();
}

CJS_Result CJX_DataWindow::gotoRecord(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  return CJS_Result::Success();
}

CJS_Result CJX_DataWindow::isRecordGroup(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  return CJS_Result::Success();
}

v8::Local<v8::Value> CJX_DataWindow::recordsBeforeGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_DataWindow::recordsBeforeSetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute,
                                         v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_DataWindow::currentRecordNumberGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_DataWindow::currentRecordNumberSetter(v8::Isolate* pIsolate,
                                               XFA_Attribute eAttribute,
                                               v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_DataWindow::recordsAfterGetter(
    v8::Isolate* pIsolate,
    XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_DataWindow::recordsAfterSetter(v8::Isolate* pIsolate,
                                        XFA_Attribute eAttribute,
                                        v8::Local<v8::Value> pValue) {}

v8::Local<v8::Value> CJX_DataWindow::isDefinedGetter(v8::Isolate* pIsolate,
                                                     XFA_Attribute eAttribute) {
  return fxv8::NewUndefinedHelper(pIsolate);
}

void CJX_DataWindow::isDefinedSetter(v8::Isolate* pIsolate,
                                     XFA_Attribute eAttribute,
                                     v8::Local<v8::Value> pValue) {}
