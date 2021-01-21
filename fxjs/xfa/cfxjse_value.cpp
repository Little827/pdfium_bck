// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cfxjse_value.h"

#include <math.h>

#include "fxjs/cfx_v8.h"
#include "fxjs/fxv8.h"
#include "fxjs/xfa/cfxjse_class.h"
#include "fxjs/xfa/cfxjse_context.h"
#include "fxjs/xfa/cfxjse_isolatetracker.h"

CFXJSE_Value::CFXJSE_Value(v8::Isolate* pIsolate,
                           bool success,
                           v8::Local<v8::Value> value)
    : is_success_(success) {
  value_.Reset(pIsolate, value);
}

CFXJSE_Value::~CFXJSE_Value() = default;

bool CFXJSE_Value::IsEmpty() const {
  return value_.IsEmpty();
}

bool CFXJSE_Value::IsUndefined(v8::Isolate* pIsolate) const {
  if (IsEmpty())
    return false;

  CFXJSE_ScopeUtil_IsolateHandle scope(pIsolate);
  v8::Local<v8::Value> hValue = v8::Local<v8::Value>::New(pIsolate, value_);
  return hValue->IsUndefined();
}

bool CFXJSE_Value::IsNull(v8::Isolate* pIsolate) const {
  if (IsEmpty())
    return false;

  CFXJSE_ScopeUtil_IsolateHandle scope(pIsolate);
  v8::Local<v8::Value> hValue = v8::Local<v8::Value>::New(pIsolate, value_);
  return hValue->IsNull();
}

bool CFXJSE_Value::IsBoolean(v8::Isolate* pIsolate) const {
  if (IsEmpty())
    return false;

  CFXJSE_ScopeUtil_IsolateHandle scope(pIsolate);
  v8::Local<v8::Value> hValue = v8::Local<v8::Value>::New(pIsolate, value_);
  return hValue->IsBoolean();
}

bool CFXJSE_Value::IsString(v8::Isolate* pIsolate) const {
  if (IsEmpty())
    return false;

  CFXJSE_ScopeUtil_IsolateHandle scope(pIsolate);
  v8::Local<v8::Value> hValue = v8::Local<v8::Value>::New(pIsolate, value_);
  return hValue->IsString();
}

bool CFXJSE_Value::ToBoolean(v8::Isolate* pIsolate) const {
  ASSERT(!IsEmpty());
  CFXJSE_ScopeUtil_IsolateHandleRootContext scope(pIsolate);
  return fxv8::ReentrantToBooleanHelper(
      pIsolate, v8::Local<v8::Value>::New(pIsolate, value_));
}

ByteString CFXJSE_Value::ToByteString(v8::Isolate* pIsolate) const {
  ASSERT(!IsEmpty());
  CFXJSE_ScopeUtil_IsolateHandleRootContext scope(pIsolate);
  return fxv8::ReentrantToByteStringHelper(
      pIsolate, v8::Local<v8::Value>::New(pIsolate, value_));
}

WideString CFXJSE_Value::ToWideString(v8::Isolate* pIsolate) const {
  return WideString::FromUTF8(ToByteString(pIsolate).AsStringView());
}

v8::Local<v8::Value> CFXJSE_Value::GetValue(v8::Isolate* pIsolate) const {
  return v8::Local<v8::Value>::New(pIsolate, value_);
}
