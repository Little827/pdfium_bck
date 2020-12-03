// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_XFA_CFXJSE_VALUE_H_
#define FXJS_XFA_CFXJSE_VALUE_H_

#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "v8/include/v8.h"

// Abstraction of a v8::Global that can be used in an environment
// free of any handle-contexts. v8::Locals should be used in all
// other places.
class CFXJSE_Value {
 public:
  CFXJSE_Value(v8::Isolate* pIsolate, v8::Local<v8::Value> value);
  CFXJSE_Value(const CFXJSE_Value&) = delete;
  CFXJSE_Value& operator=(const CFXJSE_Value&) = delete;
  ~CFXJSE_Value();

  bool IsEmpty() const;
  bool IsUndefined(v8::Isolate* pIsolate) const;
  bool IsNull(v8::Isolate* pIsolate) const;
  bool IsBoolean(v8::Isolate* pIsolate) const;
  bool IsString(v8::Isolate* pIsolate) const;

  bool ToBoolean(v8::Isolate* pIsolate) const;
  ByteString ToByteString(v8::Isolate* pIsolate) const;
  WideString ToWideString(v8::Isolate* pIsolate) const;
  v8::Local<v8::Value> GetValue(v8::Isolate* pIsolate) const;

 private:
  v8::Global<v8::Value> m_hValue;
};

#endif  // FXJS_XFA_CFXJSE_VALUE_H_
