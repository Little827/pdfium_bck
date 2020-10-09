// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/fxjse.h"

#include "fxjs/xfa/cfxjse_context.h"

// static
CFXJSE_HostObject* CFXJSE_HostObject::FromV8(v8::Local<v8::Value> arg) {
  if (arg.IsEmpty() || !arg->IsObject())
    return nullptr;

  return FXJSE_RetrieveObjectBinding(arg.As<v8::Object>());
}

CFXJSE_HostObject::CFXJSE_HostObject() = default;

CFXJSE_HostObject::~CFXJSE_HostObject() = default;

CFXJSE_FormCalcContext* CFXJSE_HostObject::AsFormCalcContext() {
  return nullptr;
}

CJX_Object* CFXJSE_HostObject::AsCJXObject() {
  return nullptr;
}
