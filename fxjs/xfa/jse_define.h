// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_XFA_JSE_DEFINE_H_
#define FXJS_XFA_JSE_DEFINE_H_

#include <vector>

#include "fxjs/cjs_result.h"

class CFX_V8;

#define JSE_METHOD(method_name)                                      \
  static CJS_Result method_name##_static(                            \
      CJX_Object* node, CFX_V8* runtime,                             \
      const std::vector<v8::Local<v8::Value>>& params) {             \
    if (!node->DynamicTypeIs(static_type__))                         \
      return CJS_Result::Failure(JSMessage::kBadObjectError);        \
    return static_cast<Type__*>(node)->method_name(runtime, params); \
  }                                                                  \
  CJS_Result method_name(CFX_V8* runtime,                            \
                         const std::vector<v8::Local<v8::Value>>& params)

#define JSE_PROP(prop_name)                                                 \
  static void prop_name##_static(v8::Isolate* pIsolate, CJX_Object* node,   \
                                 v8::Local<v8::Value>* value, bool setting, \
                                 XFA_Attribute attribute) {                 \
    if (node->DynamicTypeIs(static_type__)) {                               \
      auto* obj = static_cast<Type__*>(node);                               \
      if (setting) {                                                        \
        obj->prop_name##Setter(pIsolate, attribute, *value);                \
      } else {                                                              \
        *value = obj->prop_name##Getter(pIsolate, attribute);               \
      }                                                                     \
    }                                                                       \
  }                                                                         \
  v8::Local<v8::Value> prop_name##Getter(v8::Isolate* pIsolate,             \
                                         XFA_Attribute eAttribute);         \
  void prop_name##Setter(v8::Isolate* pIsolate, XFA_Attribute eAttribute,   \
                         v8::Local<v8::Value> pValue)

#endif  // FXJS_XFA_JSE_DEFINE_H_
