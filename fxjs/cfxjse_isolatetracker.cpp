// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cfxjse_isolatetracker.h"

CFXJSE_ScopeUtil_IsolateHandle::CFXJSE_ScopeUtil_IsolateHandle(
    v8::Isolate* pIsolate)
    : m_isolate(pIsolate), m_iscope(pIsolate), m_hscope(pIsolate) {}

CFXJSE_ScopeUtil_IsolateHandle::~CFXJSE_ScopeUtil_IsolateHandle() = default;

CFXJSE_ScopeUtil_IsolateHandleRootContext::
    CFXJSE_ScopeUtil_IsolateHandleRootContext(v8::Isolate* pIsolate)
    : m_parent(pIsolate),
      m_context(v8::Local<v8::Context>::New(
          pIsolate,
          CFXJSE_RuntimeData::Get(pIsolate)->m_hRootContext)),
      m_cscope(m_context) {}

CFXJSE_ScopeUtil_IsolateHandleRootContext::
    ~CFXJSE_ScopeUtil_IsolateHandleRootContext() = default;
