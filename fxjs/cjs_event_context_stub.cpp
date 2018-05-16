// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/cjs_event_context_stub.h"

Optional<CFXJS_Error> CJS_EventContextStub::RunScript(
    const WideString& script) {
  return {CFXJS_Error(1, 1, L"Not implemented in Stub context")};
}
