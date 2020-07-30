// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/cscript_logpseudomodel.h"

#include "fxjs/xfa/cjx_logpseudomodel.h"
#include "xfa/fxfa/parser/cxfa_document.h"

CScript_LogPseudoModel::CScript_LogPseudoModel(CXFA_Document* pDocument)
    : CXFA_Object(pDocument,
                  XFA_ObjectType::Object,
                  XFA_Element::LogPseudoModel,
                  cppgc::MakeGarbageCollected<CJX_LogPseudoModel>(
                      pDocument->GetHeap()->GetAllocationHandle(),
                      this)) {}

CScript_LogPseudoModel::~CScript_LogPseudoModel() = default;
