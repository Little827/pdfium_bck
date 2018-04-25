// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/xml/cfx_xmldocument.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/xml/cfx_xmlinstruction.h"
#include "third_party/base/ptr_util.h"

CFX_XMLDocument::CFX_XMLDocument() = default;

CFX_XMLDocument::~CFX_XMLDocument() = default;

void CFX_XMLDocument::SetInstruction(
    std::unique_ptr<CFX_XMLInstruction> instruction) {
  ASSERT(!instruction_);

  instruction_ = instruction.get();
  AddNode(pdfium::WrapUnique<CFX_XMLNode>(instruction.release()));
}
