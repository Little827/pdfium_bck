// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/cxfa_deltas.h"

#include <memory>

#include "fxjs/xfa/cjx_node.h"
#include "xfa/fxfa/parser/cxfa_document.h"

CXFA_Deltas::CXFA_Deltas(CXFA_Document* pDocument, XFA_PacketType packet)
    : CXFA_Node(pDocument,
                packet,
                {XFA_XDPPACKET::kTemplate, XFA_XDPPACKET::kForm},
                XFA_ObjectType::Node,
                XFA_Element::Deltas,
                {},
                {},
                cppgc::MakeGarbageCollected<CJX_Node>(
                    pDocument->GetHeap()->GetAllocationHandle(),
                    this)) {}

CXFA_Deltas::~CXFA_Deltas() = default;
