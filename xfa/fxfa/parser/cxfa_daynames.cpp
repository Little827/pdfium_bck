// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/cxfa_daynames.h"

namespace {

const CXFA_Node::PropertyData kDayNamesPropertyData[] = {
    {XFA_Element::Day, 7, 0},
    {XFA_Element::Unknown, 0, 0}};

const CXFA_Node::AttributeData kDayNamesAttributeData[] = {
    {XFA_Attribute::Abbr, XFA_AttributeType::Boolean, (void*)0},
    {XFA_Attribute::Unknown, XFA_AttributeType::Integer, nullptr}};

}  // namespace

CXFA_DayNames::CXFA_DayNames(CXFA_Document* doc, XFA_PacketType packet)
    : CXFA_Node(doc,
                packet,
                XFA_XDPPACKET_LocaleSet,
                XFA_ObjectType::Node,
                XFA_Element::DayNames,
                kDayNamesAttributeData) {}

CXFA_DayNames::~CXFA_DayNames() = default;

const CXFA_Node::PropertyData* CXFA_DayNames::GetPropertyDataList() const {
  return kDayNamesPropertyData;
}

const CXFA_Node::AttributeData* CXFA_DayNames::GetAttributeDataList() const {
  return kDayNamesAttributeData;
}
