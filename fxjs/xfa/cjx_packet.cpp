// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_packet.h"

#include <utility>
#include <vector>

#include "core/fxcrt/xml/cfx_xmldocument.h"
#include "core/fxcrt/xml/cfx_xmlelement.h"
#include "core/fxcrt/xml/cfx_xmltext.h"
#include "fxjs/cfx_v8.h"
#include "fxjs/fxv8.h"
#include "fxjs/js_resources.h"
#include "xfa/fxfa/cxfa_ffdoc.h"
#include "xfa/fxfa/cxfa_ffnotify.h"
#include "xfa/fxfa/parser/cxfa_packet.h"

const CJX_MethodSpec CJX_Packet::MethodSpecs[] = {
    {"getAttribute", getAttribute_static},
    {"removeAttribute", removeAttribute_static},
    {"setAttribute", setAttribute_static}};

CJX_Packet::CJX_Packet(CXFA_Packet* packet) : CJX_Node(packet) {
  DefineMethods(MethodSpecs);
}

CJX_Packet::~CJX_Packet() = default;

bool CJX_Packet::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

CJS_Result CJX_Packet::getAttribute(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 1)
    return CJS_Result::Failure(JSMessage::kParamError);

  WideString attributeValue;
  CFX_XMLElement* element = ToXMLElement(GetXFANode()->GetXMLMappingNode());
  if (element)
    attributeValue = element->GetAttribute(runtime->ToWideString(params[0]));

  return CJS_Result::Success(
      runtime->NewString(attributeValue.ToUTF8().AsStringView()));
}

CJS_Result CJX_Packet::setAttribute(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 2)
    return CJS_Result::Failure(JSMessage::kParamError);

  CFX_XMLElement* element = ToXMLElement(GetXFANode()->GetXMLMappingNode());
  if (element) {
    element->SetAttribute(runtime->ToWideString(params[1]),
                          runtime->ToWideString(params[0]));
  }
  return CJS_Result::Success(runtime->NewNull());
}

CJS_Result CJX_Packet::removeAttribute(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 1)
    return CJS_Result::Failure(JSMessage::kParamError);

  CFX_XMLElement* pElement = ToXMLElement(GetXFANode()->GetXMLMappingNode());
  if (pElement) {
    WideString name = runtime->ToWideString(params[0]);
    if (pElement->HasAttribute(name))
      pElement->RemoveAttribute(name);
  }
  return CJS_Result::Success(runtime->NewNull());
}

v8::Local<v8::Value> CJX_Packet::contentGetter(v8::Isolate* pIsolate,
                                               XFA_Attribute eAttribute) {
  CFX_XMLElement* element = ToXMLElement(GetXFANode()->GetXMLMappingNode());
  WideString wsTextData;
  if (element)
    wsTextData = element->GetTextData();

  return fxv8::NewStringHelper(pIsolate, wsTextData.ToUTF8().AsStringView());
}

void CJX_Packet::contentSetter(v8::Isolate* pIsolate,
                               XFA_Attribute eAttribute,
                               v8::Local<v8::Value> pValue) {
  CFX_XMLElement* element = ToXMLElement(GetXFANode()->GetXMLMappingNode());
  if (!element)
    return;

  WideString wsValue = fxv8::ReentrantToWideStringHelper(pIsolate, pValue);
  element->AppendLastChild(GetXFANode()
                               ->GetDocument()
                               ->GetNotify()
                               ->GetFFDoc()
                               ->GetXMLDocument()
                               ->CreateNode<CFX_XMLText>(std::move(wsValue)));
}
