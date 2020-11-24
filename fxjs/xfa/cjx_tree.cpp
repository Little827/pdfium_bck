// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fxjs/xfa/cjx_tree.h"

#include <memory>
#include <vector>

#include "fxjs/fxv8.h"
#include "fxjs/js_resources.h"
#include "fxjs/xfa/cfxjse_class.h"
#include "fxjs/xfa/cfxjse_engine.h"
#include "third_party/base/numerics/safe_conversions.h"
#include "v8/include/cppgc/allocation.h"
#include "xfa/fxfa/parser/cxfa_arraynodelist.h"
#include "xfa/fxfa/parser/cxfa_attachnodelist.h"
#include "xfa/fxfa/parser/cxfa_document.h"
#include "xfa/fxfa/parser/cxfa_node.h"
#include "xfa/fxfa/parser/cxfa_object.h"

const CJX_MethodSpec CJX_Tree::MethodSpecs[] = {
    {"resolveNode", resolveNode_static},
    {"resolveNodes", resolveNodes_static}};

CJX_Tree::CJX_Tree(CXFA_Object* obj) : CJX_Object(obj) {
  DefineMethods(MethodSpecs);
}

CJX_Tree::~CJX_Tree() = default;

bool CJX_Tree::DynamicTypeIs(TypeTag eType) const {
  return eType == static_type__ || ParentType__::DynamicTypeIs(eType);
}

CJS_Result CJX_Tree::resolveNode(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 1)
    return CJS_Result::Failure(JSMessage::kParamError);

  WideString expression = runtime->ToWideString(params[0]);
  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  CXFA_Object* refNode = GetXFAObject();
  if (refNode->GetElementType() == XFA_Element::Xfa)
    refNode = pScriptContext->GetThisObject();

  uint32_t dwFlag = XFA_RESOLVENODE_Children | XFA_RESOLVENODE_Attributes |
                    XFA_RESOLVENODE_Properties | XFA_RESOLVENODE_Parent |
                    XFA_RESOLVENODE_Siblings;
  Optional<CFXJSE_Engine::ResolveResult> maybeResult =
      pScriptContext->ResolveObjects(ToNode(refNode), expression.AsStringView(),
                                     dwFlag, nullptr);
  if (!maybeResult.has_value())
    return CJS_Result::Success(runtime->NewNull());

  if (maybeResult.value().type == CFXJSE_Engine::ResolveResult::Type::kNodes) {
    return CJS_Result::Success(
        GetDocument()->GetScriptContext()->GetOrCreateJSBindingFromMap(
            maybeResult.value().objects.front().Get()));
  }

  if (!maybeResult.value().script_attribute.getter ||
      maybeResult.value().script_attribute.eValueType !=
          XFA_ScriptType::Object) {
    return CJS_Result::Success(runtime->NewNull());
  }

  CJX_Object* jsObject = maybeResult.value().objects.front()->JSObject();
  v8::Local<v8::Value> pValue = (*maybeResult.value().script_attribute.getter)(
      runtime->GetIsolate(), jsObject,
      maybeResult.value().script_attribute.attribute);
  return CJS_Result::Success(pValue);
}

CJS_Result CJX_Tree::resolveNodes(
    CFX_V8* runtime,
    const std::vector<v8::Local<v8::Value>>& params) {
  if (params.size() != 1)
    return CJS_Result::Failure(JSMessage::kParamError);

  CXFA_Object* refNode = GetXFAObject();
  if (refNode->GetElementType() == XFA_Element::Xfa)
    refNode = GetDocument()->GetScriptContext()->GetThisObject();

  CFXJSE_Engine* pScriptContext = GetDocument()->GetScriptContext();
  v8::Local<v8::Value> pValue = ResolveNodeList(
      pScriptContext->GetIsolate(), runtime->ToWideString(params[0]),
      XFA_RESOLVENODE_Children | XFA_RESOLVENODE_Attributes |
          XFA_RESOLVENODE_Properties | XFA_RESOLVENODE_Parent |
          XFA_RESOLVENODE_Siblings,
      ToNode(refNode));
  return CJS_Result::Success(pValue);
}

v8::Local<v8::Value> CJX_Tree::allGetter(v8::Isolate* pIsolate,
                                         XFA_Attribute eAttribute) {
  uint32_t dwFlag = XFA_RESOLVENODE_Siblings | XFA_RESOLVENODE_ALL;
  WideString wsExpression = GetAttributeByEnum(XFA_Attribute::Name) + L"[*]";
  return ResolveNodeList(pIsolate, wsExpression, dwFlag, nullptr);
}

void CJX_Tree::allSetter(v8::Isolate* pIsolate,
                         XFA_Attribute eAttribute,
                         v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::classAllGetter(v8::Isolate* pIsolate,
                                              XFA_Attribute eAttribute) {
  WideString wsExpression =
      L"#" + WideString::FromASCII(GetXFAObject()->GetClassName()) + L"[*]";
  return ResolveNodeList(pIsolate, std::move(wsExpression),
                         XFA_RESOLVENODE_Siblings | XFA_RESOLVENODE_ALL,
                         nullptr);
}

void CJX_Tree::classAllSetter(v8::Isolate* pIsolate,
                              XFA_Attribute eAttribute,
                              v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::nodesGetter(v8::Isolate* pIsolate,
                                           XFA_Attribute eAttribute) {
  CXFA_Document* pDoc = GetDocument();
  auto* pNodeList = cppgc::MakeGarbageCollected<CXFA_AttachNodeList>(
      pDoc->GetHeap()->GetAllocationHandle(), pDoc, GetXFANode());
  pDoc->GetNodeOwner()->PersistList(pNodeList);

  CFXJSE_Engine* pEngine = pDoc->GetScriptContext();
  return pNodeList->JSObject()->NewBoundV8Object(
      pIsolate, pEngine->GetJseNormalClass()->GetTemplate(pIsolate));
}

void CJX_Tree::nodesSetter(v8::Isolate* pIsolate,
                           XFA_Attribute eAttribute,
                           v8::Local<v8::Value> pValue) {
  WideString wsMessage = L"Unable to set ";
  FXJSE_ThrowMessage(wsMessage.ToUTF8().AsStringView());
}

v8::Local<v8::Value> CJX_Tree::parentGetter(v8::Isolate* pIsolate,
                                            XFA_Attribute eAttribute) {
  CXFA_Node* pParent = GetXFANode()->GetParent();
  if (!pParent)
    return fxv8::NewNullHelper(pIsolate);

  return GetDocument()->GetScriptContext()->GetOrCreateJSBindingFromMap(
      pParent);
}

void CJX_Tree::parentSetter(v8::Isolate* pIsolate,
                            XFA_Attribute eAttribute,
                            v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::indexGetter(v8::Isolate* pIsolate,
                                           XFA_Attribute eAttribute) {
  CXFA_Node* pNode = GetXFANode();
  size_t iIndex = pNode ? pNode->GetIndexByName() : 0;
  return fxv8::NewNumberHelper(pIsolate,
                               pdfium::base::checked_cast<int32_t>(iIndex));
}

void CJX_Tree::indexSetter(v8::Isolate* pIsolate,
                           XFA_Attribute eAttribute,
                           v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::classIndexGetter(v8::Isolate* pIsolate,
                                                XFA_Attribute eAttribute) {
  CXFA_Node* pNode = GetXFANode();
  size_t iIndex = pNode ? pNode->GetIndexByClassName() : 0;
  return fxv8::NewNumberHelper(pIsolate,
                               pdfium::base::checked_cast<int32_t>(iIndex));
}

void CJX_Tree::classIndexSetter(v8::Isolate* pIsolate,
                                XFA_Attribute eAttribute,
                                v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::somExpressionGetter(v8::Isolate* pIsolate,
                                                   XFA_Attribute eAttribute) {
  ByteString bsSOMExpression = GetXFAObject()->GetSOMExpression().ToUTF8();
  return fxv8::NewStringHelper(pIsolate, bsSOMExpression.AsStringView());
}

void CJX_Tree::somExpressionSetter(v8::Isolate* pIsolate,
                                   XFA_Attribute eAttribute,
                                   v8::Local<v8::Value> pValue) {
  ThrowInvalidPropertyException();
}

v8::Local<v8::Value> CJX_Tree::ResolveNodeList(v8::Isolate* pIsolate,
                                               WideString wsExpression,
                                               uint32_t dwFlag,
                                               CXFA_Node* refNode) {
  if (!refNode)
    refNode = GetXFANode();

  CXFA_Document* pDoc = GetDocument();
  CFXJSE_Engine* pScriptContext = pDoc->GetScriptContext();
  Optional<CFXJSE_Engine::ResolveResult> maybeResult =
      pScriptContext->ResolveObjects(refNode, wsExpression.AsStringView(),
                                     dwFlag, nullptr);

  auto* pNodeList = cppgc::MakeGarbageCollected<CXFA_ArrayNodeList>(
      pDoc->GetHeap()->GetAllocationHandle(), pDoc);
  pDoc->GetNodeOwner()->PersistList(pNodeList);

  if (maybeResult.has_value()) {
    if (maybeResult.value().type ==
        CFXJSE_Engine::ResolveResult::Type::kNodes) {
      for (auto& pObject : maybeResult.value().objects) {
        if (pObject->IsNode())
          pNodeList->Append(pObject->AsNode());
      }
    } else {
      if (maybeResult.value().script_attribute.getter &&
          maybeResult.value().script_attribute.eValueType ==
              XFA_ScriptType::Object) {
        for (auto& pObject : maybeResult.value().objects) {
          CJX_Object* jsObject = pObject->JSObject();
          v8::Local<v8::Value> innerValue =
              (*maybeResult.value().script_attribute.getter)(
                  pIsolate, jsObject,
                  maybeResult.value().script_attribute.attribute);
          CXFA_Object* obj =
              CFXJSE_Engine::ToObject(pScriptContext->GetIsolate(), innerValue);
          if (obj->IsNode())
            pNodeList->Append(obj->AsNode());
        }
      }
    }
  }
  return pNodeList->JSObject()->NewBoundV8Object(
      pIsolate, pScriptContext->GetJseNormalClass()->GetTemplate(pIsolate));
}
