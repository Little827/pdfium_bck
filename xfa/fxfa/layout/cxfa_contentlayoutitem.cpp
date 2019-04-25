// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/layout/cxfa_contentlayoutitem.h"

#include <utility>

#include "fxjs/xfa/cjx_object.h"
#include "xfa/fxfa/cxfa_ffwidget.h"
#include "xfa/fxfa/parser/cxfa_margin.h"
#include "xfa/fxfa/parser/cxfa_node.h"

CXFA_ContentLayoutItem::CXFA_ContentLayoutItem(
    CXFA_Node* pNode,
    std::unique_ptr<CXFA_FFWidget> pWidget)
    : CXFA_LayoutItem(pNode, kContentItem), m_pFFWidget(std::move(pWidget)) {
  if (m_pFFWidget)
    m_pFFWidget->SetLayoutItem(this);
}

CXFA_ContentLayoutItem::~CXFA_ContentLayoutItem() {
  RemoveSelfFromGeneratedList();
  CJX_Object* pJsObject = GetFormNode()->JSObject();
  if (pJsObject->GetLayoutItem() == this)
    pJsObject->SetLayoutItem(nullptr);
}

CXFA_ContentLayoutItem* CXFA_ContentLayoutItem::GetFirstGenerated() {
  CXFA_ContentLayoutItem* pCurNode = this;
  while (auto* pPrev = pCurNode->GetPrevGenerated())
    pCurNode = pPrev;

  return pCurNode;
}

CXFA_ContentLayoutItem* CXFA_ContentLayoutItem::GetLastGenerated() {
  CXFA_ContentLayoutItem* pCurNode = this;
  while (auto* pNext = pCurNode->GetNextGenerated())
    pCurNode = pNext;

  return pCurNode;
}

void CXFA_ContentLayoutItem::InsertIntoGeneratedList(
    CXFA_ContentLayoutItem* pItem) {
  pItem->RemoveSelfFromGeneratedList();
  pItem->m_pNextGenerated = m_pNextGenerated;
  pItem->m_pPrevGenerated = this;
  m_pNextGenerated = pItem;
  if (pItem->m_pNextGenerated)
    pItem->m_pNextGenerated->m_pPrevGenerated = pItem;
}

void CXFA_ContentLayoutItem::RemoveSelfFromGeneratedList() {
  if (m_pNextGenerated)
    m_pNextGenerated->m_pPrevGenerated = m_pPrevGenerated;
  if (m_pPrevGenerated)
    m_pPrevGenerated->m_pNextGenerated = m_pNextGenerated;
  m_pNextGenerated = nullptr;
  m_pPrevGenerated = nullptr;
}

CFX_RectF CXFA_ContentLayoutItem::GetRect(bool bRelative) const {
  CFX_PointF sPos = m_sPos;
  CFX_SizeF sSize = m_sSize;
  if (bRelative)
    return CFX_RectF(sPos, sSize);

  for (CXFA_LayoutItem* pLayoutItem = GetParent(); pLayoutItem;
       pLayoutItem = pLayoutItem->GetParent()) {
    if (CXFA_ContentLayoutItem* pContent = pLayoutItem->AsContentLayoutItem()) {
      sPos += pContent->m_sPos;
      CXFA_Margin* pMarginNode =
          pContent->GetFormNode()->GetFirstChildByClass<CXFA_Margin>(
              XFA_Element::Margin);
      if (pMarginNode) {
        sPos += CFX_PointF(pMarginNode->JSObject()->GetMeasureInUnit(
                               XFA_Attribute::LeftInset, XFA_Unit::Pt),
                           pMarginNode->JSObject()->GetMeasureInUnit(
                               XFA_Attribute::TopInset, XFA_Unit::Pt));
      }
      continue;
    }

    if (pLayoutItem->GetFormNode()->GetElementType() ==
        XFA_Element::ContentArea) {
      sPos +=
          CFX_PointF(pLayoutItem->GetFormNode()->JSObject()->GetMeasureInUnit(
                         XFA_Attribute::X, XFA_Unit::Pt),
                     pLayoutItem->GetFormNode()->JSObject()->GetMeasureInUnit(
                         XFA_Attribute::Y, XFA_Unit::Pt));
      break;
    }
    if (pLayoutItem->GetFormNode()->GetElementType() == XFA_Element::PageArea)
      break;
  }
  return CFX_RectF(sPos, sSize);
}

size_t CXFA_ContentLayoutItem::GetIndex() const {
  size_t szIndex = 0;
  const CXFA_ContentLayoutItem* pCurNode = this;
  while (auto* pPrev = pCurNode->GetPrevGenerated()) {
    pCurNode = pPrev;
    ++szIndex;
  }
  return szIndex;
}
