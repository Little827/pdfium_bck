// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_
#define XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_

#include <memory>

#include "core/fxcrt/unowned_ptr.h"
#include "xfa/fxfa/layout/cxfa_layoutitem.h"

class CXFA_FFWidget;

class CXFA_ContentLayoutItem : public CXFA_LayoutItem {
 public:
  CXFA_ContentLayoutItem(CXFA_Node* pNode,
                         std::unique_ptr<CXFA_FFWidget> pFFWidget);
  ~CXFA_ContentLayoutItem() override;

  CXFA_FFWidget* GetFFWidget() { return m_pFFWidget.get(); }

  // Generated nodes are "orphans", in that they do not occur in the standard
  // layout tree. Instead they are maintained on a separate doubly-linked list
  // below.
  CXFA_ContentLayoutItem* GetFirstGenerated();
  CXFA_ContentLayoutItem* GetLastGenerated();
  CXFA_ContentLayoutItem* GetPrevGenerated() const {
    return m_pPrevGenerated.Get();
  }
  CXFA_ContentLayoutItem* GetNextGenerated() const {
    return m_pNextGenerated.Get();
  }
  void InsertIntoGeneratedList(CXFA_ContentLayoutItem* pNext);

  CFX_RectF GetRect(bool bRelative) const;
  size_t GetIndex() const;

  void SetStatusBits(uint32_t val) { m_dwStatus |= val; }
  void ClearStatusBits(uint32_t val) { m_dwStatus &= ~val; }

  // TRUE if all (not any) bits set in |val| are set in |m_dwStatus|.
  bool TestStatusBits(uint32_t val) const { return (m_dwStatus & val) == val; }

  CFX_PointF m_sPos;
  CFX_SizeF m_sSize;

 private:
  void RemoveSelfFromGeneratedList();

  mutable uint32_t m_dwStatus = 0;
  UnownedPtr<CXFA_ContentLayoutItem> m_pPrevGenerated;
  UnownedPtr<CXFA_ContentLayoutItem> m_pNextGenerated;
  std::unique_ptr<CXFA_FFWidget> const m_pFFWidget;
};

inline CXFA_FFWidget* GetFFWidget(CXFA_ContentLayoutItem* item) {
  return item ? item->GetFFWidget() : nullptr;
}

#endif  // XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_
