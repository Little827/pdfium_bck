// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_
#define XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_

#include <memory>

#include "core/fxcrt/unowned_ptr.h"
#include "xfa/fxfa/layout/cxfa_layoutitem.h"

class CXFA_ContentLayoutItem : public CXFA_LayoutItem {
 public:
  class WidgetBase {
   public:
    WidgetBase();
    virtual ~WidgetBase();

    void SetLayoutItem(CXFA_ContentLayoutItem* pItem) { m_pLayoutItem = pItem; }
    CXFA_ContentLayoutItem* GetLayoutItem() const {
      return m_pLayoutItem.Get();
    }

   private:
    UnownedPtr<CXFA_ContentLayoutItem> m_pLayoutItem;
  };

  CXFA_ContentLayoutItem(CXFA_Node* pNode,
                         std::unique_ptr<WidgetBase> pFFWidget);
  ~CXFA_ContentLayoutItem() override;

  WidgetBase* GetWidget() { return m_pWidget.get(); }

  CXFA_ContentLayoutItem* GetFirst();
  CXFA_ContentLayoutItem* GetLast();
  CXFA_ContentLayoutItem* GetPrev() const { return m_pPrev.Get(); }
  CXFA_ContentLayoutItem* GetNext() const { return m_pNext.Get(); }
  void InsertAfter(CXFA_ContentLayoutItem* pNext);

  CFX_RectF GetRect(bool bRelative) const;
  size_t GetIndex() const;

  void SetStatusBit(uint32_t val) { m_dwStatus |= val; }
  void ClearStatusBit(uint32_t val) { m_dwStatus &= ~val; }
  bool TestStatusBit(uint32_t val) const { return !!(m_dwStatus & val); }

  CFX_PointF m_sPos;
  CFX_SizeF m_sSize;

 private:
  void RemoveSelf();

  mutable uint32_t m_dwStatus = 0;
  std::unique_ptr<WidgetBase> const m_pWidget;
  UnownedPtr<CXFA_ContentLayoutItem> m_pPrev;
  UnownedPtr<CXFA_ContentLayoutItem> m_pNext;
};

inline CXFA_ContentLayoutItem::WidgetBase* GetWidget(
    CXFA_ContentLayoutItem* item) {
  return item ? item->GetWidget() : nullptr;
}

#endif  // XFA_FXFA_LAYOUT_CXFA_CONTENTLAYOUTITEM_H_
