// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fpdfsdk/fpdfxfa/cpdfxfa_annot.h"

#include "fpdfsdk/ipdfsdk_annothandler.h"
#include "xfa/fxfa/cxfa_ffwidget.h"

CPDFXFA_Annot::CPDFXFA_Annot(CXFA_FFWidget* pAnnot,
                             CPDFSDK_PageView* pPageView,
                             CPDFSDK_InteractiveForm* pInteractiveForm)
    : CPDFSDK_Annot(pPageView),
      m_pInteractiveForm(pInteractiveForm),
      m_pXFAWidget(pAnnot) {}

CPDFXFA_Annot::~CPDFXFA_Annot() = default;

CPDFXFA_Annot* CPDFXFA_Annot::AsXFAAnnot() {
  return this;
}

CPDF_Annot::Subtype CPDFXFA_Annot::GetAnnotSubtype() const {
  return CPDF_Annot::Subtype::XFAWIDGET;
}

CFX_FloatRect CPDFXFA_Annot::GetRect() const {
  return GetXFAWidget()->GetLayoutItem()->GetRect(false).ToFloatRect();
}
