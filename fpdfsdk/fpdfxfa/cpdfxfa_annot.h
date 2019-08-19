// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FPDFSDK_FPDFXFA_CPDFXFA_ANNOT_H_
#define FPDFSDK_FPDFXFA_CPDFXFA_ANNOT_H_

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/observed_ptr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "fpdfsdk/cpdfsdk_annot.h"

class CPDFSDK_InteractiveForm;
class CPDFSDK_PageView;
class CXFA_FFWidget;

class CPDFXFA_Annot final : public CPDFSDK_Annot {
 public:
  CPDFXFA_Annot(CXFA_FFWidget* pAnnot,
                CPDFSDK_PageView* pPageView,
                CPDFSDK_InteractiveForm* pInteractiveForm);
  ~CPDFXFA_Annot() override;

  // CPDFSDK_Annot:
  CPDFXFA_Annot* AsXFAAnnot() override;
  CPDF_Annot::Subtype GetAnnotSubtype() const override;
  CFX_FloatRect GetRect() const override;

  CXFA_FFWidget* GetXFAWidget() const { return m_pXFAWidget.Get(); }
  CPDFSDK_InteractiveForm* GetInteractiveForm() const {
    return m_pInteractiveForm.Get();
  }

 private:
  UnownedPtr<CPDFSDK_InteractiveForm> const m_pInteractiveForm;
  ObservedPtr<CXFA_FFWidget> const m_pXFAWidget;
};

#endif  // FPDFSDK_FPDFXFA_CPDFXFA_ANNOT_H_
