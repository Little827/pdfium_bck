// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fpdfsdk/cpdfsdk_baannothandler.h"

#include <memory>
#include <vector>

#include "core/fpdfapi/page/cpdf_page.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfdoc/cpdf_interactiveform.h"
#include "core/fxge/cfx_graphstatedata.h"
#include "core/fxge/cfx_pathdata.h"
#include "fpdfsdk/cpdfsdk_annot.h"
#include "fpdfsdk/cpdfsdk_baannot.h"
#include "fpdfsdk/cpdfsdk_formfillenvironment.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fpdfsdk/cpdfsdk_pageview.h"
#include "fpdfsdk/formfiller/cffl_formfiller.h"

namespace {

void UpdateAnnotRects(CPDFSDK_PageView* pPageView, CPDFSDK_BAAnnot* pBAAnnot) {
  std::vector<CFX_FloatRect> rects;
  rects.push_back(pBAAnnot->GetRect());
  if (CPDF_Annot* pPopupAnnot = pBAAnnot->GetPDFPopupAnnot())
    rects.push_back(pPopupAnnot->GetRect());

  // Make the rects round up to avoid https://crbug.com/662804
  for (CFX_FloatRect& rect : rects)
    rect.Inflate(1, 1);

  pPageView->UpdateRects(rects);
}

}  // namespace

CPDFSDK_BAAnnotHandler::CPDFSDK_BAAnnotHandler() {
  for (auto annot_type : GetFocusableAnnotSubtypes()) {
    if (annot_type != CPDF_Annot::Subtype::WIDGET) {
      focusable_annot_types_.push_back(annot_type);
    }
  }
}

CPDFSDK_BAAnnotHandler::~CPDFSDK_BAAnnotHandler() {}

void CPDFSDK_BAAnnotHandler::SetFormFillEnvironment(
    CPDFSDK_FormFillEnvironment* pFormFillEnv) {
  form_fill_environment_ = pFormFillEnv;
}

bool CPDFSDK_BAAnnotHandler::CanAnswer(CPDFSDK_Annot* pAnnot) {
  return false;
}

CPDFSDK_Annot* CPDFSDK_BAAnnotHandler::NewAnnot(CPDF_Annot* pAnnot,
                                                CPDFSDK_PageView* pPage) {
  return new CPDFSDK_BAAnnot(pAnnot, pPage);
}

void CPDFSDK_BAAnnotHandler::ReleaseAnnot(
    std::unique_ptr<CPDFSDK_Annot> pAnnot) {
  // pAnnot deleted by unique_ptr going out of scope.
}

void CPDFSDK_BAAnnotHandler::OnDraw(CPDFSDK_PageView* pPageView,
                                    CPDFSDK_Annot* pAnnot,
                                    CFX_RenderDevice* pDevice,
                                    const CFX_Matrix& mtUser2Device,
                                    bool bDrawAnnots) {
  if (pAnnot->AsXFAWidget())
    return;

  const CPDF_Annot::Subtype annot_type = pAnnot->GetAnnotSubtype();
  if (bDrawAnnots && annot_type == CPDF_Annot::Subtype::POPUP) {
    pAnnot->AsBAAnnot()->DrawAppearance(pDevice, mtUser2Device,
                                        CPDF_Annot::Normal, nullptr);
    return;
  }

  if (IsFocusableAnnot(annot_type) && is_annotation_focused_ &&
      (pAnnot == form_fill_environment_->GetFocusAnnot())) {
    CPDFSDK_BAAnnot* ba_annot = static_cast<CPDFSDK_BAAnnot*>(pAnnot);

    CFX_FloatRect view_bounding_box = GetViewBBox(pPageView, ba_annot);
    if (view_bounding_box.IsEmpty())
      return;

    view_bounding_box.Normalize();

    DrawFocusRect(pDevice, mtUser2Device, view_bounding_box);

    return;
  }
}

void CPDFSDK_BAAnnotHandler::OnMouseEnter(CPDFSDK_PageView* pPageView,
                                          ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                          uint32_t nFlag) {
  CPDFSDK_BAAnnot* pBAAnnot = (*pAnnot)->AsBAAnnot();
  pBAAnnot->SetOpenState(true);
  UpdateAnnotRects(pPageView, pBAAnnot);
}

void CPDFSDK_BAAnnotHandler::OnMouseExit(CPDFSDK_PageView* pPageView,
                                         ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                         uint32_t nFlag) {
  CPDFSDK_BAAnnot* pBAAnnot = (*pAnnot)->AsBAAnnot();
  pBAAnnot->SetOpenState(false);
  UpdateAnnotRects(pPageView, pBAAnnot);
}

bool CPDFSDK_BAAnnotHandler::OnLButtonDown(CPDFSDK_PageView* pPageView,
                                           ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                           uint32_t nFlags,
                                           const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnLButtonUp(CPDFSDK_PageView* pPageView,
                                         ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                         uint32_t nFlags,
                                         const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnLButtonDblClk(CPDFSDK_PageView* pPageView,
                                             ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                             uint32_t nFlags,
                                             const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnMouseMove(CPDFSDK_PageView* pPageView,
                                         ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                         uint32_t nFlags,
                                         const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnMouseWheel(CPDFSDK_PageView* pPageView,
                                          ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                          uint32_t nFlags,
                                          short zDelta,
                                          const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnRButtonDown(CPDFSDK_PageView* pPageView,
                                           ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                           uint32_t nFlags,
                                           const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnRButtonUp(CPDFSDK_PageView* pPageView,
                                         ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                         uint32_t nFlags,
                                         const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnRButtonDblClk(CPDFSDK_PageView* pPageView,
                                             ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                             uint32_t nFlags,
                                             const CFX_PointF& point) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnChar(CPDFSDK_Annot* pAnnot,
                                    uint32_t nChar,
                                    uint32_t nFlags) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnKeyDown(CPDFSDK_Annot* pAnnot,
                                       int nKeyCode,
                                       int nFlag) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::OnKeyUp(CPDFSDK_Annot* pAnnot,
                                     int nKeyCode,
                                     int nFlag) {
  return false;
}

void CPDFSDK_BAAnnotHandler::OnLoad(CPDFSDK_Annot* pAnnot) {}

bool CPDFSDK_BAAnnotHandler::IsFocusableAnnot(
    const CPDF_Annot::Subtype& annot_type) const {
  auto itr = std::find(focusable_annot_types_.begin(),
                       focusable_annot_types_.end(), annot_type);

  return itr != focusable_annot_types_.end();
}

void CPDFSDK_BAAnnotHandler::InvalidateRect(CPDFSDK_Annot* annot) {
  ASSERT(annot);
  CPDFSDK_BAAnnot* ba_annot = static_cast<CPDFSDK_BAAnnot*>(annot);
  CPDFSDK_PageView* page_view = ba_annot->GetPageView();
  CFX_FloatRect view_bounding_box = GetViewBBox(page_view, ba_annot);
  if (!view_bounding_box.IsEmpty()) {
    view_bounding_box.Inflate(1, 1);
    view_bounding_box.Normalize();
    FX_RECT rect = view_bounding_box.GetOuterRect();
    form_fill_environment_->Invalidate(ba_annot->GetPage(), rect);
  }
}

bool CPDFSDK_BAAnnotHandler::OnSetFocus(ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                        uint32_t nFlag) {
  ASSERT(pAnnot);
  if (!IsFocusableAnnot(pAnnot->Get()->GetAnnotSubtype()))
    return false;

  is_annotation_focused_ = true;
  InvalidateRect(pAnnot->Get());
  return true;
}

bool CPDFSDK_BAAnnotHandler::OnKillFocus(ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                         uint32_t nFlag) {
  ASSERT(pAnnot);
  if (!IsFocusableAnnot(pAnnot->Get()->GetAnnotSubtype()))
    return false;

  is_annotation_focused_ = false;
  InvalidateRect(pAnnot->Get());
  return true;
}

bool CPDFSDK_BAAnnotHandler::SetIndexSelected(
    ObservedPtr<CPDFSDK_Annot>* pAnnot,
    int index,
    bool selected) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::IsIndexSelected(ObservedPtr<CPDFSDK_Annot>* pAnnot,
                                             int index) {
  return false;
}

CFX_FloatRect CPDFSDK_BAAnnotHandler::GetViewBBox(CPDFSDK_PageView* pPageView,
                                                  CPDFSDK_Annot* pAnnot) {
  return pAnnot->GetRect();
}

WideString CPDFSDK_BAAnnotHandler::GetText(CPDFSDK_Annot* pAnnot) {
  return WideString();
}

WideString CPDFSDK_BAAnnotHandler::GetSelectedText(CPDFSDK_Annot* pAnnot) {
  return WideString();
}

void CPDFSDK_BAAnnotHandler::ReplaceSelection(CPDFSDK_Annot* pAnnot,
                                              const WideString& text) {}

bool CPDFSDK_BAAnnotHandler::CanUndo(CPDFSDK_Annot* pAnnot) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::CanRedo(CPDFSDK_Annot* pAnnot) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::Undo(CPDFSDK_Annot* pAnnot) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::Redo(CPDFSDK_Annot* pAnnot) {
  return false;
}

bool CPDFSDK_BAAnnotHandler::HitTest(CPDFSDK_PageView* pPageView,
                                     CPDFSDK_Annot* pAnnot,
                                     const CFX_PointF& point) {
  ASSERT(pPageView);
  ASSERT(pAnnot);
  return GetViewBBox(pPageView, pAnnot).Contains(point);
}
