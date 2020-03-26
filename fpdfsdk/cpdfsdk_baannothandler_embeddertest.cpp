// Copyright 2019 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fpdfsdk/cpdfsdk_annotiterator.h"
#include "fpdfsdk/cpdfsdk_baannothandler.h"
#include "fpdfsdk/cpdfsdk_formfillenvironment.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fpdfsdk/cpdfsdk_pageview.h"
#include "public/fpdf_annot.h"
#include "testing/embedder_test.h"

class CPDFSDK_BAAnnotHandlerTest : public EmbedderTest {
 public:
  void SetUp() override {
    // Test behaviour with currently supported annot i.e. Widget.
    // TODO(crbug.com/994500): Add an API that can set list of focusable
    // subtypes once other annots(links & highlights) are also supported.
    EmbedderTest::SetUp();
    SetUpBAAnnotHandler();
  }

  void TearDown() override {
    UnloadPage(m_page);
    EmbedderTest::TearDown();
  }

  void SetUpBAAnnotHandler() {
    EXPECT_TRUE(OpenDocument("links_highlights_annots.pdf"));
    m_page = LoadPage(0);
    ASSERT_TRUE(m_page);

    pFormFillEnv = CPDFSDKFormFillEnvironmentFromFPDFFormHandle(form_handle());
    ASSERT_TRUE(pFormFillEnv);
    m_pPageView = pFormFillEnv->GetPageView(IPDFPageFromFPDFPage(m_page), true);
    ASSERT_TRUE(m_pPageView);

    CPDFSDK_AnnotHandlerMgr* pAnnotHandlerMgr =
        pFormFillEnv->GetAnnotHandlerMgr();
    ASSERT_TRUE(pAnnotHandlerMgr);
    m_pBAAnnotHandler = pAnnotHandlerMgr->m_pBAAnnotHandler.get();
    ASSERT_TRUE(m_pBAAnnotHandler);
  }

  CPDFSDK_PageView* GetPageView() const { return m_pPageView; }
  CPDFSDK_BAAnnotHandler* GetBAAnnotHandler() const {
    return m_pBAAnnotHandler;
  }

  CPDFSDK_Annot* GetLinkAnnot() const {
    CPDFSDK_AnnotIterator ai(GetPageView(),
                             pFormFillEnv->GetFocusableAnnotSubtypes());
    return ai.GetNextAnnot(ai.GetFirstAnnot());
  }

  CPDFSDK_Annot* GetHighlightAnnot() const {
    CPDFSDK_AnnotIterator ai(GetPageView(),
                             pFormFillEnv->GetFocusableAnnotSubtypes());
    CPDFSDK_Annot* pAnnot = ai.GetFirstAnnot();
    ASSERT(pAnnot);

    for (int i = 0; i < 3; ++i) {
      pAnnot = ai.GetNextAnnot(pAnnot);
      ASSERT(pAnnot);
    }

    return pAnnot;
  }

 private:
  FPDF_PAGE m_page = nullptr;
  CPDFSDK_PageView* m_pPageView = nullptr;
  CPDFSDK_FormFillEnvironment* pFormFillEnv = nullptr;
  CPDFSDK_BAAnnotHandler* m_pBAAnnotHandler = nullptr;
};

TEST_F(CPDFSDK_BAAnnotHandlerTest, TabToLinkOrHighlightAnnot) {
  constexpr FPDF_ANNOTATION_SUBTYPE kFocusableSubtypes[] = {
      FPDF_ANNOT_WIDGET, FPDF_ANNOT_LINK, FPDF_ANNOT_HIGHLIGHT};
  constexpr size_t kSubtypeCount = FX_ArraySize(kFocusableSubtypes);

  ASSERT_TRUE(FPDFAnnot_SetFocusableSubtypes(form_handle(), kFocusableSubtypes,
                                             kSubtypeCount));

  // Get link annot.
  CPDFSDK_Annot* pAnnot = GetLinkAnnot();
  ASSERT_TRUE(pAnnot);
  EXPECT_EQ(pAnnot->GetAnnotSubtype(), CPDF_Annot::Subtype::LINK);

  ObservedPtr<CPDFSDK_Annot> pLinkAnnot(pAnnot);
  EXPECT_TRUE(GetBAAnnotHandler()->OnSetFocus(&pLinkAnnot, 0));
  EXPECT_TRUE(GetBAAnnotHandler()->OnKillFocus(&pLinkAnnot, 0));

  // Get highlight annot.
  pAnnot = GetHighlightAnnot();
  ASSERT_TRUE(pAnnot);
  EXPECT_EQ(pAnnot->GetAnnotSubtype(), CPDF_Annot::Subtype::HIGHLIGHT);

  ObservedPtr<CPDFSDK_Annot> pHighlightAnnot(pAnnot);
  EXPECT_TRUE(GetBAAnnotHandler()->OnSetFocus(&pHighlightAnnot, 0));
  EXPECT_TRUE(GetBAAnnotHandler()->OnKillFocus(&pHighlightAnnot, 0));
}
