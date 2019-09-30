// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "fpdfsdk/cpdfsdk_annotiterator.h"
#include "fpdfsdk/cpdfsdk_baannothandler.h"
#include "fpdfsdk/cpdfsdk_formfillenvironment.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fpdfsdk/cpdfsdk_pageview.h"
#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

class CPDFSDK_BAAnnotHandlerTest : public EmbedderTest {
 public:
  CPDFSDK_BAAnnotHandlerTest() = default;
  ~CPDFSDK_BAAnnotHandlerTest() override = default;

 protected:
  void SetUp() override {
    EmbedderTest::SetUp();
    SetUpBAAnnotHandler();
  }

  void TearDown() override {
    UnloadPage(GetPage());
    EmbedderTest::TearDown();
  }

  void SetUpBAAnnotHandler() {
    EXPECT_TRUE(OpenDocument("links_highlights_annots.pdf"));
    m_page = LoadPage(0);
    ASSERT_TRUE(m_page);

    // Set Widget, Link and Highlight as supported annots
    // tabbing should iterate over these annot subtypes via GetNextAnnot API.
    constexpr unsigned int supportedAnnotSubtypes[] = {
        FPDF_ANNOT_WIDGET, FPDF_ANNOT_LINK, FPDF_ANNOT_HIGHLIGHT};

    ResetFocusableAnnotSubtypes();
    SetFocusableAnnotSubtypes(
        supportedAnnotSubtypes,
        sizeof(supportedAnnotSubtypes) / sizeof(supportedAnnotSubtypes[0]));

    CPDFSDK_FormFillEnvironment* pFormFillEnv =
        CPDFSDKFormFillEnvironmentFromFPDFFormHandle(form_handle());
    IPDF_Page* pPage = IPDFPageFromFPDFPage(m_page);
    m_pPageView = pFormFillEnv->GetPageView(pPage, true);

    m_pBAAnnotHandler = pdfium::MakeUnique<CPDFSDK_BAAnnotHandler>();
    ASSERT(m_pBAAnnotHandler);
    m_pBAAnnotHandler->SetFormFillEnvironment(pFormFillEnv);
  }

  FPDF_PAGE GetPage() const { return m_page; }
  CPDFSDK_PageView* GetPageView() const { return m_pPageView; }
  CPDFSDK_BAAnnotHandler* GetBAAnnotHandler() const {
    return m_pBAAnnotHandler.get();
  }

 private:
  FPDF_PAGE m_page;
  CPDFSDK_PageView* m_pPageView;
  std::unique_ptr<CPDFSDK_BAAnnotHandler> m_pBAAnnotHandler;
};

TEST_F(CPDFSDK_BAAnnotHandlerTest, TabToLinkOrHighlightAnnot) {
  CPDFSDK_AnnotIterator ai(GetPageView(), GetFocusableAnnotSubtypes());
  CPDFSDK_Annot* pAnnot = ai.GetFirstAnnot();

  // Skip all annot types other than link & highlight.
  while ((pAnnot->GetAnnotSubtype() != CPDF_Annot::Subtype::LINK) &&
         (pAnnot->GetAnnotSubtype() != CPDF_Annot::Subtype::HIGHLIGHT)) {
    CPDFSDK_Annot* pNextAnnot = ai.GetNextAnnot(pAnnot);
    pAnnot = pNextAnnot;
  }

  ObservedPtr<CPDFSDK_Annot> pNonWidgetAnnot(pAnnot);

  EXPECT_TRUE(GetBAAnnotHandler()->OnSetFocus(&pNonWidgetAnnot, 0));

  EXPECT_TRUE(GetBAAnnotHandler()->OnKillFocus(&pNonWidgetAnnot, 0));
}

TEST_F(CPDFSDK_BAAnnotHandlerTest, TabToInvalidAnnot) {
  CPDFSDK_AnnotIterator ai(GetPageView(), GetFocusableAnnotSubtypes());
  CPDFSDK_Annot* pAnnot = ai.GetFirstAnnot();

  // Skip link & highlight annot types.
  while ((pAnnot->GetAnnotSubtype() == CPDF_Annot::Subtype::LINK) ||
         (pAnnot->GetAnnotSubtype() == CPDF_Annot::Subtype::HIGHLIGHT)) {
    CPDFSDK_Annot* pNextAnnot = ai.GetNextAnnot(pAnnot);
    pAnnot = pNextAnnot;
  }

  ObservedPtr<CPDFSDK_Annot> pWidgetAnnot(pAnnot);

  // Passing wrong subtype to BAAnnotHandler, API should return false.
  EXPECT_FALSE(GetBAAnnotHandler()->OnSetFocus(&pWidgetAnnot, 0));

  EXPECT_FALSE(GetBAAnnotHandler()->OnKillFocus(&pWidgetAnnot, 0));
}
