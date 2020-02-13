// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fpdfsdk/cpdfsdk_annot.h"
#include "fpdfsdk/cpdfsdk_annotiterator.h"
#include "fpdfsdk/cpdfsdk_formfillenvironment.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fpdfsdk/formfiller/cffl_formfiller.h"
#include "fpdfsdk/formfiller/cffl_interactiveformfiller.h"
#include "fpdfsdk/pwl/cpwl_special_button.h"
#include "fpdfsdk/pwl/cpwl_wnd.h"
#include "public/fpdf_fwlevent.h"
#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

class CPWLSpecialButtonEmbedderTest : public EmbedderTest {
 protected:
  void SetUp() override {
    EmbedderTest::SetUp();
    CreateAndInitializeFormPDF();
  }

  void TearDown() override {
    UnloadPage(GetPage());
    EmbedderTest::TearDown();
  }

  void CreateAndInitializeFormPDF() {
    EXPECT_TRUE(OpenDocument("click_form.pdf"));

    m_page = LoadPage(0);
    ASSERT_TRUE(m_page);

    m_pFormFillEnv =
        CPDFSDKFormFillEnvironmentFromFPDFFormHandle(form_handle());
    CPDFSDK_AnnotIterator iter(m_pFormFillEnv->GetPageView(0),
                               CPDF_Annot::Subtype::WIDGET);

    // Read only Check box
    m_pAnnotReadOnlyCheckBox = iter.GetFirstAnnot();
    ASSERT_TRUE(m_pAnnotReadOnlyCheckBox);
    ASSERT_EQ(CPDF_Annot::Subtype::WIDGET,
              m_pAnnotReadOnlyCheckBox->GetAnnotSubtype());

    // Check box
    m_pAnnotCheckBox = iter.GetNextAnnot(m_pAnnotReadOnlyCheckBox);
    ASSERT_TRUE(m_pAnnotCheckBox);
    ASSERT_EQ(CPDF_Annot::Subtype::WIDGET, m_pAnnotCheckBox->GetAnnotSubtype());

    // Read only radio button
    m_pAnnotReadOnlyRadioButton = iter.GetNextAnnot(m_pAnnotCheckBox);
    ASSERT_TRUE(m_pAnnotReadOnlyRadioButton);
    ASSERT_EQ(CPDF_Annot::Subtype::WIDGET,
              m_pAnnotReadOnlyRadioButton->GetAnnotSubtype());

    // Tabbing four times from read only radio button to unselected normal radio
    // button.
    m_pAnnotRadioButton = iter.GetNextAnnot(m_pAnnotReadOnlyRadioButton);
    m_pAnnotRadioButton = iter.GetNextAnnot(m_pAnnotReadOnlyRadioButton);
    m_pAnnotRadioButton = iter.GetNextAnnot(m_pAnnotReadOnlyRadioButton);
    m_pAnnotRadioButton = iter.GetNextAnnot(m_pAnnotReadOnlyRadioButton);
    ASSERT_TRUE(m_pAnnotRadioButton);
    ASSERT_EQ(CPDF_Annot::Subtype::WIDGET,
              m_pAnnotRadioButton->GetAnnotSubtype());
  }

  void CheckBoxAndWindowSetUp(CPDFSDK_Annot* annot) {
    CFFL_InteractiveFormFiller* pInteractiveFormFiller =
        m_pFormFillEnv->GetInteractiveFormFiller();
    {
      ObservedPtr<CPDFSDK_Annot> pObserved(annot);
      EXPECT_TRUE(pInteractiveFormFiller->OnSetFocus(&pObserved, 0));
    }

    m_pFormFiller = pInteractiveFormFiller->GetFormFillerForTesting(annot);
    ASSERT_TRUE(m_pFormFiller);

    CPWL_Wnd* pWindow =
        m_pFormFiller->GetPWLWindow(m_pFormFillEnv->GetPageView(0), true);
    ASSERT_TRUE(pWindow);
    m_pCheckBox = static_cast<CPWL_CheckBox*>(pWindow);
  }

  void RadioButtonAndWindowSetUp(CPDFSDK_Annot* annot) {
    CFFL_InteractiveFormFiller* pInteractiveFormFiller =
        m_pFormFillEnv->GetInteractiveFormFiller();
    {
      ObservedPtr<CPDFSDK_Annot> pObserved(annot);
      EXPECT_TRUE(pInteractiveFormFiller->OnSetFocus(&pObserved, 0));
    }

    m_pFormFiller = pInteractiveFormFiller->GetFormFillerForTesting(annot);
    ASSERT_TRUE(m_pFormFiller);

    CPWL_Wnd* pWindow =
        m_pFormFiller->GetPWLWindow(m_pFormFillEnv->GetPageView(0), true);
    ASSERT_TRUE(pWindow);
    m_pRadioButton = static_cast<CPWL_RadioButton*>(pWindow);
  }

  FPDF_PAGE GetPage() const { return m_page; }
  CPWL_CheckBox* GetCPWLCheckBox() const { return m_pCheckBox; }
  CPWL_RadioButton* GetCPWLRadioButton() const { return m_pRadioButton; }
  CFFL_FormFiller* GetCFFLFormFiller() const { return m_pFormFiller; }
  CPDFSDK_Annot* GetCPDFSDKAnnotCheckBox() const { return m_pAnnotCheckBox; }
  CPDFSDK_Annot* GetCPDFSDKAnnotReadOnlyCheckBox() const {
    return m_pAnnotReadOnlyCheckBox;
  }
  CPDFSDK_Annot* GetCPDFSDKAnnotRadioButton() const {
    return m_pAnnotRadioButton;
  }
  CPDFSDK_Annot* GetCPDFSDKAnnotReadOnlyRadioButton() const {
    return m_pAnnotReadOnlyRadioButton;
  }
  CPDFSDK_FormFillEnvironment* GetCPDFSDKFormFillEnv() const {
    return m_pFormFillEnv;
  }

 private:
  FPDF_PAGE m_page;
  CFFL_FormFiller* m_pFormFiller;
  CPWL_CheckBox* m_pCheckBox;
  CPWL_RadioButton* m_pRadioButton;
  CPDFSDK_Annot* m_pAnnotCheckBox;
  CPDFSDK_Annot* m_pAnnotReadOnlyCheckBox;
  CPDFSDK_Annot* m_pAnnotRadioButton;
  CPDFSDK_Annot* m_pAnnotReadOnlyRadioButton;
  CPDFSDK_FormFillEnvironment* m_pFormFillEnv;
};

TEST_F(CPWLSpecialButtonEmbedderTest, EnterOnReadOnlyCheckBox) {
  CheckBoxAndWindowSetUp(GetCPDFSDKAnnotReadOnlyCheckBox());
  EXPECT_TRUE(GetCPDFSDKFormFillEnv()->GetInteractiveFormFiller()->OnChar(
      GetCPDFSDKAnnotReadOnlyCheckBox(), '\r', 0));
  // The check box is checked by default. Since it is a read only checkbox,
  // clicking Enter is not expected to uncheck it.
  // TODO(crbug.com/1051849) : Following check should be changed to EXPECT_TRUE
  // once the issue is fixed.
  EXPECT_FALSE(GetCPWLCheckBox()->IsChecked());
}

TEST_F(CPWLSpecialButtonEmbedderTest, EnterOnCheckBox) {
  CheckBoxAndWindowSetUp(GetCPDFSDKAnnotCheckBox());
  EXPECT_TRUE(GetCPDFSDKFormFillEnv()->GetInteractiveFormFiller()->OnChar(
      GetCPDFSDKAnnotCheckBox(), '\r', 0));
  EXPECT_TRUE(GetCPWLCheckBox()->IsChecked());

  EXPECT_TRUE(GetCPDFSDKFormFillEnv()->GetInteractiveFormFiller()->OnChar(
      GetCPDFSDKAnnotCheckBox(), '\r', 0));
  EXPECT_FALSE(GetCPWLCheckBox()->IsChecked());
}

TEST_F(CPWLSpecialButtonEmbedderTest, EnterOnReadOnlyRadioButton) {
  RadioButtonAndWindowSetUp(GetCPDFSDKAnnotReadOnlyRadioButton());
  EXPECT_TRUE(GetCPDFSDKFormFillEnv()->GetInteractiveFormFiller()->OnChar(
      GetCPDFSDKAnnotReadOnlyRadioButton(), '\r', 0));
  // TODO(crbug.com/1051849) : Following check should be changed to EXPECT_FALSE
  // once the issue is fixed.
  EXPECT_TRUE(GetCPWLRadioButton()->IsChecked());
}

TEST_F(CPWLSpecialButtonEmbedderTest, EnterOnRadioButton) {
  RadioButtonAndWindowSetUp(GetCPDFSDKAnnotRadioButton());
  EXPECT_TRUE(GetCPDFSDKFormFillEnv()->GetInteractiveFormFiller()->OnChar(
      GetCPDFSDKAnnotRadioButton(), '\r', 0));
  EXPECT_TRUE(GetCPWLRadioButton()->IsChecked());
}
