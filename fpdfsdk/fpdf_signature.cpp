// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_signature.h"

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "fpdfsdk/cpdfsdk_helpers.h"

FPDF_EXPORT int FPDF_CALLCONV FPDF_GetSignatureCount(FPDF_DOCUMENT document) {
  auto* pDoc = CPDFDocumentFromFPDFDocument(document);
  if (!pDoc)
    return -1;

  CPDF_Dictionary* pRoot = pDoc->GetRoot();
  if (!pRoot)
    return 0;

  const CPDF_Dictionary* pAcroForm = pRoot->GetDictFor("AcroForm");
  if (!pAcroForm)
    return 0;

  const CPDF_Array* pFields = pAcroForm->GetArrayFor("Fields");
  if (!pFields)
    return 0;

  int nSignatureCount = 0;
  for (size_t nField = 0; nField < pFields->size(); ++nField) {
    const CPDF_Object* pField = pFields->GetObjectAt(nField);
    const CPDF_Dictionary* pFieldDict = pField->GetDict();
    if (!pFieldDict)
      continue;

    if (pFieldDict->GetStringFor("FT") != "Sig")
      continue;

    ++nSignatureCount;
  }

  return nSignatureCount;
}
