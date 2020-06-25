// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_signature.h"

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "fpdfsdk/cpdfsdk_helpers.h"

FPDF_EXPORT int FPDF_CALLCONV FPDF_GetSignatureCount(FPDF_DOCUMENT document) {
  auto* doc = CPDFDocumentFromFPDFDocument(document);
  if (!doc)
    return -1;

  CPDF_Dictionary* root = doc->GetRoot();
  if (!root)
    return 0;

  const CPDF_Dictionary* acroForm = root->GetDictFor("AcroForm");
  if (!acroForm)
    return 0;

  const CPDF_Array* fields = acroForm->GetArrayFor("Fields");
  if (!fields)
    return 0;

  int signatureCount = 0;
  for (size_t fieldIndex = 0; fieldIndex < fields->size(); ++fieldIndex) {
    const CPDF_Object* field = fields->GetObjectAt(fieldIndex);
    const CPDF_Dictionary* fieldDict = field->GetDict();
    if (!fieldDict)
      continue;

    if (fieldDict->GetNameFor("FT") != "Sig")
      continue;

    ++signatureCount;
  }

  return signatureCount;
}
