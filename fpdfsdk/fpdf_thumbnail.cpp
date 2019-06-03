// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_thumbnail.h"

#include "core/fpdfapi/page/cpdf_page.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "fpdfsdk/cpdfsdk_helpers.h"

namespace {

CPDF_Stream* CPDFStreamForThumbnailFromPage(FPDF_PAGE page) {
  CPDF_Page* pPage = CPDFPageFromFPDFPage(page);
  if (!pPage)
    return nullptr;

  CPDF_Dictionary* pFormDict = pPage->GetDict();
  if (!pFormDict || !pFormDict->KeyExist("Type"))
    return nullptr;

  CPDF_Object* pObj = pFormDict->GetObjectFor("Thumb");
  if (!pObj)
    return nullptr;

  CPDF_Object* thumbObj = pObj->GetDirect();
  if (!thumbObj)
    return nullptr;

  CPDF_Stream* pStream = thumbObj->AsStream();
  if (!pStream)
    return nullptr;

  return pStream;
}

}  // namespace

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetDecodedThumbnailDataFromPage(FPDF_PAGE page,
                                         void* buffer,
                                         unsigned long buflen) {
  CPDF_Stream* pStream = CPDFStreamForThumbnailFromPage(page);
  if (!pStream)
    return 0u;

  return DecodeStreamMaybeCopyAndReturnLength(pStream, buffer, buflen);
}

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetEncodedThumbnailDataFromPage(FPDF_PAGE page,
                                         void* buffer,
                                         unsigned long buflen) {
  CPDF_Stream* pStream = CPDFStreamForThumbnailFromPage(page);
  if (!pStream)
    return 0u;

  return EncodeStreamMaybeCopyAndReturnLength(pStream, buffer, buflen);
}
