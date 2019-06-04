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
  CPDF_Page* p_page = CPDFPageFromFPDFPage(page);
  if (!p_page)
    return nullptr;

  CPDF_Dictionary* page_dict = p_page->GetDict();
  if (!page_dict || !page_dict->KeyExist("Type"))
    return nullptr;

  CPDF_Object* thumb_obj = page_dict->GetObjectFor("Thumb");
  if (!thumb_obj)
    return nullptr;

  thumb_obj = thumb_obj->GetDirect();
  if (!thumb_obj)
    return nullptr;

  CPDF_Stream* thumb_stream = thumb_obj->AsStream();
  if (!thumb_stream)
    return nullptr;

  return thumb_stream;
}

}  // namespace

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetDecodedThumbnailDataFromPage(FPDF_PAGE page,
                                         void* buffer,
                                         unsigned long buflen) {
  CPDF_Stream* thumb_stream = CPDFStreamForThumbnailFromPage(page);
  if (!thumb_stream)
    return 0u;

  return DecodeStreamMaybeCopyAndReturnLength(thumb_stream, buffer, buflen);
}

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetRawThumbnailDataFromPage(FPDF_PAGE page,
                                     void* buffer,
                                     unsigned long buflen) {
  CPDF_Stream* thumb_stream = CPDFStreamForThumbnailFromPage(page);
  if (!thumb_stream)
    return 0u;

  return RawStreamMaybeCopyAndReturnLength(thumb_stream, buffer, buflen);
}
