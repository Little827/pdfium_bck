// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_thumbnail.h"

#include <vector>

#include "core/fpdfapi/page/cpdf_page.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fpdfapi/render/cpdf_dibbase.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "public/fpdfview.h"

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

FPDF_EXPORT FPDF_BITMAP FPDF_CALLCONV
FPDFPage_GetThumbnailAsBitmapFromPage(FPDF_PAGE page) {
  CPDF_Stream* thumb_stream = CPDFStreamForThumbnailFromPage(page);
  if (!thumb_stream)
    return nullptr;

  CPDF_Page* p_page = CPDFPageFromFPDFPage(page);
  if (!p_page || !p_page->GetDocument())
    return nullptr;

  unsigned int decoded_data_size =
      FPDFPage_GetDecodedThumbnailDataFromPage(page, NULL, 0);

  std::vector<uint8_t> thumb_buf(decoded_data_size);

  if (decoded_data_size != FPDFPage_GetDecodedThumbnailDataFromPage(
                               page, thumb_buf.data(), decoded_data_size))
    return nullptr;

  // thumb_buf destroyed on return so clone data and retain
  thumb_stream->SetDataAndRemoveFilter(thumb_buf);
  auto thumb_stream_acc = pdfium::MakeRetain<CPDF_StreamAcc>(thumb_stream);

  auto p_source = pdfium::MakeRetain<CPDF_DIBBase>();
  CPDF_DIBBase::LoadState start_status = p_source->StartLoadDIBBase(
      p_page->GetDocument(), thumb_stream, false, nullptr,
      p_page->m_pPageResources.Get(), false, 0, false);
  if (start_status == CPDF_DIBBase::LoadState::kFail)
    return nullptr;

  auto thumb_bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
  if (!thumb_bitmap->Create(p_source->GetWidth(), p_source->GetHeight(),
                            p_source->GetFormat(), thumb_stream_acc->GetData(),
                            p_source->GetPitch())) {
    thumb_bitmap.Reset();
    return nullptr;
  }

  return FPDFBitmapFromCFXDIBitmap(thumb_bitmap.Leak());
}
