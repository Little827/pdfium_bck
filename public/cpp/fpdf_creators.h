// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_CPP_FPDF_CREATORS_H_
#define PUBLIC_CPP_FPDF_CREATORS_H_

#include "public/cpp/fpdf_scopers.h"
#include "public/fpdf_dataavail.h"
#include "public/fpdf_edit.h"
#include "public/fpdf_formfill.h"
#include "public/fpdf_structtree.h"
#include "public/fpdf_text.h"

// Convenience routines to create a scoped FPDF type, when there is a
// single obvious way to make the type.

inline ScopedFPDFAvail CreateScopedFPDFAvail(FX_FILEAVAIL* file_avail,
                                             FPDF_FILEACCESS* file) {
  return ScopedFPDFAvail(FPDFAvail_Create(file_avail, file));
}

inline ScopedFPDFFormHandle CreateScopedFPDFFormHandle(
    FPDF_DOCUMENT document,
    FPDF_FORMFILLINFO* info) {
  return ScopedFPDFFormHandle(FPDFDOC_InitFormFillEnvironment(document, info));
}

inline ScopedFPDFTextPage CreateScopedFPDFTextPage(FPDF_PAGE page) {
  return ScopedFPDFTextPage(FPDFText_LoadPage(page));
}

inline ScopedFPDFStructTree CreateScopedFPDFStructTree(FPDF_PAGE page) {
  return ScopedFPDFStructTree(FPDF_StructTree_GetForPage(page));
}

inline ScopedFPDFFont CreateScopedFPDFFont(FPDF_DOCUMENT doc,
                                           const uint8_t* data,
                                           uint32_t size,
                                           int font_type,
                                           FPDF_BOOL cid) {
  return ScopedFPDFFont(FPDFText_LoadFont(doc, data, size, font_type, cid));
}

#endif  // PUBLIC_CPP_FPDF_CREATORS_H_
