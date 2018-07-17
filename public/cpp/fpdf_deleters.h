// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_CPP_FPDF_DELETERS_H_
#define PUBLIC_CPP_FPDF_DELETERS_H_

#include "public/fpdf_annot.h"
#include "public/fpdf_dataavail.h"
#include "public/fpdf_edit.h"
#include "public/fpdf_formfill.h"
#include "public/fpdf_structtree.h"
#include "public/fpdf_text.h"
#include "public/fpdfview.h"

// Custom deleters for using FPDF_* types with std::unique_ptr<>.

template <class T, void (*DEL)(T)>
struct __Deleter {
  inline void operator()(T obj) { DEL(obj); }
}

using FPDFAnnotationDeleter = __Deleter<FPDF_ANNOTATION, FPDFPage_CloseAnnot>;

using FPDFAvailDeleter = __Deleter<FPDF_AVAIL, FPDFAvail_Destroy>;

using FPDFBitmapDeleter = __Deleter<FPDF_BITMAP, FPDFBitmap_Destroy>;

using FPDFDocumentDeleter = __Deleter<FPDF_DOCUMENT, FPDF_CloseDocument>;

using FPDFFormHandleDeleter =
    __Deleter<FPDF_FORMHANDLE, FPDFDOC_ExitFormFillEnvironment>;

using FPDFTextPageDeleter = __Deleter<FPDF_TEXTPAGE, FPDFText_ClosePage>;

using FPDFPageDeleter = __Deleter<FPDF_PAGE, FPDF_ClosePage>;

using FPDFPageLinkDeleter = __Deleter<FPDF_PAGELINK, FPDFLink_CloseWebLinks>;

using FPDFStructTreeDeleter = __Deleter<FPDF_STRUCTTREE, FPDF_StructTree_Close>;

using FPDFFontDeleter = __Deleter<FPDF_FONT, FPDFFont_Close>;

#endif  // PUBLIC_CPP_FPDF_DELETERS_H_
