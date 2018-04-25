// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_CPP_FPDF_DELETERS_H_
#define PUBLIC_CPP_FPDF_DELETERS_H_

#include <memory>
#include <type_traits>

#include "public/fpdf_annot.h"
#include "public/fpdf_dataavail.h"
#include "public/fpdf_edit.h"
#include "public/fpdf_formfill.h"
#include "public/fpdf_structtree.h"
#include "public/fpdf_text.h"
#include "public/fpdfview.h"

// Custom deleters for using FPDF_* types with std::unique_ptr<>.

struct FPDFAnnotationDeleter {
  inline void operator()(FPDF_ANNOTATION annot) { FPDFPage_CloseAnnot(annot); }
};

struct FPDFAvailDeleter {
  inline void operator()(FPDF_AVAIL avail) { FPDFAvail_Destroy(avail); }
};

struct FPDFBitmapDeleter {
  inline void operator()(FPDF_BITMAP bitmap) { FPDFBitmap_Destroy(bitmap); }
};

struct FPDFDocumentDeleter {
  inline void operator()(FPDF_DOCUMENT doc) { FPDF_CloseDocument(doc); }
};

struct FPDFFormHandleDeleter {
  inline void operator()(FPDF_FORMHANDLE form) {
    FPDFDOC_ExitFormFillEnvironment(form);
  }
};

struct FPDFTextPageDeleter {
  inline void operator()(FPDF_TEXTPAGE text) { FPDFText_ClosePage(text); }
};

struct FPDFPageDeleter {
  inline void operator()(FPDF_PAGE page) { FPDF_ClosePage(page); }
};

struct FPDFStructTreeDeleter {
  inline void operator()(FPDF_STRUCTTREE tree) { FPDF_StructTree_Close(tree); }
};

struct FPDFFontDeleter {
  inline void operator()(FPDF_FONT font) { FPDFFont_Close(font); }
};

using ScopedFPDFAnnotation =
    std::unique_ptr<std::remove_pointer<FPDF_ANNOTATION>::type,
                    FPDFAnnotationDeleter>;

using ScopedFPDFAvail =
    std::unique_ptr<std::remove_pointer<FPDF_AVAIL>::type, FPDFAvailDeleter>;

using ScopedFPDFBitmap =
    std::unique_ptr<std::remove_pointer<FPDF_BITMAP>::type, FPDFBitmapDeleter>;

using ScopedFPDFDocument =
    std::unique_ptr<std::remove_pointer<FPDF_DOCUMENT>::type,
                    FPDFDocumentDeleter>;

using ScopedFPDFFormHandle =
    std::unique_ptr<std::remove_pointer<FPDF_FORMHANDLE>::type,
                    FPDFFormHandleDeleter>;

using ScopedFPDFTextPage =
    std::unique_ptr<std::remove_pointer<FPDF_TEXTPAGE>::type,
                    FPDFTextPageDeleter>;

using ScopedFPDFPage =
    std::unique_ptr<std::remove_pointer<FPDF_PAGE>::type, FPDFPageDeleter>;

using ScopedFPDFStructTree =
    std::unique_ptr<std::remove_pointer<FPDF_STRUCTTREE>::type,
                    FPDFStructTreeDeleter>;

using ScopedFPDFFont =
    std::unique_ptr<std::remove_pointer<FPDF_FONT>::type, FPDFFontDeleter>;

#endif  // PUBLIC_CPP_FPDF_DELETERS_H_
