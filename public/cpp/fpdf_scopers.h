// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_CPP_FPDF_SCOPERS_H_
#define PUBLIC_CPP_FPDF_SCOPERS_H_

#include <memory>
#include <type_traits>

#include "public/cpp/fpdf_deleters.h"
#include "public/fpdf_annot.h"
#include "public/fpdf_dataavail.h"
#include "public/fpdf_edit.h"
#include "public/fpdf_formfill.h"
#include "public/fpdf_structtree.h"
#include "public/fpdf_text.h"
#include "public/fpdfview.h"

template <class T, class DEL>
using __Scoper = std::unique_ptr<std::remove_pointer<T>::type, DEL>;

// Versions of FPDF types that clean up the object at scope exit.

using ScopedFPDFAnnotation = __Scoper<FPDF_ANNOTATION, FPDFAnnotationDeleter>;

using ScopedFPDFAvail = __Scoper<FPDF_AVAIL, FPDFAvailDeleter>;

using ScopedFPDFBitmap = __Scoper<FPDF_BITMAP, FPDFBitmapDeleter>;

using ScopedFPDFDocument = __Scoper<FPDF_DOCUMENT, FPDFDocumentDeleter>;

using ScopedFPDFFormHandle = __Scoper<FPDF_FORMHANDLE, FPDFFormHandleDeleter>;

using ScopedFPDFTextPage = __Scoper<FPDF_TEXTPAGE, FPDFTextPageDeleter>;

using ScopedFPDFPage = __Scoper<FPDF_PAGE, FPDFPageDeleter>;

using ScopedFPDFPageLink = __Scoper<FPDF_PAGELINK, FPDFPageLinkDeleter>;

using ScopedFPDFStructTree = __Scoper<FPDF_STRUCTTREE, FPDFStructTreeDeleter>;

using ScopedFPDFFont = __Scoper<FPDF_FONT, FPDFFontDeleter>;

#endif  // PUBLIC_CPP_FPDF_SCOPERS_H_
