// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef PUBLIC_FPDF_PPO_H_
#define PUBLIC_FPDF_PPO_H_

// NOLINTNEXTLINE(build/include)
#include "fpdfview.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int numPagesOnXAxis;
  int numPagesOnYAxis;
  int destPageWidth;
  int destPageHeight;
} FPDF_NUP_LAYOUT;

// Import pages to a FPDF_DOCUMENT.
//
//   dest_doc  - The destination document for the pages.
//   src_doc   - The document to be imported.
//   pagerange - A page range string, Such as "1,3,5-7". If |pagerange| is NULL,
//               all pages from |src_doc| are imported.
//   index     - The page index to insert at.
//
// Returns TRUE on success.
FPDF_EXPORT FPDF_BOOL FPDF_CALLCONV FPDF_ImportPages(FPDF_DOCUMENT dest_doc,
                                                     FPDF_DOCUMENT src_doc,
                                                     FPDF_BYTESTRING pagerange,
                                                     int index);

// Experimental API.
// Import pages to a FPDF_DOCUMENT.
//
//   dest_doc           - The destination document for the pages.
//   src_doc            - The document to be imported.
//   pagerange          - A page range string, Such as "1,3,5-7". If |pagerange|
//                        is NULL, all pages from |src_doc| are imported.
//   index              - The page index to insert at.
//   num_pages_per_page - A number indicates how many pages to be inserted into
//                        one page.
//                        num_pages_per_page > 1 : import multiple pages onto
//                                                 the same page.
//                        num_pages_per_page == 1 : same as FPDF_ImportPages.
//
// Returns TRUE on success.
// Supported num_pages_per_page: 1, 2, 4, 6, 9, 16
// num_pages_per_page = 1 : pages layout will be 1 X 1
// num_pages_per_page = 2 : pages layout will be 1 X 2
// num_pages_per_page = 4 : pages layout will be 2 X 2
// num_pages_per_page = 6 : pages layout will be 2 X 3
// num_pages_per_page = 9 : pages layout will be 3 X 3
// num_pages_per_page = 16: pages layout will be 4 X 4
FPDF_EXPORT FPDF_BOOL FPDF_CALLCONV
FPDF_ImportNPagesToOne(FPDF_DOCUMENT dest_doc,
                       FPDF_DOCUMENT src_doc,
                       FPDF_BYTESTRING pagerange,
                       int index,
                       FPDF_NUP_LAYOUT nuplayout);

// Copy the viewer preferences from |src_doc| into |dest_doc|.
//
//   dest_doc - Document to write the viewer preferences into.
//   src_doc  - Document to read the viewer preferences from.
//
// Returns TRUE on success.
FPDF_EXPORT FPDF_BOOL FPDF_CALLCONV
FPDF_CopyViewerPreferences(FPDF_DOCUMENT dest_doc, FPDF_DOCUMENT src_doc);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // PUBLIC_FPDF_PPO_H_
