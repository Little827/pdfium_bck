// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_FPDF_THUMBNAIL_H_
#define PUBLIC_FPDF_THUMBNAIL_H_

#include <stdint.h>

// NOLINTNEXTLINE(build/include)
#include "fpdfview.h"

#ifdef __cplusplus
extern "C" {
#endif

// Gets the size of the compressed stream for a thumbnail of |page|.
//
//   page - handle to a page.
FPDF_EXPORT uint32_t FPDF_CALLCONV
FPDFPage_GetThumbnailStreamSize(FPDF_PAGE page);

// Gets the decoded data from the thumbnail of |page| if it exists.
// Returns the size of the uncompressed data.
//
//   page    - handle to a page.
//   buffer  - buffer for holding the decoded image data in raw bytes.
//   buflen - size of |buffer|.
FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetDecodedThumbnailDataFromPage(FPDF_PAGE page,
                                         void* buffer,
                                         unsigned long buflen);

// Gets the raw data from the thumbnail of |page| if it exists.
// Returns the size of the uncompressed data.
//
//   page    - handle to a page.
//   buffer  - buffer for holding the decoded image data in raw bytes.
//   buflen - size of |buffer|.
FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetRawThumbnailDataFromPage(FPDF_PAGE page,
                                     void* buffer,
                                     unsigned long buflen);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_FPDF_THUMBNAIL_H_
