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

// Experimental API.
// Gets the decoded data from the thumbnail of |page| if it exists.
// This only modifies |buffer| if |buflen| less than or equal to the
// size of the decoded data. Returns the size of the uncompressed
// data or 0 if thumbnail DNE. Optional, pass null to just retrieve
// the size of the buffer needed.
//
//   page    - handle to a page.
//   buffer  - buffer for holding the decoded image data in raw bytes.
//   buflen  - size of |buffer|.
FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetDecodedThumbnailDataFromPage(FPDF_PAGE page,
                                         void* buffer,
                                         unsigned long buflen);

// Experimental API.
// Gets the raw data from the thumbnail of |page| if it exists.
// This only modifies |buffer| if |buflen| is less than or equal to
// the size of the raw data. Returns the size of the raw data or 0
// if thumbnail DNE. Optional, pass null to just retrieve the size
// of the buffer needed.
//
//   page    - handle to a page.
//   buffer  - buffer for holding the raw image data in raw bytes.
//   buflen  - size of |buffer|.
FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFPage_GetRawThumbnailDataFromPage(FPDF_PAGE page,
                                     void* buffer,
                                     unsigned long buflen);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_FPDF_THUMBNAIL_H_
