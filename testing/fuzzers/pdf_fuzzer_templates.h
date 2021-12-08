// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// File for holding strings representing PDF templates that are used by fuzzers.

#ifndef TESTING_FUZZERS_PDF_FUZZER_TEMPLATES_H_
#define TESTING_FUZZERS_PDF_FUZZER_TEMPLATES_H_

constexpr char kSimplePdfTemplate[] = R"(%PDF-1.7
1 0 obj
<</Type /Catalog /Pages 2 0 R /AcroForm <</XFA 30 0 R>> /NeedsRendering true>>
endobj
2 0 obj
<</Type /Pages /Kids [3 0 R] /Count 1>>
endobj
3 0 obj
<</Type /Page /Parent 2 0 R /MediaBox [0 0 3 3]>>
endobj
30 0 obj
<</Length $1>>
stream
$2
endstream
endobj
trailer
<</Root 1 0 R /Size 31>>
%%EOF)";

// Template PDF file for XDP-spec fuzzing. There are three unknowns in 2 0 obj,
// which are to be subtitued by the types of objects 6, 7 and 8.
const char kSimpleXDPPdfTemplate[] = R""(%PDF-1.7
%âãÏÓ
1 0 obj
<</AcroForm 2 0 R /Extensions
  <</ADBE <</BaseVersion /1.7 /ExtensionLevel 8>>>> /NeedsRendering true
  /Pages 3 0 R /Type /Catalog>>
endobj
2 0 obj
<</XFA
  [(preamble) 5 0 R ($1) 6 0 R ($2) 7 0 R ($3) 8 0 R
  (postamble) 9 0 R]>>
endobj
3 0 obj
<</Count 1 /Kids [4 0 R] /Type /Pages>>
endobj
4 0 obj
<</MediaBox [0 0 612 792] /Parent 2 0 R /Type /Page>>
endobj)"";

#endif  // TESTING_FUZZERS_PDF_FUZZER_TEMPLATES_H_
