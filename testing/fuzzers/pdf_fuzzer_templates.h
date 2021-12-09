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

constexpr char kSimplePdfHeader[] = R""(%PDF-1.7
%âãÏÓ)"";

constexpr char kSimpleAcroForm[] = R""(<</AcroForm 2 0 R /Extensions
  <</ADBE <</BaseVersion /1.7 /ExtensionLevel 8>>>> /NeedsRendering true
  /Pages 3 0 R /Type /Catalog>>)"";

constexpr char kSimpleXfaObjWrapper[] = R""(<</XFA
  [(preamble) 5 0 R ($1) 6 0 R ($2) 7 0 R ($3) 8 0 R
  (postamble) 9 0 R]>>)"";

constexpr char kSimpleObj1[] = R""(<</Count 1 /Kids [4 0 R] /Type /Pages>>)"";
constexpr char kSimpleMediabox[] =
    R""(<</MediaBox [0 0 612 792] /Parent 2 0 R /Type /Page>>)"";
constexpr char kSimplePreamble[] =
    R""(<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/" timeStamp="2021-12-14T14:14:14Z" uuid="11111111-1ab1-11b1-aa1a-1aaaaaaa11a1">)"";
constexpr char kSimplePostamble[] = R""("</xdp:xdp>")"";

#endif  // TESTING_FUZZERS_PDF_FUZZER_TEMPLATES_H_
