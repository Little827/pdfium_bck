// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_PDFIUM_EXPORT_H_
#define PUBLIC_PDFIUM_EXPORT_H_

#if defined(_WIN32) && defined(FPDFSDK_EXPORTS)
// On Windows system, functions are exported in a DLL
#define PDFIUM_EXPORT __declspec(dllexport)
#define PDFIUM_CALLCONV __stdcall
#else
#define PDFIUM_EXPORT
#define PDFIUM_CALLCONV
#endif

#endif  // PUBLIC_PDFIUM_EXPORT_H_
