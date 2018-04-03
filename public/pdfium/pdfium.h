// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_PDFIUM_PDFIUM_H_
#define PUBLIC_PDFIUM_PDFIUM_H_

#include <string>
#include <vector>

#include "public/pdfium/export.h"
#include "public/pdfium/document.h"
#include "public/pdfium/unsupported_feature_delegate.h"

namespace pdfium {

enum class Status {
  kSuccess = 0,
  kUnknownError = 1,
  kFileNotFoundOrFileError = 2,
  kFileInvalid = 3,
  kPasswordError = 4,
  kUnsupportSecurityScheme = 5,
  kPageNotFoundOrContentError = 6,
#if PDF_EENABLE_XFA
  kXFALoadError = 7,
  kXFALayoutError = 8
#endif  // PDF_ENABLE_XFA
};

/// Data used to initialize the library.
struct Config {
  Config();
  ~Config();

  /// Paths to scan in place of the defaults when using built-in font loading
  /// code. The path list may be empty which will cause the system to use the
  /// default paths.
  ///
  /// Note, depending on the host platform, these paths may have now effect.
  std::vector<std::string> user_font_paths;

  /// Pointer to the vi::Isolate to use, or |nullptr| to have the library
  /// create an isolate.
  void* js_isolate;

  /// The embedder data slot to use in the v8::Isolate to store the
  /// per-isolate data. The value needs to be between 0 and
  /// v8::Internals::kNumIsolateDataLots (exclusive). The 0 value is fine for
  /// most embedders.
  uint32_t js_embedder_slot;
};

/// Initialize the library
///
///   config the configuration data used during initialization
///
/// Note, you must call this method before calling any other PDFium code.
PDFIUM_EXPORT void PDFIUM_CALLCONV Initialize(const Config& config);

/// Shutdown the library and release all resources.
///
/// Note, after calling this method you may not call any other PDFium code.
PDFIUM_EXPORT void PDFIUM_CALLCONV Shutdown();

/// Sets the delegate to call for unsupported features.
///
///  delegate the |UnsupportedFeatureDelegate| subclass
PDFIUM_EXPORT void PDFIUM_CALLCONV
SetUnsupportedFeatureDelegate(const UnsupportedFeatureDelegate* delegate);

/// Returns the status code from the last method.
PDFIUM_EXPORT Status PDFIUM_CALLCONV GetLastStatus();

/// Returns the string representation of the given |Status|
///
///   status the status code to return
PDFIUM_EXPORT std::string PDFIUM_CALLCONV StatusString(Status status);

}  // namespace pdfium

#endif  // PUBLIC_PDFIUM_PDFIUM_H_
