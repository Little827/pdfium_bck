// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include "public/fpdfview.h"

namespace pdfium {

struct DocumentWrapper;

class Document {
 public:
  /// Creates a document from the given |file| using the given |password| if
  /// provided. Returns the Document on success or |nullptr| otherwise. The
  /// |GetLastStatus| method can be used to determine the failure reason.
  static std::unique_ptr<Document> LoadFile(const std::string& file,
                                            const std::string& password);

  /// Creates a document from the given |data| using the provided |password|.
  /// Returns the document on success or |nullptr| otherwise. The
  /// |GetLastStatus| method can be used to determine the failure reason.
  static std::unique_ptr<Document> LoadMemory(const uint8_t* data,
                                              size_t size,
                                              const std::string& password);

  // static std::unique_ptr<Document> LoadFromFileAccess(..., const std::string&
  // password);

  /// Creates a new, empty, document.
  Document();
  explicit Document(std::unique_ptr<DocumentWrapper> wrapper);
  ~Document();

  /// Returns the number of pages in the document.
  size_t PageCount() const;

  /// For migration purposes. Will be removed.
  FPDF_DOCUMENT AsUnderlyingDocument();

  void SetUnderlyingForTesting(std::unique_ptr<FPDF_DOCUMENT> underlying);

 private:
  std::unique_ptr<DocumentWrapper> wrapper_;
};

}  // namespace pdfium
