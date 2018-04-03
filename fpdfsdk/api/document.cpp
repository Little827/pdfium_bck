// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "public/pdfium/document.h"

#include "core/fxcrt/fx_stream.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fpdfsdk/cpdfsdk_memoryaccess.h"
#include "third_party/base/ptr_util.h"
#include "core/fpdfapi/parser/cpdf_parser.h"
#include "core/fpdfapi/parser/cpdf_string.h"
#include "core/fpdfapi/parser/cpdf_document.h"

namespace pdfium {

struct DocumentWrapper {
  std::unique_ptr<UnderlyingDocumentType> doc;
};

namespace {

std::unique_ptr<Document> LoadDocument(
    const RetainPtr<IFX_SeekableReadStream>& pFileAccess,
    const std::string& password) {
  if (!pFileAccess) {
    ProcessParseError(CPDF_Parser::FILE_ERROR);
    return nullptr;
  }

  auto pParser = pdfium::MakeUnique<CPDF_Parser>();
  pParser->SetPassword(password.c_str());

  auto pDocument = pdfium::MakeUnique<CPDF_Document>(std::move(pParser));
  CPDF_Parser::Error error =
      pDocument->GetParser()->StartParse(pFileAccess, pDocument.get());
  if (error != CPDF_Parser::SUCCESS) {
    ProcessParseError(error);
    return nullptr;
  }
  CheckUnSupportError(pDocument.get(), error);

  // The FPDFDocumentFromCPDFDocument will convert the document into the
  // correct underlying type.
  auto wrapper = pdfium::MakeUnique<DocumentWrapper>();
  wrapper->doc = pdfium::WrapUnique<UnderlyingDocumentType>(
      UnderlyingFromFPDFDocument(FPDFDocumentFromCPDFDocument(pDocument.release())));
  return pdfium::MakeUnique<Document>(std::move(wrapper));
}

}  // namespace

// static
std::unique_ptr<Document> Document::LoadFile(const std::string& file,
                                             const std::string& password) {
  return LoadDocument(IFX_SeekableReadStream::CreateFromFilename(file.c_str()),
                          password);
}

// static
std::unique_ptr<Document> Document::LoadMemory(const uint8_t* data,
                                     size_t size,
                                     const std::string& password) {
  return LoadDocument(pdfium::MakeRetain<CPDFSDK_MemoryAccess>(
                             data, size), password);
}

Document::Document() {
  wrapper_ = pdfium::MakeUnique<DocumentWrapper>();

  auto doc = pdfium::MakeUnique<CPDF_Document>(nullptr);
  doc->CreateNewDoc();

  time_t currentTime;
  ByteString DateStr;
  if (time(&currentTime) != -1) {
    tm* pTM = localtime(&currentTime);
    if (pTM) {
      DateStr = ByteString::Format(
          "D:%04d%02d%02d%02d%02d%02d", pTM->tm_year + 1900, pTM->tm_mon + 1,
          pTM->tm_mday, pTM->tm_hour, pTM->tm_min, pTM->tm_sec);
    }
  }

  CPDF_Dictionary* pInfoDict = doc->GetInfo();
  if (!pInfoDict)
    return;

  pInfoDict->SetNewFor<CPDF_String>("CreationDate", DateStr, false);
  pInfoDict->SetNewFor<CPDF_String>("Creator", L"PDFium");

  wrapper_->doc = pdfium::WrapUnique<UnderlyingDocumentType>(
      UnderlyingFromFPDFDocument(FPDFDocumentFromCPDFDocument(doc.release())));
}

Document::Document(std::unique_ptr<DocumentWrapper> wrapper) : wrapper_(std::move(wrapper)) {
  ASSERT(wrapper_);
  ASSERT(wrapper_->doc);
}

Document::~Document() = default;

size_t Document::PageCount() const {
  return wrapper_->doc->GetPageCount();
}

FPDF_DOCUMENT Document::AsUnderlyingDocument() {
  return wrapper_->doc.get();
}

void Document::SetUnderlyingForTesting(std::unique_ptr<FPDF_DOCUMENT> underlying) {
  wrapper_->doc = pdfium::WrapUnique<UnderlyingDocumentType>(
      UnderlyingFromFPDFDocument(underlying.release()));
}

}  // namespace pdfium
