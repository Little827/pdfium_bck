// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/edit/cpdf_stringarchivestream.h"

#include <sstream>

#include "third_party/base/notreached.h"

CPDF_StringArchiveStream::CPDF_StringArchiveStream(std::ostringstream* stream)
    : stream_(stream) {}

CPDF_StringArchiveStream::~CPDF_StringArchiveStream() = default;

bool CPDF_StringArchiveStream::WriteByte(uint8_t byte) {
  NOTREACHED();
  return false;
}

bool CPDF_StringArchiveStream::WriteDWord(uint32_t i) {
  NOTREACHED();
  return false;
}

FX_FILESIZE CPDF_StringArchiveStream::CurrentOffset() const {
  NOTREACHED();
  return false;
}

bool CPDF_StringArchiveStream::WriteBlock(pdfium::span<const uint8_t> pData) {
  stream_->write(reinterpret_cast<const char*>(pData.data()), pData.size());
  return true;
}

bool CPDF_StringArchiveStream::WriteString(ByteStringView str) {
  stream_->write(str.unterminated_c_str(), str.GetLength());
  return true;
}
