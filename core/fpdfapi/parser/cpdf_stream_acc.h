// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_PARSER_CPDF_STREAM_ACC_H_
#define CORE_FPDFAPI_PARSER_CPDF_STREAM_ACC_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "core/fxcrt/bytestring.h"
#include "core/fxcrt/data_vector.h"
#include "core/fxcrt/retain_ptr.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/base/span.h"

class CPDF_Dictionary;
class CPDF_Stream;

class CPDF_StreamAcc final : public Retainable {
 public:
  CONSTRUCT_VIA_MAKE_RETAIN;

  CPDF_StreamAcc(const CPDF_StreamAcc&) = delete;
  CPDF_StreamAcc& operator=(const CPDF_StreamAcc&) = delete;

  void LoadAllDataFiltered();
  void LoadAllDataFilteredWithEstimatedSize(uint32_t estimated_size);
  void LoadAllDataImageAcc(uint32_t estimated_size);
  void LoadAllDataRaw();

  const CPDF_Stream* GetStream() const { return m_pStream.Get(); }
  const CPDF_Dictionary* GetDict() const;

  uint32_t GetSize() const;
  pdfium::span<const uint8_t> GetSpan() const;
  ByteString ComputeDigest() const;
  ByteString GetImageDecoder() const { return m_ImageDecoder; }
  const CPDF_Dictionary* GetImageParam() const { return m_pImageParam.Get(); }
  DataVector<uint8_t> DetachData();

 private:
  explicit CPDF_StreamAcc(const CPDF_Stream* pStream);
  ~CPDF_StreamAcc() override;

  void LoadAllData(bool bRawAccess, uint32_t estimated_size, bool bImageAcc);
  void ProcessRawData();
  void ProcessFilteredData(uint32_t estimated_size, bool bImageAcc);
  const uint8_t* GetData() const;

  // Returns the raw data from `m_pStream`, or no data on failure.
  DataVector<uint8_t> ReadRawStream() const;

  bool is_owned() const { return m_Data.index() == 1; }

  absl::variant<pdfium::span<const uint8_t>, DataVector<uint8_t>> m_Data;
  ByteString m_ImageDecoder;
  RetainPtr<const CPDF_Dictionary> m_pImageParam;
  RetainPtr<const CPDF_Stream> const m_pStream;
};

#endif  // CORE_FPDFAPI_PARSER_CPDF_STREAM_ACC_H_
