// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_PARSER_CPDF_STREAM_H_
#define CORE_FPDFAPI_PARSER_CPDF_STREAM_H_

#include <memory>
#include <set>
#include <vector>

#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fxcrt/fx_memory_wrappers.h"
#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/fx_string_wrappers.h"
#include "core/fxcrt/retain_ptr.h"
#include "third_party/abseil-cpp/absl/types/variant.h"

class CPDF_Stream final : public CPDF_Object {
 public:
  static constexpr int kFileBufSize = 512;

  CONSTRUCT_VIA_MAKE_RETAIN;

  // CPDF_Object:
  Type GetType() const override;
  RetainPtr<CPDF_Object> Clone() const override;
  const CPDF_Dictionary* GetDict() const override;
  WideString GetUnicodeText() const override;
  bool IsStream() const override;
  CPDF_Stream* AsStream() override;
  const CPDF_Stream* AsStream() const override;
  bool WriteTo(IFX_ArchiveStream* archive,
               const CPDF_Encryptor* encryptor) const override;

  size_t GetRawSize() const;
  // Will be null in case when stream is not memory based.
  // Use CPDF_StreamAcc to data access in all cases.
  uint8_t* GetInMemoryRawData() const;

  // Copies span or stream into internally-owned buffer.
  void SetData(pdfium::span<const uint8_t> pData);
  void SetDataFromStringstream(fxcrt::ostringstream* stream);

  // TODO(crbug.com/pdfium/1872): Replace with vector version.
  void TakeData(std::unique_ptr<uint8_t, FxFreeDeleter> pData, size_t size);

  // Set data and remove "Filter" and "DecodeParms" fields from stream
  // dictionary. Copies span or stream into internally-owned buffer.
  void SetDataAndRemoveFilter(pdfium::span<const uint8_t> pData);
  void SetDataFromStringstreamAndRemoveFilter(fxcrt::ostringstream* stream);

  void InitStream(pdfium::span<const uint8_t> pData,
                  RetainPtr<CPDF_Dictionary> pDict);
  void InitStreamFromFile(RetainPtr<IFX_SeekableReadStream> pFile,
                          RetainPtr<CPDF_Dictionary> pDict);

  bool ReadRawData(FX_FILESIZE offset, uint8_t* pBuf, size_t buf_size) const;

  bool IsUninitialized() const { return m_Data.index() == 0; }
  bool IsFileBased() const { return m_Data.index() == 1; }
  bool IsMemoryBased() const { return m_Data.index() == 2; }
  bool HasFilter() const;

 private:
  struct FileStream {
    FileStream(RetainPtr<IFX_SeekableReadStream> file, size_t size);
    ~FileStream();

    RetainPtr<IFX_SeekableReadStream> file;
    size_t size = 0;
  };

  struct MemoryStream {
    MemoryStream(std::unique_ptr<uint8_t, FxFreeDeleter> buffer, size_t size);
    ~MemoryStream();

    std::unique_ptr<uint8_t, FxFreeDeleter> buffer;
    size_t size = 0;
  };

  CPDF_Stream();
  CPDF_Stream(pdfium::span<const uint8_t> pData,
              RetainPtr<CPDF_Dictionary> pDict);
  CPDF_Stream(std::vector<uint8_t, FxAllocAllocator<uint8_t>> pData,
              RetainPtr<CPDF_Dictionary> pDict);
  // TODO(crbug.com/pdfium/1872): Replace with vector version above.
  CPDF_Stream(std::unique_ptr<uint8_t, FxFreeDeleter> pData,
              size_t size,
              RetainPtr<CPDF_Dictionary> pDict);
  ~CPDF_Stream() override;

  RetainPtr<CPDF_Object> CloneNonCyclic(
      bool bDirect,
      std::set<const CPDF_Object*>* pVisited) const override;

  absl::variant<absl::monostate, FileStream, MemoryStream> m_Data;
  RetainPtr<CPDF_Dictionary> m_pDict;
};

inline CPDF_Stream* ToStream(CPDF_Object* obj) {
  return obj ? obj->AsStream() : nullptr;
}

inline const CPDF_Stream* ToStream(const CPDF_Object* obj) {
  return obj ? obj->AsStream() : nullptr;
}

inline RetainPtr<CPDF_Stream> ToStream(RetainPtr<CPDF_Object> obj) {
  return RetainPtr<CPDF_Stream>(ToStream(obj.Get()));
}

#endif  // CORE_FPDFAPI_PARSER_CPDF_STREAM_H_
