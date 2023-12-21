// Copyright 2018 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_TABLE_H_
#define CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_TABLE_H_

#include <stdint.h>

#include <map>
#include <memory>

#include "core/fxcrt/fx_types.h"
#include "core/fxcrt/retain_ptr.h"
#include "third_party/abseil-cpp/absl/types/variant.h"

class CPDF_Dictionary;

class CPDF_CrossRefTable {
 public:
  struct ObjectInfo {
    struct Free {};
    struct Normal {
      FX_FILESIZE pos = 0;
    };
    struct Compressed {
      uint32_t obj_num = 0;
      uint32_t obj_index = 0;
    };
    struct Null {};

    bool IsNull() const { return absl::holds_alternative<Null>(vary); }
    bool IsFree() const { return absl::holds_alternative<Free>(vary); }
    bool IsNormal() const { return absl::holds_alternative<Normal>(vary); }
    bool IsCompressed() const {
      return absl::holds_alternative<Compressed>(vary);
    }

    uint16_t gennum = 0;
    bool is_object_stream_flag = false;
    absl::variant<Free, Normal, Compressed, Null> vary;
  };

  // Merge cross reference tables.  Apply top on current.
  static std::unique_ptr<CPDF_CrossRefTable> MergeUp(
      std::unique_ptr<CPDF_CrossRefTable> current,
      std::unique_ptr<CPDF_CrossRefTable> top);

  CPDF_CrossRefTable();
  CPDF_CrossRefTable(RetainPtr<CPDF_Dictionary> trailer,
                     uint32_t trailer_object_number);
  ~CPDF_CrossRefTable();

  void AddCompressed(uint32_t obj_num,
                     uint32_t archive_obj_num,
                     uint32_t archive_obj_index);
  void AddNormal(uint32_t obj_num,
                 uint16_t gen_num,
                 bool is_object_stream,
                 FX_FILESIZE pos);
  void SetFree(uint32_t obj_num);

  void SetTrailer(RetainPtr<CPDF_Dictionary> trailer,
                  uint32_t trailer_object_number);
  uint32_t trailer_object_number() const { return trailer_object_number_; }
  const CPDF_Dictionary* trailer() const { return trailer_.Get(); }
  CPDF_Dictionary* GetMutableTrailerForTesting() { return trailer_.Get(); }

  const ObjectInfo* GetObjectInfo(uint32_t obj_num) const;

  const std::map<uint32_t, ObjectInfo>& objects_info() const {
    return objects_info_;
  }

  void Update(std::unique_ptr<CPDF_CrossRefTable> new_cross_ref);

  // Objects with object number >= `size` will be removed.
  void SetObjectMapSize(uint32_t size);

 private:
  void UpdateInfo(std::map<uint32_t, ObjectInfo> new_objects_info);
  void UpdateTrailer(RetainPtr<CPDF_Dictionary> new_trailer);

  RetainPtr<CPDF_Dictionary> trailer_;
  // `trailer_` can be the dictionary part of a XRef stream object. Since it is
  // inline, it has no object number. Store the stream's object number, or 0 if
  // there is none.
  uint32_t trailer_object_number_ = 0;
  std::map<uint32_t, ObjectInfo> objects_info_;
};

#endif  // CORE_FPDFAPI_PARSER_CPDF_CROSS_REF_TABLE_H_
