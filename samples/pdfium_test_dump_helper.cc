// Copyright 2018 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "samples/pdfium_test_dump_helper.h"

#include <string.h>

#include <algorithm>
#include <functional>
#include <string>
#include <utility>

#include "public/cpp/fpdf_scopers.h"
#include "public/fpdf_transformpage.h"
#include "testing/fx_string_testhelpers.h"

using GetBoxInfoFunc =
    std::function<bool(FPDF_PAGE, float*, float*, float*, float*)>;

namespace {

std::wstring ConvertToWString(const unsigned short* buf,
                              unsigned long buf_size) {
  std::wstring result;
  result.reserve(buf_size);
  std::copy(buf, buf + buf_size, std::back_inserter(result));
  return result;
}

//std::string ConvertToString(const std::wstring& wide) {
//  return std::string(wide.begin(), wide.end());
//}

void DumpBoxInfo(GetBoxInfoFunc func,
                 const char* box_type,
                 FPDF_PAGE page,
                 int page_idx) {
  FS_RECTF rect;
  bool ret = func(page, &rect.left, &rect.bottom, &rect.right, &rect.top);
  if (!ret) {
    printf("Page %d: No %s.\n", page_idx, box_type);
    return;
  }
  printf("Page %d: %s: %0.2f %0.2f %0.2f %0.2f\n", page_idx, box_type,
         rect.left, rect.bottom, rect.right, rect.top);
}

}  // namespace

void DumpChildStructure(FPDF_STRUCTELEMENT child, int indent) {
  static const size_t kBufSize = 1024;
  unsigned short buf[kBufSize];
  unsigned long len = FPDF_StructElement_GetType(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s S: %ls\n", indent * 2, "", ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetTitle(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Title: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetAltText(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s AltText: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetActualText(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s ActualText: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetID(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s ID: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  int mcid = FPDF_StructElement_GetMarkedContentID(child);
  if (mcid != -1) {
    printf("%*s MCID: %d\n", indent*2, "", mcid);
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetObjType(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Type: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetLang(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Lang: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
  }

  FPDF_STRUCTELEMENT parent = FPDF_StructElement_GetParent(child);
  if (!parent) {
    memset(buf, 0, sizeof(buf));
    len = FPDF_StructElement_GetID(parent, buf, kBufSize);
    if (len > 0) {
      printf("%*s Parent ID: %ls\n", indent*2, "", ConvertToWString(buf, len).c_str());
    } else {
      printf("%*s No Parent ID\n", indent*2, "");
    }
  } else {
    printf("%*s No Parent\n", indent*2, "");
  }

  for (int i = 0; i < FPDF_StructElement_CountChildren(child); ++i) {
    FPDF_STRUCTELEMENT sub_child = FPDF_StructElement_GetChildAtIndex(child, i);
    // If the child is not an Element then this will return null. This can
    // happen if the element is things like an object reference or a stream.
    if (!sub_child)
      continue;

    DumpChildStructure(sub_child, indent + 1);
  }
}

void DumpMarkedContentInfo(FPDF_PAGE page, int page_idx) {
  FPDF_TEXTPAGE text_page = FPDFText_LoadPage(page);
  int object_count = FPDFPage_CountObjects(page);
  printf("Page object count: %d\n", object_count);
  static const size_t kBufSize = 1024;
  char buf[kBufSize];
 
  for (int i=0; i < object_count; i++) {
    FPDF_PAGEOBJECT page_object = FPDFPage_GetObject(page, i);
    unsigned long text_size = FPDFTextObj_GetText(page_object, text_page, nullptr, 0);
    std::vector<unsigned short> text(text_size);
    if (FPDFTextObj_GetText(page_object, text_page, text.data(), text_size) < 0) {
      printf("%*s Failed FPDFTextObj_GetText\n", 2, "");
      continue;
    }
    printf("%*s text: %ls\n", 2, "", ConvertToWString(text.data(), text_size).c_str());

    int mark_count = FPDFPageObj_CountMarks(page_object);
    printf("%*s mark_count: %d\n", 2, "", mark_count);
    for (int j=0; j < mark_count; j++)  {
      FPDF_PAGEOBJECTMARK mark = FPDFPageObj_GetMark(page_object, j);
      memset(buf, '\0', sizeof(buf));
      unsigned long len = -1;
      if(!FPDFPageObjMark_GetName(mark, buf, sizeof(buf), &len)) {
        printf("%*s Failed FPDFPageObjMark_GetName\n", 2, "");
        continue;
      }
      printf("%*s name: %ls\n", 4, "", ConvertToWString(reinterpret_cast<unsigned short*>(buf), len).c_str());
      int param_count = FPDFPageObjMark_CountParams(mark);
      printf("%*s param_count: %d\n", 4, "", param_count);

      for (int k=0; k < param_count; k++) {
        memset(buf, '\0', sizeof(buf));
        if(!FPDFPageObjMark_GetParamKey(mark, k, buf, sizeof(buf), &len)) {
          printf("%*s failed FPDFPageObjMark_GetParamKey\n", 6, "");
          continue;
        }
        printf("%*s param_key: %ls\n", 6, "", ConvertToWString(reinterpret_cast<unsigned short*>(buf), len).c_str());
        std::string key_str(buf, len);
        const char* key = key_str.c_str();
        FPDF_OBJECT_TYPE value_type = FPDFPageObjMark_GetParamValueType(mark, key);
        if (value_type == FPDF_OBJECT_BOOLEAN) {
          printf("%*s bool_type\n", 6, "");
        } else if (value_type == FPDF_OBJECT_NUMBER) {
          int value;
          if(!FPDFPageObjMark_GetParamIntValue(mark, key, &value)) {
            printf("%*s Failed FPDFPageObjMark_GetParamIntValue\n", 6, "");
            continue;
          }
          printf("%*s int_value: %d\n", 6, "", value);
        } else if (value_type == FPDF_OBJECT_STRING) {
          char string_val[kBufSize];
          memset(string_val, '\0', sizeof(string_val));
          if (!FPDFPageObjMark_GetParamStringValue(mark, key, string_val, sizeof(string_val), &len)) {
            printf("%*s failed FPDFPageObjMark_GetParamStringValue\n", 6, "");
            continue;
          }
          printf("%*s string_value: %ls\n", 6, "", ConvertToWString(reinterpret_cast<unsigned short*>(string_val), len).c_str());
        } else if (value_type == FPDF_OBJECT_UNKNOWN) {
          printf("%*s unknown type\n", 6, "");
        } else {
          printf("%*s value is other type: %d\n", 6, "", value_type);
        }
      }
    }
  }

}

void DumpPageInfo(FPDF_PAGE page, int page_idx) {
  DumpBoxInfo(&FPDFPage_GetMediaBox, "MediaBox", page, page_idx);
  DumpBoxInfo(&FPDFPage_GetCropBox, "CropBox", page, page_idx);
  DumpBoxInfo(&FPDFPage_GetBleedBox, "BleedBox", page, page_idx);
  DumpBoxInfo(&FPDFPage_GetTrimBox, "TrimBox", page, page_idx);
  DumpBoxInfo(&FPDFPage_GetArtBox, "ArtBox", page, page_idx);
}

void DumpPageStructure(FPDF_PAGE page, int page_idx) {
  ScopedFPDFStructTree tree(FPDF_StructTree_GetForPage(page));
  if (!tree) {
    fprintf(stderr, "Failed to load struct tree for page %d\n", page_idx);
    return;
  }

  printf("Structure Tree for Page %d\n", page_idx);
  for (int i = 0; i < FPDF_StructTree_CountChildren(tree.get()); ++i) {
    FPDF_STRUCTELEMENT child = FPDF_StructTree_GetChildAtIndex(tree.get(), i);
    if (!child) {
      fprintf(stderr, "Failed to load child %d for page %d\n", i, page_idx);
      continue;
    }
    DumpChildStructure(child, 0);
  }
  printf("\n\n");
}

void DumpMetaData(FPDF_DOCUMENT doc) {
  static constexpr const char* kMetaTags[] = {
      "Title",   "Author",   "Subject",      "Keywords",
      "Creator", "Producer", "CreationDate", "ModDate"};
  for (const char* meta_tag : kMetaTags) {
    char meta_buffer[4096];
    unsigned long len =
        FPDF_GetMetaText(doc, meta_tag, meta_buffer, sizeof(meta_buffer));
    if (!len)
      continue;

    auto* meta_string = reinterpret_cast<unsigned short*>(meta_buffer);
    printf("%-12s = %ls (%lu bytes)\n", meta_tag,
           GetPlatformWString(meta_string).c_str(), len);
  }
}
