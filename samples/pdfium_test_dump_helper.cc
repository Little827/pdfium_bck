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

void DumpStructureElementAttributes(FPDF_STRUCTELEMENT_ATTR attr, int indent) {
  int count = FPDF_StructElement_Attr_GetCount(attr);
  printf("%*s A[%d]:\n", indent, "", i);
  indent = indent + 2;
  for (int j = 0; j < count; j++) {
    char attr_name[kBufSize];
    memset(attr_name, 0, sizeof(attr_name));
    unsigned long attr_len = -1;
    if (!FPDF_StructElement_Attr_GetName(attr, j, attr_name, sizeof(attr_name),
                                         &attr_len)) {
      printf("%*s FPDF_StructElement_Attr_GetName failed for %d\n", indent, "",
             j);
      continue;
    }
    std::wstring attr_name_wstring =
        ConvertToWString(reinterpret_cast<unsigned short*>(attr_name), attr_len)
            .c_str();
    std::string name_str(attr_name, attr_len);
    const char* name = name_str.c_str();
    FPDF_OBJECT_TYPE type = FPDF_StructElement_Attr_GetType(attr, name);

    if (type == FPDF_OBJECT_BOOLEAN) {
      int value;
      if (!FPDF_StructElement_Attr_GetIntValue(attr, name, &value)) {
        printf("%*s %ls: Failed FPDF_StructElement_Attr_GetIntValue\n", indent,
               "", attr_name_wstring.c_str());
        continue;
      }
      printf("%*s %ls: %d\n", indent, "", attr_name_wstring.c_str(), value);
    } else if (type == FPDF_OBJECT_NUMBER) {
      float value;
      if (!FPDF_StructElement_Attr_GetNumberValue(attr, name, &value)) {
        printf("%*s %ls: Failed FPDF_StructElement_Attr_GetNumberValue\n",
               indent, "", attr_name_wstring.c_str());
        continue;
      }
      printf("%*s %ls: %f\n", indent, "", attr_name_wstring.c_str(), value);
    } else if (type == FPDF_OBJECT_STRING || type == FPDF_OBJECT_NAME) {
      char string_val[kBufSize];
      memset(string_val, 0, sizeof(string_val));
      if (!FPDF_StructElement_Attr_GetStringValue(attr, name, string_val,
                                                  sizeof(string_val), &len)) {
        printf("%*s %ls: Failed FPDF_StructElement_Attr_GetStringValue\n",
               indent, "", attr_name_wstring.c_str());
        continue;
      }
      printf(
          "%*s %ls: %ls\n", indent, "", attr_name_wstring.c_str(),
          ConvertToWString(reinterpret_cast<unsigned short*>(string_val), len)
              .c_str());
    } else if (type == FPDF_OBJECT_UNKNOWN) {
      printf("%*s %ls: FPDF_OBJECT_UNKNOWN\n", indent, "",
             attr_name_wstring.c_str());
    } else {
      printf("%*s %ls: NOT_YET_IMPLEMENTED: %d\n", indent, "",
             attr_name_wstring.c_str(), type);
    }
  }
}

}  // namespace

void DumpChildStructure(FPDF_STRUCTELEMENT child, int indent) {
  static const size_t kBufSize = 1024;
  unsigned short buf[kBufSize];
  unsigned long len = FPDF_StructElement_GetType(child, buf, kBufSize);
  if (len > 0)
    printf("%*s S: %ls\n", indent * 2, "", ConvertToWString(buf, len).c_str());

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetTitle(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Title: %ls\n", indent * 2, "",
           ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetAltText(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s AltText: %ls\n", indent * 2, "",
           ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetActualText(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s ActualText: %ls\n", indent * 2, "",
           ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetID(child, buf, kBufSize);
  if (len > 0)
    printf("%*s ID: %ls\n", indent * 2, "", ConvertToWString(buf, len).c_str());

  int mcid = FPDF_StructElement_GetMarkedContentID(child);
  if (mcid != -1)
    printf("%*s MCID: %d\n", indent * 2, "", mcid);

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetObjType(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Type: %ls\n", indent * 2, "",
           ConvertToWString(buf, len).c_str());
  }

  memset(buf, 0, sizeof(buf));
  len = FPDF_StructElement_GetLang(child, buf, kBufSize);
  if (len > 0) {
    printf("%*s Lang: %ls\n", indent * 2, "",
           ConvertToWString(buf, len).c_str());
  }

  int attr_count = FPDF_StructElement_GetAttributeCount(child);
  for (int i = 0; i < attr_count; i++) {
    FPDF_STRUCTELEMENT_ATTR child_attr =
        FPDF_StructElement_GetAttributeAtIndex(child, i);
    if (!child_attr)
      continue;
    DumpStructureElementAttributes(attr, indent * 2);
  }

  FPDF_STRUCTELEMENT parent = FPDF_StructElement_GetParent(child);
  if (parent) {
    memset(buf, 0, sizeof(buf));
    len = FPDF_StructElement_GetID(parent, buf, kBufSize);
    if (len > 0) {
      printf("%*s Parent ID: %ls\n", indent * 2, "",
             ConvertToWString(buf, len).c_str());
    }
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
