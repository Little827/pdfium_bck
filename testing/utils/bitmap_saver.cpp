// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/utils/bitmap_saver.h"

#include <fstream>
#include <vector>

#include "core/fxcrt/fx_safe_types.h"
#include "testing/image_diff/image_diff_png.h"
#include "third_party/base/check.h"

namespace {

std::vector<uint8_t> BitmapToPng(FPDF_BITMAP bitmap) {
  const int stride = FPDFBitmap_GetStride(bitmap);
  const int width = FPDFBitmap_GetWidth(bitmap);
  const int height = FPDFBitmap_GetHeight(bitmap);
  CHECK(stride >= 0);
  CHECK(width >= 0);
  CHECK(height >= 0);
  FX_SAFE_FILESIZE size = stride;
  size *= height;
  auto input = pdfium::make_span(
      static_cast<const uint8_t*>(FPDFBitmap_GetBuffer(bitmap)),
      pdfium::base::ValueOrDieForType<size_t>(size));

  std::vector<uint8_t> png;
  int format = FPDFBitmap_GetFormat(bitmap);
  if (format == FPDFBitmap_Gray) {
    png = image_diff_png::EncodeGrayPNG(input, width, height, stride);
  } else if (format == FPDFBitmap_BGR) {
    png = image_diff_png::EncodeBGRPNG(input, width, height, stride);
  } else {
    png = image_diff_png::EncodeBGRAPNG(input, width, height, stride,
                                        /*discard_transparency=*/false);
  }
  return png;
}

}  // namespace

// static
void BitmapSaver::PrintBitmapAsPngString(FPDF_BITMAP bitmap) {
  std::vector<uint8_t> png = BitmapToPng(bitmap);
  int i = 0;
  for (uint8_t d : png) {
    printf("%02x", d);
    if (++i % 40 == 0)
      printf("\n");
  }
  printf("\n");
}

// static
void BitmapSaver::WriteBitmapToPng(FPDF_BITMAP bitmap,
                                   const std::string& filename) {
  std::vector<uint8_t> png = BitmapToPng(bitmap);
  DCHECK(!png.empty());
  DCHECK(filename.size() < 256u);

  std::ofstream png_file;
  png_file.open(filename, std::ios_base::out | std::ios_base::binary);
  png_file.write(reinterpret_cast<char*>(&png.front()), png.size());
  DCHECK(png_file.good());
  png_file.close();
}

// static
void BitmapSaver::WriteBitmapToPng(CFX_DIBitmap* bitmap,
                                   const std::string& filename) {
  WriteBitmapToPng(reinterpret_cast<FPDF_BITMAP>(bitmap), filename);
}
