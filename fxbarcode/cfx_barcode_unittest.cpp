// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxbarcode/cfx_barcode.h"

#include <memory>
#include <string>
#include <utility>

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxge/cfx_defaultrenderdevice.h"
#include "core/fxge/cfx_renderdevice.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/utils/bitmap_saver.h"
#include "testing/utils/hash.h"

class BarcodeTest : public testing::Test {
 public:
  void SetUp() override {
    BC_Library_Init();

    auto device = std::make_unique<CFX_DefaultRenderDevice>();
    auto bitmap = pdfium::MakeRetain<CFX_DIBitmap>();
    if (bitmap->Create(640, 480, FXDIB_Format::kRgb32))
      bitmap_ = bitmap;
    ASSERT_TRUE(bitmap_);
    ASSERT_TRUE(device->Attach(bitmap_, false, nullptr, false));
    device_ = std::move(device);
  }

  void TearDown() override {
    bitmap_.Reset();
    device_.reset();
    barcode_.reset();
    BC_Library_Destroy();
  }

  CFX_Barcode* barcode() const { return barcode_.get(); }

  void Create(BC_TYPE type) {
    barcode_ = CFX_Barcode::Create(type);
    barcode_->SetHeight(298);
    barcode_->SetWidth(418);
  }

  bool RenderDevice() { return barcode_->RenderDevice(device_.get(), matrix_); }

  std::string BitmapChecksum() {
    return GenerateMD5Base16(bitmap_->GetBuffer(),
                             bitmap_->GetPitch() * bitmap_->GetHeight());
  }

  // Manually insert calls to this as needed for debugging.
  void SaveBitmap(const std::string& filename) {
    BitmapSaver::WriteBitmapToPng(bitmap_.Get(), filename);
  }

 protected:
  CFX_Matrix matrix_;
  std::unique_ptr<CFX_Barcode> barcode_;
  std::unique_ptr<CFX_RenderDevice> device_;
  RetainPtr<CFX_DIBitmap> bitmap_;
};

TEST_F(BarcodeTest, Code39) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCode39);
  EXPECT_TRUE(barcode()->Encode(L"CLAMS"));
  RenderDevice();
  EXPECT_EQ("cd4cd3f36da38ff58d9f621827018903", BitmapChecksum());
}

TEST_F(BarcodeTest, CodaBar) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCodabar);
  EXPECT_TRUE(barcode()->Encode(L"$123-456"));
  RenderDevice();
  EXPECT_EQ("5fad4fc19f099001a0fe83c89430c977", BitmapChecksum());
}

TEST_F(BarcodeTest, CodaBarLetters) {
  Create(BC_TYPE::kCodabar);
  EXPECT_FALSE(barcode()->Encode(L"clams"));
}

TEST_F(BarcodeTest, Code128) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCode128);
  EXPECT_TRUE(barcode()->Encode(L"Clams"));
  RenderDevice();
  EXPECT_EQ("6351f0f6e997050e4658bbb4777aef74", BitmapChecksum());
}

TEST_F(BarcodeTest, Code128B) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCode128B);
  EXPECT_TRUE(barcode()->Encode(L"Clams"));
  RenderDevice();
  EXPECT_EQ("6351f0f6e997050e4658bbb4777aef74", BitmapChecksum());
}

TEST_F(BarcodeTest, Code128C) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCode128C);
  EXPECT_TRUE(barcode()->Encode(L"123456"));
  RenderDevice();
  EXPECT_EQ("fba730a807ba6363f9bd2bc7f8c56d1f", BitmapChecksum());
}

TEST_F(BarcodeTest, Code128CLetters) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kCode128C);
  EXPECT_TRUE(barcode()->Encode(L"clams"));
  RenderDevice();
  EXPECT_EQ("6284ec8503d5a948c9518108da33cdd3", BitmapChecksum());
}

TEST_F(BarcodeTest, Ean8) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kEAN8);
  EXPECT_TRUE(barcode()->Encode(L"123456"));
  RenderDevice();
  EXPECT_EQ("aff88491ac46ca6217d780d185300cde", BitmapChecksum());
}

TEST_F(BarcodeTest, Ean8Letters) {
  Create(BC_TYPE::kEAN8);
  EXPECT_FALSE(barcode()->Encode(L"clams"));
}

TEST_F(BarcodeTest, UPCA) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kUPCA);
  EXPECT_TRUE(barcode()->Encode(L"123456"));
  RenderDevice();
  EXPECT_EQ("fe26a5714cff7ffe3f9b02183efc435b", BitmapChecksum());
}

TEST_F(BarcodeTest, UPCALetters) {
  Create(BC_TYPE::kUPCA);
  EXPECT_FALSE(barcode()->Encode(L"clams"));
}

TEST_F(BarcodeTest, Ean13) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kEAN13);
  EXPECT_TRUE(barcode()->Encode(L"123456"));
  RenderDevice();
  EXPECT_EQ("72d2190b98d635c32834bf67552e561e", BitmapChecksum());
}

TEST_F(BarcodeTest, Ean13Letters) {
  Create(BC_TYPE::kEAN13);
  EXPECT_FALSE(barcode()->Encode(L"clams"));
}

TEST_F(BarcodeTest, Pdf417) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kPDF417);
  EXPECT_TRUE(barcode()->Encode(L"clams"));
  RenderDevice();
  EXPECT_EQ("191e35d11613901b7d5d51033689aa89", BitmapChecksum());
}

TEST_F(BarcodeTest, DataMatrix) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kDataMatrix);
  EXPECT_TRUE(barcode()->Encode(L"clams"));
  RenderDevice();
  EXPECT_EQ("5e5cd9a680b86fcd4ffd53ed36e3c980", BitmapChecksum());
}

TEST_F(BarcodeTest, QrCode) {
  // TODO(https://crbug.com/pdfium/738)  Update for Skia.
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;

  Create(BC_TYPE::kQRCode);
  EXPECT_TRUE(barcode()->Encode(L"clams"));
  RenderDevice();
  EXPECT_EQ("4751c6e0f67749fabe24f787128decee", BitmapChecksum());
}
