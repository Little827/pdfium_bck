// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcodec/basic/basicmodule.h"
#include "core/fxcodec/fax/faxmodule.h"
#include "core/fxcodec/flate/flatemodule.h"
#include "core/fxcodec/jpeg/jpegmodule.h"
#include "core/fxcrt/fx_coordinates.h"
#include "core/fxge/cfx_pathdata.h"
#include "core/fxge/cfx_windowsrenderdevice.h"
#include "core/fxge/win32/win32_int.h"
#include "testing/gtest/include/gtest/gtest.h"

#include <windows.h>

namespace {

constexpr EncoderIface kEncoderIface = {
    BasicModule::A85Encode, FaxModule::FaxEncode, FlateModule::Encode,
    JpegModule::JpegEncode, BasicModule::RunLengthEncode};

constexpr CFX_Matrix kIdentityMatrix;

void SimpleClipTriangle(CFX_WindowsRenderDevice* driver) {
  CFX_PathData path_data;
  CFX_PointF p1(0.0f, 0.0f);
  CFX_PointF p2(0.0f, 100.0f);
  CFX_PointF p3(100.0f, 100.0f);

  path_data.AppendLine(p1, p2);
  path_data.AppendLine(p2, p3);
  path_data.AppendLine(p3, p1);
  path_data.ClosePath();
  EXPECT_TRUE(
      driver->SetClip_PathFill(&path_data, &kIdentityMatrix, FXFILL_WINDING));
}

void SimpleClipRect(CFX_WindowsRenderDevice* driver) {
  CFX_PathData path_data;

  path_data.AppendRect(0.0f, 100.0f, 200.0f, 0.0f);
  path_data.ClosePath();
  EXPECT_TRUE(
      driver->SetClip_PathFill(&path_data, &kIdentityMatrix, FXFILL_WINDING));
}

void GargantuanClipRect(CFX_WindowsRenderDevice* driver) {
  CFX_PathData path_data;

  path_data.AppendRect(-257698020.0f, -257697252.0f, 257698044.0f,
                       257698812.0f);
  path_data.ClosePath();
  // These coordinates for a clip path are valid, just very large. Using these
  // for a clip path should allow IntersectClipRect() to return success;
  // however they do not because the GDI API IntersectClipRect() errors out and
  // affect subsequent imaging.  crbug.com/1019026
  EXPECT_FALSE(
      driver->SetClip_PathFill(&path_data, &kIdentityMatrix, FXFILL_WINDING));
}

void Harness(void (*Test)(CFX_WindowsRenderDevice* driver)) {
  // Get a device context with Windows GDI.
  HDC hDC = CreateCompatibleDC(nullptr);
  EXPECT_NE(hDC, nullptr);
  CFX_GEModule::Create(nullptr);
  CFX_WindowsRenderDevice driver(hDC, &kEncoderIface);
  driver.SaveState();
  (*Test)(&driver);
  driver.RestoreState(false);
  CFX_GEModule::Destroy();
  DeleteDC(hDC);
}

}  // namespace

TEST(FXGEWin32Device, SetClip_PathFill) {
  Harness(&SimpleClipTriangle);
  Harness(&SimpleClipRect);
  Harness(&GargantuanClipRect);
}
