// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include <algorithm>
#include <ctime>
#include <iostream>

#include "core/fxge/cfx_graphstatedata.h"
#include "core/fxge/cfx_pathdata.h"
#include "core/fxge/cfx_renderdevice.h"
#include "fxbarcode/BC_TwoDimWriter.h"
#include "fxbarcode/BC_Writer.h"
#include "fxbarcode/common/BC_CommonBitMatrix.h"
#include "third_party/base/numerics/safe_math.h"
#include "third_party/base/ptr_util.h"

CBC_TwoDimWriter::CBC_TwoDimWriter() : m_iCorrectLevel(1), m_bFixedSize(true) {}

CBC_TwoDimWriter::~CBC_TwoDimWriter() {}

void CBC_TwoDimWriter::RenderDeviceResult(CFX_RenderDevice* device,
                                          const CFX_Matrix* matrix) {
  std::cerr << "CBC_TwoDimWriter::RenderDeviceResult m_output->GetWidth()="
            << m_output->GetWidth()
            << ", m_output->GetHeight()=" << m_output->GetHeight() << std::endl;
  clock_t begin = clock();
  CFX_GraphStateData stateData;
  CFX_PathData path;
  path.AppendRect(0, 0, (float)m_Width, (float)m_Height);
  device->DrawPath(&path, matrix, &stateData, m_backgroundColor,
                   m_backgroundColor, FXFILL_ALTERNATE);
  int32_t leftPos = 0;
  int32_t topPos = 0;
  if (m_bFixedSize) {
    leftPos = (m_Width - m_outputWidth) / 2;
    topPos = (m_Height - m_outputHeight) / 2;
  }
  CFX_Matrix matri = *matrix;
  if (m_Width < m_outputWidth && m_Height < m_outputHeight) {
    CFX_Matrix matriScale((float)m_Width / (float)m_outputWidth, 0.0, 0.0,
                          (float)m_Height / (float)m_outputHeight, 0.0, 0.0);
    matriScale.Concat(*matrix);
    matri = matriScale;
  }
  CFX_GraphStateData data;
  for (int32_t x = 0; x < m_inputWidth; ++x) {
    for (int32_t y = 0; y < m_inputHeight; ++y) {
      CFX_PathData rect;
      rect.AppendRect((float)leftPos + x * m_multiX,
                      (float)topPos + y * m_multiY,
                      (float)(leftPos + (x + 1) * m_multiX),
                      (float)(topPos + (y + 1) * m_multiY));
      if (m_output->Get(x, y)) {
        device->DrawPath(&rect, &matri, &data, m_barColor, 0, FXFILL_WINDING);
      }
    }
  }
  std::cerr << "CBC_TwoDimWriter::RenderDeviceResult time="
            << (float(clock() - begin) / CLOCKS_PER_SEC) << std::endl;
}

int32_t CBC_TwoDimWriter::GetErrorCorrectionLevel() const {
  return m_iCorrectLevel;
}

bool CBC_TwoDimWriter::RenderResult(uint8_t* code,
                                    int32_t codeWidth,
                                    int32_t codeHeight) {
  int32_t inputWidth = codeWidth;
  int32_t inputHeight = codeHeight;
  std::cerr << "CBC_TwoDimWriter::RenderResult input " << inputWidth << ", "
            << inputHeight << std::endl;
  int32_t tempWidth = inputWidth + 2;
  int32_t tempHeight = inputHeight + 2;
  std::cerr << "CBC_TwoDimWriter::RenderResult temp " << tempWidth << ", "
            << tempHeight << std::endl;
  float moduleHSize = std::min(m_ModuleWidth, m_ModuleHeight);
  std::cerr << "CBC_TwoDimWriter::RenderResult moduleHSize " << moduleHSize
            << std::endl;
  moduleHSize = std::min(moduleHSize, 8.0f);
  moduleHSize = std::max(moduleHSize, 1.0f);
  std::cerr << "CBC_TwoDimWriter::RenderResult moduleHSize bounded "
            << moduleHSize << std::endl;
  pdfium::base::CheckedNumeric<int32_t> scaledWidth = tempWidth;
  pdfium::base::CheckedNumeric<int32_t> scaledHeight = tempHeight;
  scaledWidth *= moduleHSize;
  scaledHeight *= moduleHSize;

  int32_t outputWidth = scaledWidth.ValueOrDie();
  int32_t outputHeight = scaledHeight.ValueOrDie();
  std::cerr << "CBC_TwoDimWriter::RenderResult output " << outputWidth << ", "
            << outputHeight << std::endl;
  std::cerr << "CBC_TwoDimWriter::RenderResult m_bFixedSize " << m_bFixedSize
            << std::endl;
  if (m_bFixedSize) {
    if (m_Width < outputWidth || m_Height < outputHeight) {
      return false;
    }
  } else {
    if (m_Width > outputWidth || m_Height > outputHeight) {
      std::cerr << "CBC_TwoDimWriter::RenderResult override m_Width m_Height "
                << m_Width << ", " << m_Height << std::endl;
      std::cerr << "CBC_TwoDimWriter::RenderResult override output was "
                << outputWidth << ", " << outputHeight << std::endl;
      outputWidth =
          (int32_t)(outputWidth * ceil((float)m_Width / (float)outputWidth));
      outputHeight =
          (int32_t)(outputHeight * ceil((float)m_Height / (float)outputHeight));
      std::cerr << "CBC_TwoDimWriter::RenderResult override output to "
                << outputWidth << ", " << outputHeight << std::endl;
    }
  }
  int32_t multiX = (int32_t)ceil((float)outputWidth / (float)tempWidth);
  int32_t multiY = (int32_t)ceil((float)outputHeight / (float)tempHeight);
  if (m_bFixedSize) {
    multiX = std::min(multiX, multiY);
    multiY = multiX;
  }
  std::cerr << "CBC_TwoDimWriter::RenderResult multi " << multiX << ", "
            << multiY << std::endl;

  m_leftPadding = std::max((outputWidth - (inputWidth * multiX)) / 2, 0);
  m_topPadding = std::max((outputHeight - (inputHeight * multiY)) / 2, 0);
  std::cerr << "CBC_TwoDimWriter::RenderResult leftPadding " << m_leftPadding
            << ", topPadding " << m_topPadding << std::endl;

  m_inputWidth = inputWidth;
  m_inputHeight = inputHeight;
  m_outputWidth = outputWidth;
  m_outputHeight = outputHeight;
  m_multiX = multiX;
  m_multiY = multiY;

  m_output = pdfium::MakeUnique<CBC_CommonBitMatrix>();
  m_output->Init(m_inputWidth, m_inputHeight);
  for (int32_t y = 0; y < m_inputHeight; ++y) {
    for (int32_t x = 0; x < m_inputWidth; ++x) {
      if (code[x + y * m_inputWidth] == 1 && !m_output->SetPiece(x, y)) {
        return false;
      }
    }
  }
  return true;
}
