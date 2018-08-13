// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include <algorithm>

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
    CFX_Matrix matriScale(static_cast<float>(m_Width) / m_outputWidth, 0.0, 0.0,
                          static_cast<float>(m_Height) / m_outputHeight, 0.0,
                          0.0);
    matriScale.Concat(*matrix);
    matri = matriScale;
  }

  CFX_GraphStateData data;
  for (int32_t x = 0; x < m_inputWidth; x++) {
    for (int32_t y = 0; y < m_inputHeight; y++) {
      CFX_PathData rect;
      rect.AppendRect((float)leftPos + x * m_multiX,
                      (float)topPos + y * m_multiY,
                      (float)leftPos + (x + 1) * m_multiX,
                      (float)topPos + (y + 1) * m_multiY);
      if (m_output->Get(x, y))
        device->DrawPath(&rect, &matri, &data, m_barColor, 0, FXFILL_WINDING);
    }
  }
}

int32_t CBC_TwoDimWriter::GetErrorCorrectionLevel() const {
  return m_iCorrectLevel;
}

bool CBC_TwoDimWriter::RenderResult(uint8_t* code,
                                    int32_t codeWidth,
                                    int32_t codeHeight) {
  m_inputWidth = codeWidth;
  m_inputHeight = codeHeight;
  int32_t tempWidth = m_inputWidth + 2;
  int32_t tempHeight = m_inputHeight + 2;
  float moduleHSize = std::min(m_ModuleWidth, m_ModuleHeight);
  moduleHSize = std::min(moduleHSize, 8.0f);
  moduleHSize = std::max(moduleHSize, 1.0f);
  pdfium::base::CheckedNumeric<int32_t> scaledWidth = tempWidth;
  pdfium::base::CheckedNumeric<int32_t> scaledHeight = tempHeight;
  scaledWidth *= moduleHSize;
  scaledHeight *= moduleHSize;
  m_outputWidth = scaledWidth.ValueOrDie();
  m_outputHeight = scaledHeight.ValueOrDie();

  if (m_bFixedSize) {
    if (m_Width < m_outputWidth || m_Height < m_outputHeight) {
      return false;
    }
  } else {
    if (m_Width > m_outputWidth || m_Height > m_outputHeight) {
      m_outputWidth = (int32_t)(m_outputWidth *
                                ceil((float)m_Width / (float)m_outputWidth));
      m_outputHeight = (int32_t)(m_outputHeight *
                                 ceil((float)m_Height / (float)m_outputHeight));
    }
  }
  m_multiX = (int32_t)ceil((float)m_outputWidth / (float)tempWidth);
  m_multiY = (int32_t)ceil((float)m_outputHeight / (float)tempHeight);
  if (m_bFixedSize) {
    m_multiX = std::min(m_multiX, m_multiY);
    m_multiY = m_multiX;
  }

  m_output = pdfium::MakeUnique<CBC_CommonBitMatrix>();
  m_output->Init(m_inputWidth, m_inputHeight);
  for (int32_t y = 0; y < m_inputHeight; ++y) {
    for (int32_t x = 0; x < m_inputWidth; ++x) {
      if (code[x + y * m_inputWidth] == 1 && !m_output->Set(x, y))
        return false;
    }
  }
  return true;
}
