// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcodec/jbig2/JBig2_Image.h"

#include <limits.h>
#include <string.h>

#include <algorithm>
#include <memory>

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_safe_types.h"
#include "third_party/base/ptr_util.h"
#include "third_party/base/stl_util.h"

#define JBIG2_GETDWORD(buf)                  \
  ((static_cast<uint32_t>((buf)[0]) << 24) | \
   (static_cast<uint32_t>((buf)[1]) << 16) | \
   (static_cast<uint32_t>((buf)[2]) << 8) |  \
   (static_cast<uint32_t>((buf)[3]) << 0))

#define JBIG2_PUTDWORD(buf, val)                 \
  ((buf)[0] = static_cast<uint8_t>((val) >> 24), \
   (buf)[1] = static_cast<uint8_t>((val) >> 16), \
   (buf)[2] = static_cast<uint8_t>((val) >> 8),  \
   (buf)[3] = static_cast<uint8_t>((val) >> 0))

#define BIT_INDEX_TO_BYTE(x) ((x) >> 3)
#define BIT_INDEX_TO_ALIGNED_BYTE(x) (((x) >> 5) << 2)
#define IS_INTRAWORD(start, end) (((start) & ~31) == (((end)-1) & ~31))

namespace {

const int kMaxImagePixels = INT_MAX - 31;
const int kMaxImageBytes = kMaxImagePixels / 8;

struct OperatorOR {
  static inline uint32_t Eval(uint32_t arg1, uint32_t arg2) {
    return arg1 | arg2;
  }
};

struct OperatorAND {
  static inline uint32_t Eval(uint32_t arg1, uint32_t arg2) {
    return arg1 & arg2;
  }
};

struct OperatorXOR {
  static inline uint32_t Eval(uint32_t arg1, uint32_t arg2) {
    return arg1 ^ arg2;
  }
};

struct OperatorXNOR {
  static inline uint32_t Eval(uint32_t arg1, uint32_t arg2) {
    return ~(arg1 ^ arg2);
  }
};

struct OperatorReplace {
  static inline uint32_t Eval(uint32_t arg1, uint32_t arg2) { return arg1; }
};

struct AlignedSrc {
  static inline uint32_t Fetch(const uint8_t* lineSrc,
                               const CJBig2_Image::ComposeArgs& args) {
    return JBIG2_GETDWORD(lineSrc);
  }
};

struct IntraWordLeftSrc {
  static inline uint32_t Fetch(const uint8_t* lineSrc,
                               const CJBig2_Image::ComposeArgs& args) {
    return JBIG2_GETDWORD(lineSrc) << args.shift;
  }
};

struct IntraWordRightSrc {
  static inline uint32_t Fetch(const uint8_t* lineSrc,
                               const CJBig2_Image::ComposeArgs& args) {
    return JBIG2_GETDWORD(lineSrc) >> args.shift;
  }
};

struct MultiWordSrc {
  static inline uint32_t Fetch(const uint8_t* lineSrc,
                               const CJBig2_Image::ComposeArgs& args) {
    uint32_t shift2 = 32 - args.shift;
    return (JBIG2_GETDWORD(lineSrc) << args.shift) |
           (JBIG2_GETDWORD(lineSrc + 4) >> shift2);
  }
};

struct ConditionalWordSrc {
  static inline uint32_t Fetch(const uint8_t* lineSrc,
                               const CJBig2_Image::ComposeArgs& args) {
    uint32_t tmp = JBIG2_GETDWORD(lineSrc) << args.shift;
    if (lineSrc + 4 < args.lineSrcEnd) {
      uint32_t shift2 = 32 - args.shift;
      tmp |= JBIG2_GETDWORD(lineSrc + 4) >> shift2;
    }
    return tmp;
  }
};

template <class C, class F>
struct SingleWordDst {
  static inline bool Compose(const CJBig2_Image::ComposeArgs& args) {
    const uint8_t* lineSrc = args.lineSrc;
    uint8_t* lineDst = args.lineDst;
    for (int32_t yy = args.yd0; yy < args.yd1; yy++) {
      if (lineSrc >= args.lineSrcEnd)
        return false;
      uint32_t tmp1 = F::Fetch(lineSrc, args);
      uint32_t tmp2 = JBIG2_GETDWORD(lineDst);
      uint32_t tmp = (tmp2 & ~args.maskM) | (C::Eval(tmp1, tmp2) & args.maskM);
      JBIG2_PUTDWORD(lineDst, tmp);
      lineSrc += args.srcStride;
      lineDst += args.dstStride;
    }
    return true;
  }
};

template <class C, class F1, class F2, class F3>
struct MultiWordDst {
  static inline bool Compose(const CJBig2_Image::ComposeArgs& args) {
    const uint8_t* lineSrc = args.lineSrc;
    uint8_t* lineDst = args.lineDst;
    for (int32_t yy = args.yd0; yy < args.yd1; yy++) {
      if (lineSrc > args.lineSrcEnd)
        return false;
      const uint8_t* sp = lineSrc;
      uint8_t* dp = lineDst;
      if (args.d1 != 0) {
        uint32_t tmp1 = F1::Fetch(sp, args);
        uint32_t tmp2 = JBIG2_GETDWORD(dp);
        uint32_t tmp =
            (tmp2 & ~args.maskL) | (C::Eval(tmp1, tmp2) & args.maskL);
        JBIG2_PUTDWORD(dp, tmp);
        sp += 4;
        dp += 4;
      }
      for (int32_t xx = 0; xx < args.middleDwords; xx++) {
        uint32_t tmp1 = F2::Fetch(sp, args);
        uint32_t tmp2 = JBIG2_GETDWORD(dp);
        uint32_t tmp = C::Eval(tmp1, tmp2);
        JBIG2_PUTDWORD(dp, tmp);
        sp += 4;
        dp += 4;
      }
      if (args.d2 != 0) {
        uint32_t tmp1 = F3::Fetch(sp, args);
        uint32_t tmp2 = JBIG2_GETDWORD(dp);
        uint32_t tmp =
            (tmp2 & ~args.maskR) | (C::Eval(tmp1, tmp2) & args.maskR);
        JBIG2_PUTDWORD(dp, tmp);
      }
      lineSrc += args.srcStride;
      lineDst += args.dstStride;
    }
    return true;
  }
};

template <class C>
using SingleWordLeft = SingleWordDst<C, IntraWordLeftSrc>;

template <class C>
using SingleWordRight = SingleWordDst<C, IntraWordRightSrc>;

template <class C>
using SingleWordMiddle = SingleWordDst<C, MultiWordSrc>;

template <class C>
using MultiWordLeft =
    MultiWordDst<C, IntraWordRightSrc, MultiWordSrc, ConditionalWordSrc>;

template <class C>
using MultiWordRight =
    MultiWordDst<C, IntraWordRightSrc, AlignedSrc, AlignedSrc>;

template <class C>
using MultiWordMiddle = MultiWordDst<C, AlignedSrc, AlignedSrc, AlignedSrc>;

}  // namespace

CJBig2_Image::CJBig2_Image(int32_t w, int32_t h) {
  if (w <= 0 || h <= 0 || w > kMaxImagePixels)
    return;

  int32_t stride_pixels = (w + 31) & ~31;
  if (h > kMaxImagePixels / stride_pixels)
    return;

  m_nWidth = w;
  m_nHeight = h;
  m_nStride = stride_pixels / 8;
  m_pData.Reset(std::unique_ptr<uint8_t, FxFreeDeleter>(
      FX_Alloc2D(uint8_t, m_nStride, m_nHeight)));
}

CJBig2_Image::CJBig2_Image(int32_t w,
                           int32_t h,
                           int32_t stride,
                           uint8_t* pBuf) {
  if (w < 0 || h < 0)
    return;

  // Stride must be word-aligned.
  if (stride < 0 || stride > kMaxImageBytes || stride % 4 != 0)
    return;

  int32_t stride_pixels = 8 * stride;
  if (stride_pixels < w || h > kMaxImagePixels / stride_pixels)
    return;

  m_nWidth = w;
  m_nHeight = h;
  m_nStride = stride;
  m_pData.Reset(pBuf);
}

CJBig2_Image::CJBig2_Image(const CJBig2_Image& other)
    : m_nWidth(other.m_nWidth),
      m_nHeight(other.m_nHeight),
      m_nStride(other.m_nStride) {
  if (other.m_pData) {
    m_pData.Reset(std::unique_ptr<uint8_t, FxFreeDeleter>(
        FX_Alloc2D(uint8_t, m_nStride, m_nHeight)));
    memcpy(data(), other.data(), m_nStride * m_nHeight);
  }
}

CJBig2_Image::~CJBig2_Image() {}

// static
bool CJBig2_Image::IsValidImageSize(int32_t w, int32_t h) {
  return w > 0 && w <= JBIG2_MAX_IMAGE_SIZE && h > 0 &&
         h <= JBIG2_MAX_IMAGE_SIZE;
}

int CJBig2_Image::GetPixel(int32_t x, int32_t y) const {
  if (!m_pData)
    return 0;

  if (x < 0 || x >= m_nWidth)
    return 0;

  const uint8_t* pLine = GetLine(y);
  if (!pLine)
    return 0;

  int32_t m = BIT_INDEX_TO_BYTE(x);
  int32_t n = x & 7;
  return ((pLine[m] >> (7 - n)) & 1);
}

void CJBig2_Image::SetPixel(int32_t x, int32_t y, int v) {
  if (!m_pData)
    return;

  if (x < 0 || x >= m_nWidth)
    return;

  uint8_t* pLine = GetLine(y);
  if (!pLine)
    return;

  int32_t m = BIT_INDEX_TO_BYTE(x);
  int32_t n = 1 << (7 - (x & 7));
  if (v)
    pLine[m] |= n;
  else
    pLine[m] &= ~n;
}

void CJBig2_Image::CopyLine(int32_t hTo, int32_t hFrom) {
  if (!m_pData)
    return;

  uint8_t* pDst = GetLine(hTo);
  if (!pDst)
    return;

  const uint8_t* pSrc = GetLine(hFrom);
  if (!pSrc) {
    memset(pDst, 0, m_nStride);
    return;
  }
  memcpy(pDst, pSrc, m_nStride);
}

void CJBig2_Image::Fill(bool v) {
  if (!m_pData)
    return;

  memset(data(), v ? 0xff : 0, m_nStride * m_nHeight);
}

bool CJBig2_Image::ComposeTo(CJBig2_Image* pDst,
                             int32_t x,
                             int32_t y,
                             JBig2ComposeOp op) {
  return m_pData && ComposeToOpt2(pDst, x, y, op);
}

bool CJBig2_Image::ComposeToWithRect(CJBig2_Image* pDst,
                                     int32_t x,
                                     int32_t y,
                                     const FX_RECT& rtSrc,
                                     JBig2ComposeOp op) {
  if (!m_pData)
    return false;
  if (rtSrc == FX_RECT(0, 0, m_nWidth, m_nHeight))
    return ComposeToOpt2(pDst, x, y, op);
  return ComposeToOpt2WithRect(pDst, x, y, op, rtSrc);
}

bool CJBig2_Image::ComposeFrom(int32_t x,
                               int32_t y,
                               CJBig2_Image* pSrc,
                               JBig2ComposeOp op) {
  return m_pData ? pSrc->ComposeTo(this, x, y, op) : false;
}

bool CJBig2_Image::ComposeFromWithRect(int32_t x,
                                       int32_t y,
                                       CJBig2_Image* pSrc,
                                       const FX_RECT& rtSrc,
                                       JBig2ComposeOp op) {
  return m_pData ? pSrc->ComposeToWithRect(this, x, y, rtSrc, op) : false;
}

std::unique_ptr<CJBig2_Image> CJBig2_Image::SubImage(int32_t x,
                                                     int32_t y,
                                                     int32_t w,
                                                     int32_t h) {
  auto pImage = pdfium::MakeUnique<CJBig2_Image>(w, h);
  if (!pImage->data() || !m_pData)
    return pImage;

  if (x < 0 || x >= m_nWidth || y < 0 || y >= m_nHeight)
    return pImage;

  int32_t m = BIT_INDEX_TO_ALIGNED_BYTE(x);
  int32_t n = x & 31;
  int32_t bytes_to_copy = std::min(pImage->m_nStride, m_nStride - m);
  int32_t lines_to_copy = std::min(pImage->m_nHeight, m_nHeight - y);

  // Fast case when DWORD-aligned.
  if (n == 0) {
    for (int32_t j = 0; j < lines_to_copy; j++) {
      const uint8_t* pLineSrc = GetLineUnsafe(y + j);
      uint8_t* pLineDst = pImage->GetLineUnsafe(j);
      memcpy(pLineDst, pLineSrc + m, bytes_to_copy);
    }
    return pImage;
  }

  // Normal slow case.
  for (int32_t j = 0; j < lines_to_copy; j++) {
    const uint8_t* pLineSrc = GetLineUnsafe(y + j);
    uint8_t* pLineDst = pImage->GetLineUnsafe(j);
    const uint8_t* pSrc = pLineSrc + m;
    const uint8_t* pSrcEnd = pLineSrc + m_nStride;
    uint8_t* pDstEnd = pLineDst + bytes_to_copy;
    for (uint8_t *pDst = pLineDst; pDst < pDstEnd; pSrc += 4, pDst += 4) {
      uint32_t wTmp = JBIG2_GETDWORD(pSrc) << n;
      if (pSrc + 4 < pSrcEnd)
        wTmp |= (JBIG2_GETDWORD(pSrc + 4) >> (32 - n));
      JBIG2_PUTDWORD(pDst, wTmp);
    }
  }
  return pImage;
}

void CJBig2_Image::Expand(int32_t h, bool v) {
  if (!m_pData || h <= m_nHeight || h > kMaxImageBytes / m_nStride)
    return;

  if (m_pData.IsOwned()) {
    m_pData.Reset(std::unique_ptr<uint8_t, FxFreeDeleter>(FX_Realloc(
        uint8_t, m_pData.ReleaseAndClear().release(), h * m_nStride)));
  } else {
    uint8_t* pExternalBuffer = data();
    m_pData.Reset(std::unique_ptr<uint8_t, FxFreeDeleter>(
        FX_Alloc(uint8_t, h * m_nStride)));
    memcpy(data(), pExternalBuffer, m_nHeight * m_nStride);
  }
  memset(data() + m_nHeight * m_nStride, v ? 0xff : 0,
         (h - m_nHeight) * m_nStride);
  m_nHeight = h;
}

bool CJBig2_Image::ComposeToOpt2(CJBig2_Image* pDst,
                                 int32_t x,
                                 int32_t y,
                                 JBig2ComposeOp op) {
  ASSERT(m_pData);

  if (x < -1048576 || x > 1048576 || y < -1048576 || y > 1048576)
    return false;

  ComposeArgs args;
  args.xs0 = x < 0 ? -x : 0;
  args.ys0 = y < 0 ? -y : 0;

  FX_SAFE_INT32 iChecked = pDst->m_nWidth;
  iChecked -= x;
  if (iChecked.IsValid() && m_nWidth > iChecked.ValueOrDie())
    args.xs1 = iChecked.ValueOrDie();
  else
    args.xs1 = m_nWidth;

  iChecked = pDst->m_nHeight;
  iChecked -= y;
  if (iChecked.IsValid() && m_nHeight > iChecked.ValueOrDie())
    args.ys1 = pDst->m_nHeight - y;
  else
    args.ys1 = m_nHeight;

  if (args.ys0 >= args.ys1 || args.xs0 >= args.xs1)
    return false;

  const int32_t w = args.xs1 - args.xs0;
  const int32_t h = args.ys1 - args.ys0;

  args.xd0 = std::max(x, 0);
  args.yd0 = std::max(y, 0);
  args.xd1 = args.xd0 + w;
  args.yd1 = args.yd0 + h;
  args.s1 = args.xs0 & 31;
  args.d1 = args.xd0 & 31;
  args.d2 = args.xd1 & 31;
  args.maskL = 0xffffffff >> args.d1;
  args.maskR = 0xffffffff << ((32 - (args.xd1 & 31)) % 32);
  args.maskM = args.maskL & args.maskR;
  args.lineSrc = GetLineUnsafe(args.ys0) + BIT_INDEX_TO_ALIGNED_BYTE(args.xs0);
  args.lineLeft = m_nStride - BIT_INDEX_TO_ALIGNED_BYTE(args.xs0);
  args.lineDst =
      pDst->GetLineUnsafe(args.yd0) + BIT_INDEX_TO_ALIGNED_BYTE(args.xd0);
  args.srcStride = m_nStride;
  args.dstStride = pDst->m_nStride;
  args.middleDwords = (args.xd1 >> 5) - ((args.xd0 + 31) >> 5);

  return ComposeCommon(op, &args);
}

bool CJBig2_Image::ComposeToOpt2WithRect(CJBig2_Image* pDst,
                                         int32_t x,
                                         int32_t y,
                                         JBig2ComposeOp op,
                                         const FX_RECT& rtSrc) {
  ASSERT(m_pData);

  // TODO(weili): Check whether the range check is correct. Should x>=1048576?
  if (x < -1048576 || x > 1048576 || y < -1048576 || y > 1048576)
    return false;

  const int32_t sw = rtSrc.Width();
  const int32_t sh = rtSrc.Height();

  ComposeArgs args;
  args.ys0 = y < 0 ? -y : 0;
  args.ys1 = y + sh > pDst->m_nHeight ? pDst->m_nHeight - y : sh;
  args.xs0 = x < 0 ? -x : 0;
  args.xs1 = x + sw > pDst->m_nWidth ? pDst->m_nWidth - x : sw;
  if (args.ys0 >= args.ys1 || args.xs0 >= args.xs1)
    return false;

  const int32_t w = args.xs1 - args.xs0;
  const int32_t h = args.ys1 - args.ys0;

  args.yd0 = y < 0 ? 0 : y;
  args.xd0 = x < 0 ? 0 : x;
  args.xd1 = args.xd0 + w;
  args.yd1 = args.yd0 + h;
  args.d1 = args.xd0 & 31;
  args.d2 = args.xd1 & 31;
  args.s1 = args.xs0 & 31;
  args.maskL = 0xffffffff >> args.d1;
  args.maskR = 0xffffffff << ((32 - (args.xd1 & 31)) % 32);
  args.maskM = args.maskL & args.maskR;
  args.lineSrc = GetLineUnsafe(rtSrc.top + args.ys0) +
                 BIT_INDEX_TO_ALIGNED_BYTE(args.xs0 + rtSrc.left);
  args.lineDst =
      pDst->GetLineUnsafe(args.yd0) + BIT_INDEX_TO_ALIGNED_BYTE(args.xd0);
  args.lineLeft = m_nStride - BIT_INDEX_TO_ALIGNED_BYTE(args.xs0);

  return ComposeCommon(op, &args);
}

bool CJBig2_Image::ComposeCommon(JBig2ComposeOp op, ComposeArgs* args) {
  bool status = true;
  args->lineSrcEnd = GetLineUnsafe(m_nHeight);

  // Single-word cases.
  if (IS_INTRAWORD(args->xd0, args->xd1)) {
    if (IS_INTRAWORD(args->xs0, args->xs1)) {
      if (args->s1 > args->d1) {
        args->shift = args->s1 - args->d1;
        status = ComposeBothIntrawordLeft(op, *args);
      } else {
        args->shift = args->d1 - args->s1;
        status = ComposeBothIntrawordRight(op, *args);
      }
    } else {
      args->shift = args->s1 - args->d1;
      status = ComposeDstIntraword(op, *args);
    }
    return status;
  }

  // Multi-word cases.
  if (args->s1 > args->d1) {
    args->shift = args->s1 - args->d1;
    status = ComposeLeft(op, *args);
  } else if (args->s1 == args->d1) {
    args->shift = 0;
    status = ComposeMiddle(op, *args);
  } else {
    args->shift = args->d1 - args->s1;
    status = ComposeRight(op, *args);
  }
  return status;
}

bool CJBig2_Image::ComposeBothIntrawordLeft(JBig2ComposeOp op,
                                            const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return SingleWordLeft<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return SingleWordLeft<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return SingleWordLeft<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return SingleWordLeft<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return SingleWordLeft<OperatorReplace>::Compose(args);
  }
  return false;
}

bool CJBig2_Image::ComposeBothIntrawordRight(JBig2ComposeOp op,
                                             const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return SingleWordRight<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return SingleWordRight<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return SingleWordRight<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return SingleWordRight<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return SingleWordRight<OperatorReplace>::Compose(args);
  }
  return false;
}

bool CJBig2_Image::ComposeDstIntraword(JBig2ComposeOp op,
                                       const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return SingleWordMiddle<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return SingleWordMiddle<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return SingleWordMiddle<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return SingleWordMiddle<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return SingleWordMiddle<OperatorReplace>::Compose(args);
  }
  return false;
}

bool CJBig2_Image::ComposeLeft(JBig2ComposeOp op, const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return MultiWordLeft<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return MultiWordLeft<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return MultiWordLeft<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return MultiWordLeft<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return MultiWordLeft<OperatorReplace>::Compose(args);
  }
  return false;
}

bool CJBig2_Image::ComposeRight(JBig2ComposeOp op, const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return MultiWordRight<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return MultiWordRight<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return MultiWordRight<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return MultiWordRight<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return MultiWordRight<OperatorReplace>::Compose(args);
  }
  return false;
}

bool CJBig2_Image::ComposeMiddle(JBig2ComposeOp op, const ComposeArgs& args) {
  switch (op) {
    case JBIG2_COMPOSE_OR:
      return MultiWordMiddle<OperatorOR>::Compose(args);
    case JBIG2_COMPOSE_AND:
      return MultiWordMiddle<OperatorAND>::Compose(args);
    case JBIG2_COMPOSE_XOR:
      return MultiWordMiddle<OperatorXOR>::Compose(args);
    case JBIG2_COMPOSE_XNOR:
      return MultiWordMiddle<OperatorXNOR>::Compose(args);
    case JBIG2_COMPOSE_REPLACE:
      return MultiWordMiddle<OperatorReplace>::Compose(args);
  }
  return false;
}
