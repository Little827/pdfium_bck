// Copyright 2016 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_PAGE_CPDF_PAGEIMAGECACHE_H_
#define CORE_FPDFAPI_PAGE_CPDF_PAGEIMAGECACHE_H_

#include <stdint.h>

#include <functional>
#include <map>
#include <memory>

#include "core/fpdfapi/page/cpdf_dib.h"
#include "core/fxcrt/maybe_owned.h"
#include "core/fxcrt/retain_ptr.h"
#include "core/fxcrt/unowned_ptr.h"

#if defined(_SKIA_SUPPORT_)
#include "core/fxge/dib/cfx_dibbase.h"
#include "third_party/skia/include/core/SkRefCnt.h"  // nogncheck
#endif

class CPDF_Dictionary;
class CPDF_Image;
class CPDF_Page;
class CPDF_Stream;
class PauseIndicatorIface;

#if defined(_SKIA_SUPPORT_)
class SkImage;
#endif  // defined(_SKIA_SUPPORT_)

class CPDF_PageImageCache {
 public:
  explicit CPDF_PageImageCache(CPDF_Page* pPage);
  ~CPDF_PageImageCache();

  void ResetBitmapForImage(RetainPtr<CPDF_Image> pImage);
  void CacheOptimization(int32_t dwLimitCacheSize);
  uint32_t GetTimeCount() const { return m_nTimeCount; }
  CPDF_Page* GetPage() const { return m_pPage; }

  bool StartGetCachedBitmap(RetainPtr<CPDF_Image> pImage,
                            const CPDF_Dictionary* pFormResources,
                            const CPDF_Dictionary* pPageResources,
                            bool bStdCS,
                            CPDF_ColorSpace::Family eFamily,
                            bool bLoadMask,
                            const CFX_Size& max_size_required);

  bool Continue(PauseIndicatorIface* pPause);

  uint32_t GetCurMatteColor() const;
  RetainPtr<CFX_DIBBase> DetachCurBitmap();
  RetainPtr<CFX_DIBBase> DetachCurMask();

 private:
#if defined(_SKIA_SUPPORT_)
  // Wrapper around a `CFX_DIBBase` that memoizes `RealizeSkImage()`. This is
  // only safe if the underlying `CFX_DIBBase` is not mutable.
  class CachedImage final : public CFX_DIBBase {
   public:
    explicit CachedImage(RetainPtr<CFX_DIBBase> image);
    ~CachedImage() override;

    // `CFX_DIBBase`:
    pdfium::span<const uint8_t> GetBuffer() const override;
    pdfium::span<const uint8_t> GetScanline(int line) const override;
    bool SkipToScanline(int line, PauseIndicatorIface* pause) const override;
    size_t GetEstimatedImageMemoryBurden() const override;
    sk_sp<SkImage> RealizeSkImage() const override;

   private:
    RetainPtr<CFX_DIBBase> image_;
    mutable sk_sp<SkImage> cached_skia_image_;
  };
#endif  // defined(_SKIA_SUPPORT_)

  class Entry {
   public:
    explicit Entry(RetainPtr<CPDF_Image> pImage);
    ~Entry();

    void Reset();
    uint32_t EstimateSize() const { return m_dwCacheSize; }
    uint32_t GetMatteColor() const { return m_MatteColor; }
    uint32_t GetTimeCount() const { return m_dwTimeCount; }
    void SetTimeCount(uint32_t count) { m_dwTimeCount = count; }
    CPDF_Image* GetImage() const { return m_pImage.Get(); }

    CPDF_DIB::LoadState StartGetCachedBitmap(
        CPDF_PageImageCache* pPageImageCache,
        const CPDF_Dictionary* pFormResources,
        const CPDF_Dictionary* pPageResources,
        bool bStdCS,
        CPDF_ColorSpace::Family eFamily,
        bool bLoadMask,
        const CFX_Size& max_size_required);

    // Returns whether to Continue() or not.
    bool Continue(PauseIndicatorIface* pPause,
                  CPDF_PageImageCache* pPageImageCache);

    RetainPtr<CFX_DIBBase> DetachBitmap();
    RetainPtr<CFX_DIBBase> DetachMask();

   private:
    void ContinueGetCachedBitmap(CPDF_PageImageCache* pPageImageCache);
    void CalcSize();
    bool IsCacheValid(const CFX_Size& max_size_required) const;

    uint32_t m_dwTimeCount = 0;
    uint32_t m_MatteColor = 0;
    uint32_t m_dwCacheSize = 0;
    RetainPtr<CPDF_Image> const m_pImage;
    RetainPtr<CFX_DIBBase> m_pCurBitmap;
    RetainPtr<CFX_DIBBase> m_pCurMask;
    RetainPtr<CFX_DIBBase> m_pCachedBitmap;
    RetainPtr<CFX_DIBBase> m_pCachedMask;
    bool m_bCachedSetMaxSizeRequired = false;
  };

  // Makes a `CachedImage` backed by `image` if Skia is the default renderer,
  // otherwise return the image itself. `realize_hint` indicates whether it
  // would be beneficial to realize `image` before caching.
  static RetainPtr<CFX_DIBBase> MakeCachedImage(RetainPtr<CFX_DIBBase> image,
                                                bool realize_hint);

  void ClearImageCacheEntry(const CPDF_Stream* pStream);

  UnownedPtr<CPDF_Page> const m_pPage;
  std::map<RetainPtr<const CPDF_Stream>, std::unique_ptr<Entry>, std::less<>>
      m_ImageCache;
  MaybeOwned<Entry> m_pCurImageCacheEntry;
  uint32_t m_nTimeCount = 0;
  uint32_t m_nCacheSize = 0;
  bool m_bCurFindCache = false;
};

#endif  // CORE_FPDFAPI_PAGE_CPDF_PAGEIMAGECACHE_H_
