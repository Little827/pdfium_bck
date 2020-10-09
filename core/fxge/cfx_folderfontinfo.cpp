// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_folderfontinfo.h"

#include <limits>
#include <utility>

#include "build/build_config.h"
#include "core/fxcrt/fx_codepage.h"
#include "core/fxcrt/fx_memory_wrappers.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/fx_stream.h"
#include "core/fxge/cfx_fontmapper.h"
#include "core/fxge/fx_font.h"
#include "third_party/base/stl_util.h"

#define CHARSET_FLAG_ANSI (1 << 0)
#define CHARSET_FLAG_SYMBOL (1 << 1)
#define CHARSET_FLAG_SHIFTJIS (1 << 2)
#define CHARSET_FLAG_BIG5 (1 << 3)
#define CHARSET_FLAG_GB (1 << 4)
#define CHARSET_FLAG_KOREAN (1 << 5)

namespace {

constexpr struct {
  // FX_HashCode_GetA(name, false)
  uint32_t hash;
  // Inline string data does not effect struct size, and avoids relocation.
  const char subst_name[28];
} kBase14Substs[] = {
    {/* "Courier" */ 2622592525, "Courier New"},
    {/* "Courier-Bold" */ 2114255461, "Courier New Bold"},
    {/* "Courier-BoldOblique" */ 1468992524, "Courier New Bold Italic"},
    {/* "Courier-Oblique" */ 2664738385, "Courier New Italic"},
    {/* "Helvetica" */ 3478674545, "Arial"},
    {/* "Helvetica-Bold" */ 3371078273, "Arial Bold"},
    {/* "Helvetica-BoldOblique" */ 3016449136, "Arial Bold Italic"},
    {/* "Helvetica-Oblique" */ 1148244149, "Arial Italic"},
    {/* "Times-Roman" */ 1058166902, "Times New Roman"},
    {/* "Times-Bold" */ 3635888364, "Times New Roman Bold"},
    {/* "Times-BoldItalic" */ 162006588, "Times New Roman Bold Italic"},
    {/* "Times-Italic" */ 2485011159, "Times New Roman Italic"},
};

// Used with std::unique_ptr to automatically call fclose().
struct FxFileCloser {
  inline void operator()(FILE* h) const {
    if (h)
      fclose(h);
  }
};

ByteString ReadStringFromFile(FILE* pFile, uint32_t size) {
  ByteString result;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<char> buffer = result.GetBuffer(size);
    if (!fread(buffer.data(), size, 1, pFile))
      return ByteString();
  }
  result.ReleaseBuffer(size);
  return result;
}

ByteString LoadTableFromTT(FILE* pFile,
                           const uint8_t* pTables,
                           uint32_t nTables,
                           uint32_t tag,
                           uint32_t fileSize) {
  for (uint32_t i = 0; i < nTables; i++) {
    const uint8_t* p = pTables + i * 16;
    if (GET_TT_LONG(p) == tag) {
      uint32_t offset = GET_TT_LONG(p + 8);
      uint32_t size = GET_TT_LONG(p + 12);
      if (offset > std::numeric_limits<uint32_t>::max() - size ||
          offset + size > fileSize || fseek(pFile, offset, SEEK_SET) < 0) {
        return ByteString();
      }
      return ReadStringFromFile(pFile, size);
    }
  }
  return ByteString();
}

uint32_t GetCharset(int charset) {
  switch (charset) {
    case FX_CHARSET_ShiftJIS:
      return CHARSET_FLAG_SHIFTJIS;
    case FX_CHARSET_ChineseSimplified:
      return CHARSET_FLAG_GB;
    case FX_CHARSET_ChineseTraditional:
      return CHARSET_FLAG_BIG5;
    case FX_CHARSET_Hangul:
      return CHARSET_FLAG_KOREAN;
    case FX_CHARSET_Symbol:
      return CHARSET_FLAG_SYMBOL;
    case FX_CHARSET_ANSI:
      return CHARSET_FLAG_ANSI;
    default:
      break;
  }
  return 0;
}

int32_t GetSimilarValue(int weight,
                        bool bItalic,
                        int pitch_family,
                        uint32_t style,
                        bool bMatchName,
                        size_t familyNameLength,
                        size_t bsNameLength) {
  int32_t iSimilarValue = 0;
  if (bMatchName && (familyNameLength == bsNameLength))
    iSimilarValue += 4;
  if (FontStyleIsForceBold(style) == (weight > 400))
    iSimilarValue += 16;
  if (FontStyleIsItalic(style) == bItalic)
    iSimilarValue += 16;
  if (FontStyleIsSerif(style) == FontFamilyIsRoman(pitch_family))
    iSimilarValue += 16;
  if (FontStyleIsScript(style) == FontFamilyIsScript(pitch_family))
    iSimilarValue += 8;
  if (FontStyleIsFixedPitch(style) == FontFamilyIsFixedPitch(pitch_family))
    iSimilarValue += 8;
  return iSimilarValue;
}

}  // namespace

CFX_FolderFontInfo::CFX_FolderFontInfo() = default;

CFX_FolderFontInfo::~CFX_FolderFontInfo() = default;

void CFX_FolderFontInfo::AddPath(const ByteString& path) {
  m_PathList.push_back(path);
}

bool CFX_FolderFontInfo::EnumFontList(CFX_FontMapper* pMapper) {
  m_pMapper = pMapper;
  for (const auto& path : m_PathList)
    ScanPath(path);
  return true;
}

void CFX_FolderFontInfo::ScanPath(const ByteString& path) {
  std::unique_ptr<FX_FolderHandle, FxFolderHandleCloser> handle(
      FX_OpenFolder(path.c_str()));
  if (!handle)
    return;

  ByteString filename;
  bool bFolder;
  while (FX_GetNextFile(handle.get(), &filename, &bFolder)) {
    if (bFolder) {
      if (filename == "." || filename == "..")
        continue;
    } else {
      ByteString ext = filename.Last(4);
      ext.MakeLower();
      if (ext != ".ttf" && ext != ".ttc" && ext != ".otf")
        continue;
    }

    ByteString fullpath = path;
#if defined(OS_WIN)
    fullpath += "\\";
#else
    fullpath += "/";
#endif

    fullpath += filename;
    bFolder ? ScanPath(fullpath) : ScanFile(fullpath);
  }
}

void CFX_FolderFontInfo::ScanFile(const ByteString& path) {
  std::unique_ptr<FILE, FxFileCloser> pFile(fopen(path.c_str(), "rb"));
  if (!pFile)
    return;

  fseek(pFile.get(), 0, SEEK_END);

  uint32_t filesize = ftell(pFile.get());
  uint8_t buffer[16];
  fseek(pFile.get(), 0, SEEK_SET);

  size_t readCnt = fread(buffer, 12, 1, pFile.get());
  if (readCnt != 1)
    return;

  if (GET_TT_LONG(buffer) != kTableTTCF) {
    ReportFace(path, pFile.get(), filesize, 0);
    return;
  }

  uint32_t nFaces = GET_TT_LONG(buffer + 8);
  FX_SAFE_SIZE_T safe_face_bytes = nFaces;
  safe_face_bytes *= 4;
  if (!safe_face_bytes.IsValid())
    return;

  const size_t face_bytes = safe_face_bytes.ValueOrDie();
  std::unique_ptr<uint8_t, FxFreeDeleter> offsets(
      FX_Alloc(uint8_t, face_bytes));
  readCnt = fread(offsets.get(), 1, face_bytes, pFile.get());
  if (readCnt != face_bytes)
    return;

  auto offsets_span = pdfium::make_span(offsets.get(), face_bytes);
  for (uint32_t i = 0; i < nFaces; i++)
    ReportFace(path, pFile.get(), filesize, GET_TT_LONG(&offsets_span[i * 4]));
}

void CFX_FolderFontInfo::ReportFace(const ByteString& path,
                                    FILE* pFile,
                                    uint32_t filesize,
                                    uint32_t offset) {
  char buffer[16];
  if (fseek(pFile, offset, SEEK_SET) < 0 || !fread(buffer, 12, 1, pFile))
    return;

  uint32_t nTables = GET_TT_SHORT(buffer + 4);
  ByteString tables = ReadStringFromFile(pFile, nTables * 16);
  if (tables.IsEmpty())
    return;

  ByteString names =
      LoadTableFromTT(pFile, tables.raw_str(), nTables, 0x6e616d65, filesize);
  if (names.IsEmpty())
    return;

  ByteString facename = GetNameFromTT(names.raw_span(), 1);
  if (facename.IsEmpty())
    return;

  ByteString style = GetNameFromTT(names.raw_span(), 2);
  if (style != "Regular")
    facename += " " + style;

  if (pdfium::Contains(m_FontList, facename))
    return;

  auto pInfo =
      std::make_unique<FontFaceInfo>(path, facename, tables, offset, filesize);
  ByteString os2 =
      LoadTableFromTT(pFile, tables.raw_str(), nTables, 0x4f532f32, filesize);
  if (os2.GetLength() >= 86) {
    const uint8_t* p = os2.raw_str() + 78;
    uint32_t codepages = GET_TT_LONG(p);
    if (codepages & (1U << 17)) {
      m_pMapper->AddInstalledFont(facename, FX_CHARSET_ShiftJIS);
      pInfo->m_Charsets |= CHARSET_FLAG_SHIFTJIS;
    }
    if (codepages & (1U << 18)) {
      m_pMapper->AddInstalledFont(facename, FX_CHARSET_ChineseSimplified);
      pInfo->m_Charsets |= CHARSET_FLAG_GB;
    }
    if (codepages & (1U << 20)) {
      m_pMapper->AddInstalledFont(facename, FX_CHARSET_ChineseTraditional);
      pInfo->m_Charsets |= CHARSET_FLAG_BIG5;
    }
    if ((codepages & (1U << 19)) || (codepages & (1U << 21))) {
      m_pMapper->AddInstalledFont(facename, FX_CHARSET_Hangul);
      pInfo->m_Charsets |= CHARSET_FLAG_KOREAN;
    }
    if (codepages & (1U << 31)) {
      m_pMapper->AddInstalledFont(facename, FX_CHARSET_Symbol);
      pInfo->m_Charsets |= CHARSET_FLAG_SYMBOL;
    }
  }
  m_pMapper->AddInstalledFont(facename, FX_CHARSET_ANSI);
  pInfo->m_Charsets |= CHARSET_FLAG_ANSI;
  pInfo->m_Styles = 0;
  if (style.Contains("Bold"))
    pInfo->m_Styles |= FXFONT_FORCE_BOLD;
  if (style.Contains("Italic") || style.Contains("Oblique"))
    pInfo->m_Styles |= FXFONT_ITALIC;
  if (facename.Contains("Serif"))
    pInfo->m_Styles |= FXFONT_SERIF;

  m_FontList[facename] = std::move(pInfo);
}

void* CFX_FolderFontInfo::GetSubstFont(ByteStringView face) {
  uint32_t hash = FX_HashCode_GetA(face, /*bIgnoreCase=*/false);
  for (size_t i = 0; i < pdfium::size(kBase14Substs); ++i) {
    if (hash == kBase14Substs[i].hash)
      return GetFont(kBase14Substs[i].subst_name);
  }
  return nullptr;
}

void* CFX_FolderFontInfo::FindFont(int weight,
                                   bool bItalic,
                                   int charset,
                                   int pitch_family,
                                   const char* family,
                                   bool bMatchName) {
  FontFaceInfo* pFind = nullptr;
  if (charset == FX_CHARSET_ANSI && FontFamilyIsFixedPitch(pitch_family))
    return GetFont("Courier New");

  ByteStringView bsFamily(family);
  uint32_t charset_flag = GetCharset(charset);
  int32_t iBestSimilar = 0;
  for (const auto& it : m_FontList) {
    const ByteString& bsName = it.first;
    FontFaceInfo* pFont = it.second.get();
    if (!(pFont->m_Charsets & charset_flag) && charset != FX_CHARSET_Default)
      continue;

    if (bMatchName && !bsName.Contains(bsFamily))
      continue;

    size_t familyNameLength = strlen(family);
    size_t bsNameLength = bsName.GetLength();
    int32_t iSimilarValue =
        GetSimilarValue(weight, bItalic, pitch_family, pFont->m_Styles,
                        bMatchName, familyNameLength, bsNameLength);
    if (iSimilarValue > iBestSimilar) {
      iBestSimilar = iSimilarValue;
      pFind = pFont;
    }
  }
  return pFind;
}

void* CFX_FolderFontInfo::MapFont(int weight,
                                  bool bItalic,
                                  int charset,
                                  int pitch_family,
                                  const char* family) {
  return nullptr;
}

void* CFX_FolderFontInfo::GetFont(const char* face) {
  auto it = m_FontList.find(face);
  return it != m_FontList.end() ? it->second.get() : nullptr;
}

uint32_t CFX_FolderFontInfo::GetFontData(void* hFont,
                                         uint32_t table,
                                         pdfium::span<uint8_t> buffer) {
  if (!hFont)
    return 0;

  const FontFaceInfo* pFont = static_cast<FontFaceInfo*>(hFont);
  uint32_t datasize = 0;
  uint32_t offset = 0;
  if (table == 0) {
    datasize = pFont->m_FontOffset ? 0 : pFont->m_FileSize;
  } else if (table == kTableTTCF) {
    datasize = pFont->m_FontOffset ? pFont->m_FileSize : 0;
  } else {
    uint32_t nTables = pFont->m_FontTables.GetLength() / 16;
    for (uint32_t i = 0; i < nTables; i++) {
      const uint8_t* p = pFont->m_FontTables.raw_str() + i * 16;
      if (GET_TT_LONG(p) == table) {
        offset = GET_TT_LONG(p + 8);
        datasize = GET_TT_LONG(p + 12);
      }
    }
  }

  if (!datasize || buffer.size() < datasize)
    return datasize;

  std::unique_ptr<FILE, FxFileCloser> pFile(
      fopen(pFont->m_FilePath.c_str(), "rb"));
  if (!pFile)
    return 0;

  if (fseek(pFile.get(), offset, SEEK_SET) < 0 ||
      fread(buffer.data(), datasize, 1, pFile.get()) != 1) {
    return 0;
  }
  return datasize;
}

void CFX_FolderFontInfo::DeleteFont(void* hFont) {}

bool CFX_FolderFontInfo::GetFaceName(void* hFont, ByteString* name) {
  if (!hFont)
    return false;
  *name = static_cast<FontFaceInfo*>(hFont)->m_FaceName;
  return true;
}

bool CFX_FolderFontInfo::GetFontCharset(void* hFont, int* charset) {
  return false;
}

CFX_FolderFontInfo::FontFaceInfo::FontFaceInfo(ByteString filePath,
                                               ByteString faceName,
                                               ByteString fontTables,
                                               uint32_t fontOffset,
                                               uint32_t fileSize)
    : m_FilePath(filePath),
      m_FaceName(faceName),
      m_FontTables(fontTables),
      m_FontOffset(fontOffset),
      m_FileSize(fileSize),
      m_Styles(0),
      m_Charsets(0) {}
