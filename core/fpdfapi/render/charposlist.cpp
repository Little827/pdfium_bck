// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/charposlist.h"

#include "build/build_config.h"
#include "core/fpdfapi/font/cpdf_cidfont.h"
#include "core/fpdfapi/font/cpdf_font.h"
#include "core/fxge/cfx_substfont.h"
#include "core/fxge/text_char_pos.h"

namespace {

bool InitializeCharPosFromFontAndCharCode(CPDF_Font* font,
                                          uint32_t char_code,
                                          TextCharPos* charpos) {
  WideString unicode = font->UnicodeFromCharCode(char_code);
  charpos->m_Unicode = !unicode.IsEmpty() ? unicode[0] : char_code;

  bool vertical_glyph = false;
  charpos->m_GlyphIndex = font->GlyphFromCharCode(char_code, &vertical_glyph);

#if defined(OS_MACOSX)
  charpos->m_ExtGID = font->GlyphFromCharCodeExt(char_code);
#endif

  if (font->AsCIDFont())
    charpos->m_bFontStyle = true;

  return vertical_glyph;
}

uint32_t GetGlyphID(const TextCharPos& charpos) {
#if defined(OS_MACOSX)
  return charpos.m_ExtGID != static_cast<uint32_t>(-1) ? charpos.m_ExtGID
                                                       : charpos.m_GlyphIndex;
#else
  return charpos.m_GlyphIndex;
#endif
}

}  // namespace

std::vector<TextCharPos> GetCharPosList(const std::vector<uint32_t>& charCodes,
                                        const std::vector<float>& charPos,
                                        CPDF_Font* pFont,
                                        float font_size) {
  std::vector<TextCharPos> results;
  results.reserve(charCodes.size());

  CPDF_CIDFont* pCIDFont = pFont->AsCIDFont();
  bool bVertWriting = pCIDFont && pCIDFont->IsVertWriting();
  bool bToUnicode = !!pFont->GetFontDict()->GetStreamFor("ToUnicode");
  for (size_t i = 0; i < charCodes.size(); ++i) {
    uint32_t CharCode = charCodes[i];
    if (CharCode == static_cast<uint32_t>(-1))
      continue;

    results.emplace_back();
    TextCharPos& charpos = results.back();
    bool vertical_glyph =
        InitializeCharPosFromFontAndCharCode(pFont, CharCode, &charpos);

    uint32_t glyph_id = GetGlyphID(charpos);
    bool bIsInvalidGlyph = glyph_id == static_cast<uint32_t>(-1);
    bool bIsTrueTypeZeroGlyph = glyph_id == 0 && pFont->IsTrueTypeFont();
    bool bUseFallbackFont = false;
    if (bIsInvalidGlyph || bIsTrueTypeZeroGlyph) {
      charpos.m_FallbackFontPosition =
          pFont->FallbackFontFromCharcode(CharCode);
      charpos.m_GlyphIndex = pFont->FallbackGlyphFromCharcode(
          charpos.m_FallbackFontPosition, CharCode);
      if (bIsTrueTypeZeroGlyph &&
          charpos.m_GlyphIndex == static_cast<uint32_t>(-1)) {
        // For a TrueType font character, when finding the glyph from the
        // fallback font fails, switch back to using the original font.

        // When keyword "ToUnicode" exists in the PDF file, it indicates
        // a "ToUnicode" mapping file is used to convert from CIDs (which
        // begins at decimal 0) to Unicode code. (See ToUnicode Mapping File
        // Tutorial - Adobe
        // https://www.adobe.com/content/dam/acom/en/devnet/acrobat/pdfs/5411.ToUnicode.pdf
        // and
        // https://www.freetype.org/freetype2/docs/tutorial/step1.html#section-6)
        if (bToUnicode)
          charpos.m_GlyphIndex = 0;
      } else {
        bUseFallbackFont = true;
      }
    }
    CFX_Font* pCurrentFont;
    if (bUseFallbackFont) {
      pCurrentFont = pFont->GetFontFallback(charpos.m_FallbackFontPosition);
#if defined(OS_MACOSX)
      charpos.m_ExtGID = charpos.m_GlyphIndex;
#endif
    } else {
      pCurrentFont = pFont->GetFont();
      charpos.m_FallbackFontPosition = -1;
    }

    if (!pFont->IsEmbedded() && !pFont->IsCIDFont())
      charpos.m_FontCharWidth = pFont->GetCharWidthF(CharCode);

    charpos.m_Origin = CFX_PointF(i > 0 ? charPos[i - 1] : 0, 0);

    float scalingFactor = 1.0f;
    if (!pFont->IsEmbedded() && pFont->HasFontWidths() && !bVertWriting &&
        !pCurrentFont->GetSubstFont()->m_bFlagMM) {
      uint32_t pdfGlyphWidth = pFont->GetCharWidthF(CharCode);
      uint32_t ftGlyphWidth =
          pCurrentFont ? pCurrentFont->GetGlyphWidth(charpos.m_GlyphIndex) : 0;
      if (ftGlyphWidth && pdfGlyphWidth > ftGlyphWidth + 1) {
        // Move the initial x position by half of the excess (transformed to
        // text space coordinates).
        charpos.m_Origin.x +=
            (pdfGlyphWidth - ftGlyphWidth) * font_size / 2000.0f;
      } else if (pdfGlyphWidth && ftGlyphWidth &&
                 pdfGlyphWidth < ftGlyphWidth) {
        scalingFactor = static_cast<float>(pdfGlyphWidth) / ftGlyphWidth;
        charpos.m_AdjustMatrix[0] = scalingFactor;
        charpos.m_AdjustMatrix[1] = 0.0f;
        charpos.m_AdjustMatrix[2] = 0.0f;
        charpos.m_AdjustMatrix[3] = 1.0f;
        charpos.m_bGlyphAdjust = true;
      }
    }
    if (!pCIDFont)
      continue;

    uint16_t CID = pCIDFont->CIDFromCharCode(CharCode);
    if (bVertWriting) {
      charpos.m_Origin = CFX_PointF(0, charpos.m_Origin.x);

      short vx;
      short vy;
      pCIDFont->GetVertOrigin(CID, vx, vy);
      charpos.m_Origin.x -= font_size * vx / 1000;
      charpos.m_Origin.y -= font_size * vy / 1000;
    }

    const uint8_t* pTransform = pCIDFont->GetCIDTransform(CID);
    if (pTransform && !vertical_glyph) {
      charpos.m_AdjustMatrix[0] =
          pCIDFont->CIDTransformToFloat(pTransform[0]) * scalingFactor;
      charpos.m_AdjustMatrix[1] =
          pCIDFont->CIDTransformToFloat(pTransform[1]) * scalingFactor;
      charpos.m_AdjustMatrix[2] = pCIDFont->CIDTransformToFloat(pTransform[2]);
      charpos.m_AdjustMatrix[3] = pCIDFont->CIDTransformToFloat(pTransform[3]);
      charpos.m_Origin.x +=
          pCIDFont->CIDTransformToFloat(pTransform[4]) * font_size;
      charpos.m_Origin.y +=
          pCIDFont->CIDTransformToFloat(pTransform[5]) * font_size;
      charpos.m_bGlyphAdjust = true;
    }
  }

  return results;
}
