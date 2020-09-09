// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_CXFA_TEXTLAYOUT_H_
#define XFA_FXFA_CXFA_TEXTLAYOUT_H_

#include <memory>
#include <vector>

#include "core/fxcrt/css/cfx_css.h"
#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/retain_ptr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "fxjs/gc/heap.h"
#include "v8/include/cppgc/garbage-collected.h"
#include "v8/include/cppgc/member.h"
#include "v8/include/cppgc/visitor.h"
#include "xfa/fgas/layout/cfx_char.h"
#include "xfa/fxfa/cxfa_textparser.h"

class CFDE_RenderDevice;
class CFX_CSSComputedStyle;
class CFX_RTFBreak;
class CFX_RenderDevice;
class CFX_XMLNode;
class CFX_LinkUserData;
class CXFA_Node;
class CXFA_PieceLine;
class CXFA_TextPiece;
class CXFA_TextProvider;
class CXFA_TextTabstopsContext;
class TextCharPos;
struct FX_RTFTEXTOBJ;

class CXFA_TextLayout final : public cppgc::GarbageCollected<CXFA_TextLayout> {
 public:
  CONSTRUCT_VIA_MAKE_GARBAGE_COLLECTED;
  ~CXFA_TextLayout();

  void Trace(cppgc::Visitor* visitor) const;

  float GetLayoutHeight();
  float StartLayout(float fWidth);
  float DoLayout(float fTextHeight);
  float DoSplitLayout(size_t szBlockIndex,
                      float fCalcHeight,
                      float fTextHeight);
  float Layout(const CFX_SizeF& size);

  CFX_SizeF CalcSize(const CFX_SizeF& minSize, const CFX_SizeF& maxSize);
  void ItemBlocks(const CFX_RectF& rtText, size_t szBlockIndex);
  bool DrawString(CFX_RenderDevice* pFxDevice,
                  const CFX_Matrix& mtDoc2Device,
                  const CFX_RectF& rtClip,
                  size_t szBlockIndex);
  bool IsLoaded() const { return !m_pieceLines.empty(); }
  void Unload();

  const std::vector<std::unique_ptr<CXFA_PieceLine>>* GetPieceLines() const {
    return &m_pieceLines;
  }

  bool HasBlock() const { return m_bHasBlock; }
  void ClearBlocks() { m_Blocks.clear(); }
  void ResetHasBlock() { m_bHasBlock = false; }

 private:
  struct BlockData {
    size_t szIndex;
    size_t szLength;
  };

  struct BlockHeight {
    size_t szBlockIndex;
    float fHeight;
  };

  struct LoaderContext {
    LoaderContext();
    ~LoaderContext();

    void Trace(cppgc::Visitor* visitor) const;

    bool bSaveLineHeight = false;
    bool bFilterSpace = false;
    float fWidth = 0;
    float fHeight = 0;
    float fLastPos = 0;
    float fStartLineOffset = 0;
    int32_t iChar = 0;
    // TODO(thestig): Make this size_t?
    int32_t iTotalLines = -1;
    UnownedPtr<const CFX_XMLNode> pXMLNode;
    RetainPtr<CFX_CSSComputedStyle> pParentStyle;
    cppgc::Member<CXFA_Node> pNode;
    std::vector<float> lineHeights;
    std::vector<BlockHeight> blockHeights;
  };

  CXFA_TextLayout(CXFA_FFDoc* doc, CXFA_TextProvider* pTextProvider);

  void GetTextDataNode();
  CFX_XMLNode* GetXMLContainerNode();
  std::unique_ptr<CFX_RTFBreak> CreateBreak(bool bDefault);
  void InitBreak(float fLineWidth);
  void InitBreak(CFX_CSSComputedStyle* pStyle,
                 CFX_CSSDisplay eDisplay,
                 float fLineWidth,
                 const CFX_XMLNode* pXMLNode,
                 CFX_CSSComputedStyle* pParentStyle);
  void Loader(float textWidth, float* pLinePos, bool bSavePieces);
  void LoadText(CXFA_Node* pNode,
                float textWidth,
                float* pLinePos,
                bool bSavePieces);
  bool LoadRichText(const CFX_XMLNode* pXMLNode,
                    float textWidth,
                    float* pLinePos,
                    const RetainPtr<CFX_CSSComputedStyle>& pParentStyle,
                    bool bSavePieces,
                    RetainPtr<CFX_LinkUserData> pLinkData,
                    bool bEndBreak,
                    bool bIsOl,
                    int32_t iLiCount);
  bool AppendChar(const WideString& wsText,
                  float* pLinePos,
                  float fSpaceAbove,
                  bool bSavePieces);
  void AppendTextLine(CFX_BreakType dwStatus,
                      float* pLinePos,
                      bool bSavePieces,
                      bool bEndBreak);
  void EndBreak(CFX_BreakType dwStatus, float* pLinePos, bool bDefault);
  bool IsEnd(bool bSavePieces);
  void UpdateAlign(float fHeight, float fBottom);
  void RenderString(CFX_RenderDevice* pDevice,
                    CXFA_PieceLine* pPieceLine,
                    size_t szPiece,
                    std::vector<TextCharPos>* pCharPos,
                    const CFX_Matrix& mtDoc2Device);
  void RenderPath(CFX_RenderDevice* pDevice,
                  CXFA_PieceLine* pPieceLine,
                  size_t szPiece,
                  std::vector<TextCharPos>* pCharPos,
                  const CFX_Matrix& mtDoc2Device);
  size_t GetDisplayPos(const CXFA_TextPiece* pPiece,
                       std::vector<TextCharPos>* pCharPos);
  void DoTabstops(CFX_CSSComputedStyle* pStyle, CXFA_PieceLine* pPieceLine);
  bool LayoutInternal(size_t szBlockIndex);
  size_t CountBlocks() const;
  size_t GetNextIndexFromLastBlockData() const;
  void UpdateLoaderHeight(float fTextHeight);

  bool m_bHasBlock = false;
  bool m_bRichText = false;
  int32_t m_iLines = 0;
  float m_fMaxWidth = 0;
  std::vector<BlockData> m_Blocks;
  cppgc::Member<CXFA_FFDoc> const m_pDoc;
  cppgc::Member<CXFA_TextProvider> const m_pTextProvider;
  cppgc::Member<CXFA_Node> m_pTextDataNode;
  std::unique_ptr<CFX_RTFBreak> m_pBreak;
  std::unique_ptr<LoaderContext> m_pLoader;
  CXFA_TextParser m_textParser;
  std::vector<std::unique_ptr<CXFA_PieceLine>> m_pieceLines;
  std::unique_ptr<CXFA_TextTabstopsContext> m_pTabstopContext;
};

#endif  // XFA_FXFA_CXFA_TEXTLAYOUT_H_
