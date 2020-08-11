// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXFA_CXFA_FFDOC_H_
#define XFA_FXFA_CXFA_FFDOC_H_

#include <map>
#include <memory>

#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/unowned_ptr.h"
#include "fxjs/gc/heap.h"
#include "v8/include/cppgc/garbage-collected.h"
#include "v8/include/cppgc/member.h"
#include "v8/include/cppgc/prefinalizer.h"
#include "v8/include/cppgc/visitor.h"
#include "xfa/fxfa/fxfa.h"
#include "xfa/fxfa/parser/cxfa_document.h"

class CFGAS_PDFFontMgr;
class CFX_ChecksumContext;
class CFX_DIBBase;
class CFX_DIBitmap;
class CFX_XMLDocument;
class CPDF_Document;
class CXFA_FFApp;
class CXFA_FFNotify;
class CXFA_FFDocView;
class CXFA_LayoutProcessor;

namespace cppgc {
class Heap;
}  // namespace cppgc

struct FX_IMAGEDIB_AND_DPI {
  FX_IMAGEDIB_AND_DPI();
  FX_IMAGEDIB_AND_DPI(const FX_IMAGEDIB_AND_DPI& that);
  FX_IMAGEDIB_AND_DPI(const RetainPtr<CFX_DIBBase>& pDib,
                      int32_t xDpi,
                      int32_t yDpi);
  ~FX_IMAGEDIB_AND_DPI();

  RetainPtr<CFX_DIBBase> pDibSource;
  int32_t iImageXDpi;
  int32_t iImageYDpi;
};

class CXFA_FFDoc : public cppgc::GarbageCollected<CXFA_FFDoc> {
  CPPGC_USING_PRE_FINALIZER(CXFA_FFDoc, PreFinalize);

 public:
  CONSTRUCT_VIA_MAKE_GARBAGE_COLLECTED;
  ~CXFA_FFDoc();

  void PreFinalize();
  void Trace(cppgc::Visitor* visitor) const;

  bool OpenDoc(CFX_XMLDocument* pXML);

  IXFA_DocEnvironment* GetDocEnvironment() const {
    return m_pDocEnvironment.Get();
  }
  FormType GetFormType() const { return m_FormType; }
  cppgc::Heap* GetHeap() const { return m_pHeap.Get(); }
  CFX_XMLDocument* GetXMLDocument() const {
    return m_pDocEnvironment->GetXMLDoc();
  }

  CXFA_FFDocView* CreateDocView();
  CXFA_Document* GetXFADoc() const { return m_pDocument; }
  CXFA_FFApp* GetApp() const { return m_pApp.Get(); }
  CPDF_Document* GetPDFDoc() const { return m_pPDFDoc.Get(); }
  CXFA_FFDocView* GetDocView(CXFA_LayoutProcessor* pLayout);
  CXFA_FFDocView* GetDocView();
  RetainPtr<CFX_DIBitmap> GetPDFNamedImage(WideStringView wsName,
                                           int32_t& iImageXDpi,
                                           int32_t& iImageYDpi);
  CFGAS_PDFFontMgr* GetPDFFontMgr() const { return m_pPDFFontMgr.get(); }

  bool SavePackage(CXFA_Node* pNode,
                   const RetainPtr<IFX_SeekableStream>& pFile);

 private:
  CXFA_FFDoc(CXFA_FFApp* pApp,
             IXFA_DocEnvironment* pDocEnvironment,
             CPDF_Document* pPDFDoc,
             cppgc::Heap* pHeap);
  bool BuildDoc(CFX_XMLDocument* pXML);

  UnownedPtr<IXFA_DocEnvironment> const m_pDocEnvironment;
  UnownedPtr<CXFA_FFApp> const m_pApp;
  UnownedPtr<CPDF_Document> const m_pPDFDoc;
  UnownedPtr<cppgc::Heap> const m_pHeap;
  UnownedPtr<CFX_XMLDocument> m_pXMLDoc;
  cppgc::Member<CXFA_FFNotify> m_pNotify;
  cppgc::Member<CXFA_Document> m_pDocument;
  cppgc::Member<CXFA_FFDocView> m_DocView;
  std::unique_ptr<CFGAS_PDFFontMgr> m_pPDFFontMgr;
  std::map<uint32_t, FX_IMAGEDIB_AND_DPI> m_HashToDibDpiMap;
  FormType m_FormType = FormType::kXFAForeground;
};

#endif  // XFA_FXFA_CXFA_FFDOC_H_
