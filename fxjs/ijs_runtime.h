// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_IJS_RUNTIME_H_
#define FXJS_IJS_RUNTIME_H_

#include <memory>

#include "core/fxcrt/cfx_timer.h"
#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/observed_ptr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "core/fxcrt/widestring.h"
#include "third_party/abseil-cpp/absl/types/optional.h"

class CJS_Runtime;
class IJS_EventContext;
class IPDF_Page;
class CPDFSDK_Annot;
class CPDFSDK_InteractiveForm;
class CPDFSDK_PageView;
class CPDF_Document;
typedef struct _FPDF_FORMFILLINFO FPDF_FORMFILLINFO;

// Owns the FJXS objects needed to actually execute JS, if possible. This
// virtual interface is backed by either an actual JS runtime, or a stub,
// when JS is not present.
class IJS_Runtime {
 public:
  struct JS_Error {
    int line;
    int column;
    WideString exception;

    JS_Error(int line, int column, const WideString& exception);
  };

  class ScopedEventContext {
   public:
    FX_STACK_ALLOCATED();

    explicit ScopedEventContext(IJS_Runtime* pRuntime);
    ~ScopedEventContext();

    IJS_EventContext* Get() const { return m_pContext.Get(); }
    IJS_EventContext* operator->() const { return m_pContext.Get(); }

   private:
    UnownedPtr<IJS_Runtime> const m_pRuntime;
    UnownedPtr<IJS_EventContext> m_pContext;
  };

  class FormFillEnvIface : virtual public Observable {
   public:
    virtual bool IsJSPlatformPresent() const = 0;
    virtual bool HasPermissions(uint32_t flags) const = 0;
    virtual bool GetChangeMark() const = 0;
    virtual void SetChangeMark() = 0;
    virtual void ClearChangeMark() = 0;
    virtual int GetPageCount() const = 0;
    virtual FPDF_FORMFILLINFO* GetFormFillInfo() const = 0;
    virtual CFX_Timer::HandlerIface* GetTimerHandler() = 0;
    virtual CPDFSDK_InteractiveForm*
    GetInteractiveForm() = 0;  // Creates if not present.
    virtual CPDF_Document* GetPDFDocument() const = 0;
#ifdef PDF_ENABLE_V8
    virtual CPDFSDK_PageView* GetCurrentView() = 0;
    virtual IPDF_Page* GetCurrentPage() const = 0;
    virtual WideString GetLanguage() const = 0;
    virtual WideString GetPlatform() const = 0;
    virtual int JS_appAlert(const WideString& Msg,
                            const WideString& Title,
                            int Type,
                            int Icon) = 0;
    virtual int JS_appResponse(const WideString& Question,
                               const WideString& Title,
                               const WideString& Default,
                               const WideString& cLabel,
                               bool bPassword,
                               pdfium::span<uint8_t> response) = 0;
    virtual void JS_appBeep(int nType) = 0;
    virtual void JS_docmailForm(pdfium::span<uint8_t> mailData,
                                bool bUI,
                                const WideString& To,
                                const WideString& Subject,
                                const WideString& CC,
                                const WideString& BCC,
                                const WideString& Msg) = 0;
    virtual void JS_docprint(bool bUI,
                             int nStart,
                             int nEnd,
                             bool bSilent,
                             bool bShrinkToFit,
                             bool bPrintAsImage,
                             bool bReverse,
                             bool bAnnotations) = 0;
    virtual WideString JS_docGetFilePath() = 0;
    virtual void JS_DocGotoPage(int nPageNum) = 0;
    virtual WideString JS_fieldBrowse() = 0;
#endif  // PDF_ENABLE_V8
    virtual bool KillFocusAnnot(/*Mask<FWL_EVENTFLAG>*/ int nFlags) = 0;
    virtual CPDFSDK_PageView* GetPageView(IPDF_Page* pUnderlyingPage) = 0;
    virtual CPDFSDK_PageView* GetPageViewAtIndex(int nIndex) = 0;
    virtual CPDFSDK_PageView* GetOrCreatePageView(
        IPDF_Page* pUnderlyingPage) = 0;
    virtual bool SetFocusAnnot(ObservedPtr<CPDFSDK_Annot>& pAnnot) = 0;
    virtual void DoGoToAction(int nPageIndex,
                              int zoomMode,
                              pdfium::span<float> fPosArray) = 0;
  };

  static void Initialize(unsigned int slot, void* isolate, void* platform);
  static void Destroy();
  static std::unique_ptr<IJS_Runtime> Create(FormFillEnvIface* pFormFillEnv);

  virtual ~IJS_Runtime();

  virtual CJS_Runtime* AsCJSRuntime() = 0;
  virtual IJS_EventContext* NewEventContext() = 0;
  virtual void ReleaseEventContext(IJS_EventContext* pContext) = 0;
  virtual FormFillEnvIface* GetFormFillEnv() const = 0;
  virtual absl::optional<JS_Error> ExecuteScript(const WideString& script) = 0;

 protected:
  IJS_Runtime() = default;
};

#endif  // FXJS_IJS_RUNTIME_H_
