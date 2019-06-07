// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_javascript.h"

#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_name.h"
#include "core/fpdfapi/parser/cpdf_string.h"
#include "core/fpdfdoc/cpdf_nametree.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "third_party/base/ptr_util.h"

struct CPDF_JavaScript {
  WideString name;
  WideString script;
};

FPDF_EXPORT int FPDF_CALLCONV
FPDFDoc_GetJavaScriptCount(FPDF_DOCUMENT document) {
  CPDF_Document* doc = CPDFDocumentFromFPDFDocument(document);
  return doc ? CPDF_NameTree(doc, "JavaScript").GetCount() : -1;
}

FPDF_EXPORT FPDF_JAVASCRIPT FPDF_CALLCONV
FPDFDoc_GetJavaScript(FPDF_DOCUMENT document, int index) {
  CPDF_Document* doc = CPDFDocumentFromFPDFDocument(document);
  if (!doc || index < 0)
    return nullptr;

  CPDF_NameTree name_tree(doc, "JavaScript");
  if (static_cast<size_t>(index) >= name_tree.GetCount())
    return nullptr;

  WideString name;
  CPDF_Dictionary* obj =
      ToDictionary(name_tree.LookupValueAndName(index, &name));
  if (!obj)
    return nullptr;

  // Validate |obj|. Type is optional, but must be valid if present.
  const CPDF_Object* obj_type = obj->GetObjectFor("Type");
  if (obj_type) {
    const CPDF_Name* obj_type_name = obj_type->AsName();
    if (!obj_type_name || obj_type_name->GetString() != "Action")
      return nullptr;
  }

  // Sub-type is required.
  const CPDF_Name* action_type = ToName(obj->GetObjectFor("S"));
  if (!action_type || action_type->GetString() != "JavaScript")
    return nullptr;

  const CPDF_Object* script = obj->GetDirectObjectFor("JS");
  if (!script || (script->GetType() != CPDF_Object::kStream &&
                  script->GetType() != CPDF_Object::kString)) {
    return nullptr;
  }

  auto js = pdfium::MakeUnique<CPDF_JavaScript>();
  js->name = name;
  js->script = script->GetUnicodeText();
  return FPDFJavaScriptFromCPDFJavaScript(js.release());
}

FPDF_EXPORT void FPDF_CALLCONV
FPDFDoc_CloseJavaScript(FPDF_JAVASCRIPT javascript) {
  delete CPDFJavaScriptFromFPDFJavaScript(javascript);
}

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFJavaScript_GetName(FPDF_JAVASCRIPT javascript,
                       FPDF_WCHAR* buffer,
                       unsigned long buflen) {
  CPDF_JavaScript* js = CPDFJavaScriptFromFPDFJavaScript(javascript);
  if (!js)
    return 0;
  return Utf16EncodeMaybeCopyAndReturnLength(js->name, buffer, buflen);
}

FPDF_EXPORT unsigned long FPDF_CALLCONV
FPDFJavaScript_GetScript(FPDF_JAVASCRIPT javascript,
                         FPDF_WCHAR* buffer,
                         unsigned long buflen) {
  CPDF_JavaScript* js = CPDFJavaScriptFromFPDFJavaScript(javascript);
  if (!js)
    return 0;
  return Utf16EncodeMaybeCopyAndReturnLength(js->script, buffer, buflen);
}
