// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <iostream>
#include <list>
#include <string>
#include <vector>

#include "public/fpdf_formfill.h"
#include "testing/fuzzers/pdfium_fuzzer_helper.h"

class PDFiumXFAFuzzer : public PDFiumFuzzerHelper {
 public:
  PDFiumXFAFuzzer() = default;
  ~PDFiumXFAFuzzer() override = default;

  int GetFormCallbackVersion() const override { return 2; }

  // Return false if XFA doesn't load as otherwise we're duplicating the work
  // done by the non-xfa fuzzer.
  bool OnFormFillEnvLoaded(FPDF_DOCUMENT doc) override {
    int form_type = FPDF_GetFormType(doc);
    if (form_type != FORMTYPE_XFA_FULL && form_type != FORMTYPE_XFA_FOREGROUND)
      return false;
    return FPDF_LoadXFA(doc);
  }
};

// Possible names of an XFA script function
std::string GenXfaScriptFuncName(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_script_funcs = {
      "Abs",          "Avg",          "Ceil",     "Count",       "Floor",
      "Max",          "Min",          "Mod",      "Round",       "Sum",
      "Date",         "Date2Num",     "DateFmt",  "IsoDate2Num", "IsoTime2Num",
      "LocalDateFmt", "LocalTimeFmt", "Num2Date", "Num2GMTime",  "Num2Time",
      "Time",         "Time2Num",     "TimeFmt",  "Apr",         "Cterm",
      "FV",           "Ipmt",         "NPV",      "Pmt",         "PPmt",
      "PV",           "Rate",         "Term",     "Choose",      "Exists",
      "HasValue",     "Oneof",        "Within",   "If",          "Eval",
      "Translate",    "Ref",          "UnitType", "UnitValue",   "At",
      "Concat",       "Decode",       "Encode",   "Format",      "Left",
      "Len",          "Lower",        "Ltrim",    "Parse",       "Replace",
      "Right",        "Rtrim",        "Space",    "Str",         "Stuff",
      "Substr",       "Uuid",         "Upper",    "WordNum",     "Get",
      "Post",         "Put",
  };

  size_t elemSelector = data_provider->ConsumeIntegralInRange<size_t>(
      0, xfa_script_funcs.size() - 1);
  std::string val = xfa_script_funcs[elemSelector];
  return val;
}

// Possible arguments to a XFA script function
std::string GenXfaScriptParam(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_func_params = {
      "&amp;|",
      "HTML",
      "123124",
      "<br>",
      "<html>",
      "1.2131",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "-1",
      "2009-06-01T13:45:30",
      "2009-06-15T13:45:30.5275000",
      "2009-06-15T13:45:30-07:00",
      "2009-06-15T01:45:30",
      "04/13/2019",
      "lkdjfglsdkfgj",
      "xml",
      "html",
      "json",
      "xhtml",
      "Str",
      "Space",
      "XML&quot;",
      "&quot;",
      "2 + 3 + 9",
      "3 -9",
      "%123",
      "3 * 1",
      " 2 < 3 + 1",
      "5 < 5",
      "$",
      "Amount[*]",
      "[1,2,3]",
      "[1,2,3][0]",
      "name[0]",
      "name[*].numAmount",
      "1",
      "2",
      "3",
      "99",
      "99999999999",
      "9999999",
      "123342123",
      "-99",
      "1024",
      "-0",
      "es_ES",
      "de_DE",
      "HH:MM:SS",
      "13:13:13 GMT",
      "13:13:13",
      "20000201",
      "19960315T20:20:20",
      ".05",
      "A",
      "B",
      "C",
      "10 * a + 9",
      "10 * 10 * 10 * 9 * 123",
      "name1",
      "name2",
      "name3",
      "name4",
      " 1 | 0",
      "1 and 2",
      "1 and 1",
      "url",
      "&AElig;&Aacute;&Acirc;&Aacute;",
      "~!@#$%^&amp;*()_+",
      "<a><b></b></a>",
      "&Acirc;",
      "&apos",
      "ÁÂÃÄÅÆ",
      "jan",
      "feb",
      "mar",
      "apr",
      "january",
      "febuary",
      "march",
      "april",
  };

  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, xfa_func_params.size() - 1);
  std::string xfa_string = xfa_func_params[elem_selector];

  // Maybe add quotation
  if (data_provider->ConsumeIntegralInRange<uint32_t>(0, 100) < 20) {
    xfa_string = "\"" + xfa_string + "\"";
  }

  return xfa_string;
}

// Possible XFA tags
std::string GenXfaTag(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_elem_tags = {
      "template",
      "validate",
      "subform",
      "config",
      "acrobat",
      "textedit",
      "present",
      "ps",
      "to",
      "ui",
      "recordSet",
      "subsetBelow",
      "subformSet",
      "adobeExtensionLevel",
      "typeface",
      "break",
      "fontInfo",
      "numberPattern",
      "dynamicRender",
      "printScaling",
      "checkButton",
      "datePatterns",
      "sourceSet",
      "amd",
      "arc",
      "day",
      "era",
      "jog",
      "log",
      "map",
      "mdp",
      "breakBefore",
      "oid",
      "pcl",
      "pdf",
      "ref",
      "uri",
      "xdc",
      "xdp",
      "xfa",
      "xsl",
      "zpl",
      "cache",
      "margin",
      "keyUsage",
      "exclude",
      "choiceList",
      "level",
      "labelPrinter",
      "calendarSymbols",
      "para",
      "part",
      "pdfa",
      "filter",
      "present",
      "pagination",
      "encoding",
      "event",
      "whitespace",
      "defaultUi",
      "dataModel",
      "barcode",
      "timePattern",
      "batchOutput",
      "enforce",
      "currencySymbols",
      "addSilentPrint",
      "rename",
      "operation",
      "typefaces",
      "subjectDNs",
      "issuers",
      "wsdlConnection",
      "debug",
      "delta",
      "eraNames",
      "modifyAnnots",
      "startNode",
      "button",
      "format",
      "border",
      "area",
      "hyphenation",
      "text",
      "time",
      "type",
      "overprint",
      "certificates",
      "encryptionMethods",
      "setProperty",
      "printerName",
      "startPage",
      "pageOffset",
      "dateTime",
      "comb",
      "pattern",
      "ifEmpty",
      "suppressBanner",
      "outputBin",
      "field",
      "agent",
      "outputXSL",
      "adjustData",
      "autoSave",
      "contentArea",
      "wsdlAddress",
      "solid",
      "dateTimeSymbols",
      "encryptionLevel",
      "edge",
      "stipple",
      "attributes",
      "versionControl",
      "meridiem",
      "exclGroup",
      "toolTip",
      "compress",
      "reason",
      "execute",
      "contentCopy",
      "dateTimeEdit",
      "config",
      "image",
      "#xHTML",
      "numberOfCopies",
      "behaviorOverride",
      "timeStamp",
      "month",
      "viewerPreferences",
      "scriptModel",
      "decimal",
      "subform",
      "select",
      "window",
      "localeSet",
      "handler",
      "presence",
      "record",
      "embed",
      "version",
      "command",
      "copies",
      "staple",
      "submitFormat",
      "boolean",
      "message",
      "output",
      "psMap",
      "excludeNS",
      "assist",
      "picture",
      "traversal",
      "silentPrint",
      "webClient",
      "producer",
      "corner",
      "msgId",
      "color",
      "keep",
      "query",
      "insert",
      "imageEdit",
      "validate",
      "digestMethods",
      "numberPatterns",
      "pageSet",
      "integer",
      "soapAddress",
      "equate",
      "formFieldFilling",
      "pageRange",
      "update",
      "connectString",
      "mode",
      "layout",
      "#xml",
      "xsdConnection",
      "traverse",
      "encodings",
      "template",
      "acrobat",
      "validationMessaging",
      "signing",
      "script",
      "addViewerPreferences",
      "alwaysEmbed",
      "passwordEdit",
      "numericEdit",
      "encryptionMethod",
      "change",
      "pageArea",
      "submitUrl",
      "oids",
      "signature",
      "ADBE_JSConsole",
      "caption",
      "relevant",
      "flipLabel",
      "exData",
      "dayNames",
      "soapAction",
      "defaultTypeface",
      "manifest",
      "overflow",
      "linear",
      "currencySymbol",
      "delete",
      "deltas",
      "digestMethod",
      "instanceManager",
      "equateRange",
      "medium",
      "textEdit",
      "templateCache",
      "compressObjectStream",
      "dataValue",
      "accessibleContent",
      "includeXDPContent",
      "xmlConnection",
      "validateApprovalSignatures",
      "signData",
      "packets",
      "datePattern",
      "duplexOption",
      "base",
      "bind",
      "compression",
      "user",
      "rectangle",
      "effectiveOutputPolicy",
      "ADBE_JSDebugger",
      "acrobat7",
      "interactive",
      "locale",
      "currentPage",
      "data",
      "date",
      "desc",
      "encrypt",
      "draw",
      "encryption",
      "meridiemNames",
      "messaging",
      "speak",
      "dataGroup",
      "common",
      "#text",
      "paginationOverride",
      "reasons",
      "signatureProperties",
      "threshold",
      "appearanceFilter",
      "fill",
      "font",
      "form",
      "mediumInfo",
      "certificate",
      "password",
      "runScripts",
      "trace",
      "float",
      "renderPolicy",
      "destination",
      "value",
      "bookend",
      "exObject",
      "openAction",
      "neverEmbed",
      "bindItems",
      "calculate",
      "print",
      "extras",
      "proto",
      "dSigData",
      "creator",
      "connect",
      "permissions",
      "connectionSet",
      "submit",
      "range",
      "linearized",
      "packet",
      "rootElement",
      "plaintextMetadata",
      "numberSymbols",
      "printHighQuality",
      "driver",
      "incrementalLoad",
      "subjectDN",
      "compressLogicalStructure",
      "incrementalMerge",
      "radial",
      "variables",
      "timePatterns",
      "effectiveInputPolicy",
      "nameAttr",
      "conformance",
      "transform",
      "lockDocument",
      "breakAfter",
      "line",
      "source",
      "occur",
      "pickTrayByPDFSize",
      "monthNames",
      "severity",
      "groupParent",
      "documentAssembly",
      "numberSymbol",
      "tagged",
      "items",
      "signaturePseudoModel",
      "eventPseudoModel",
      "hostPseudoModel",
      "layoutPseudoModel",
      "dataWindow",
      "treeList",
      "logPseudoModel",
      "list",
      "object",
  };

  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, xfa_elem_tags.size() - 1);
  std::string val = xfa_elem_tags[elem_selector];
  return val;
}

// Possible Xfa attributes values
std::string GenXfaTagValue(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_tag_vals = {
      "6.35mm",
      "203.2mm",
      "form1",
      "en_US",
      "Page1",
      "RadioList[0]",
      "8in",
      "tb",
      "5431.21mm",
      "123",
      "321",
      "middle",
      "0pt",
      "1pt",
      "255",
      "256",
      "0",
      "-1",
      "bold",
      "8pt",
      "Verdana",
      "italic",
      "consumeData",
      "subform_1",
      "name2",
      "name3",
      "name4",
      "name5",
      "application/x-javascript",
      "initialize",
      "bold",
      "Verdana",
      "22.1404mm",
  };

  size_t elem_selector =
      data_provider->ConsumeIntegralInRange<size_t>(0, xfa_tag_vals.size() - 1);
  std::string xfa_string = xfa_tag_vals[elem_selector];
  if (data_provider->ConsumeIntegralInRange(0, 100) < 20) {
    xfa_string = "\"" + xfa_string + "\"";
  }
  return xfa_string;
}

// possible XFA attributes
std::string GenXfaTagName(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_tag_names = {
      "id",
      "name",
      "layout",
      "mergeMode",
      "scriptTest",
      "startNew",
      "contentType",
      "marginRight",
      "tetIndent",
      "h",
      "w",
      "x",
      "y",
      "locale",
      "layout",
      "value",
      "size",
      "ref",
      "vAlign",
      "leftInset",
      "stock",
      "short",
      "long",
      "activity",
      "marginLeft",
      "marginRight",
      "spaceAbove",
      "spaceBelow",
      "baselineShift",
      "typeface",
      "weight",
      "timeStamp",
      "uuid",
      "activity",
  };
  std::string xfa_string = "";
  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, xfa_tag_names.size() - 1);
  xfa_string += xfa_tag_names[elem_selector];
  return xfa_string;
}

// Will create a simple XFA script that calls a single function.
std::string GenXfacript(FuzzedDataProvider* data_provider) {
  std::string xfa_string = GenXfaScriptFuncName(data_provider);
  xfa_string += "(";

  std::string p1 = GenXfaScriptParam(data_provider);
  std::string p2 = GenXfaScriptParam(data_provider);
  std::string p3 = GenXfaScriptParam(data_provider);

  int numParams = data_provider->ConsumeIntegralInRange(0, 3);
  // 0 case we do nothing.
  if (numParams == 1) {
    xfa_string += p1;
  }
  if (numParams == 2) {
    xfa_string += p1 + "," + p2;
  }
  if (numParams == 3) {
    xfa_string += p1 + "," + p2 + "," + p3;
  }
  xfa_string += ")";
  return xfa_string;
}

// Will create a single XFA attributes, with both lhs and rhs.
std::string getXfaElemAttributes(FuzzedDataProvider* data_provider) {
  // Generate a set of tags, and a set of values for the tags.
  std::string xfa_string =
      GenXfaTagName(data_provider) + " = " + GenXfaTagValue(data_provider);
  return xfa_string;
}

// Creates an XFA structure wrapped in <xdp tags.
std::string GenXfaTree(FuzzedDataProvider* data_provider) {
  std::string xfa_string = "<xdp xmlns=\"http://ns.adobe.com/xdp/\">";

  // One stack iteration
  int stack_iterations = data_provider->ConsumeIntegralInRange(1, 3);
  for (int si = 0; si < stack_iterations; si++) {
    std::list<std::string> xmlStack;
    int elemCount = data_provider->ConsumeIntegralInRange(1, 6);
    for (int i = 0; i < elemCount; i++) {
      xfa_string += "<";
      std::string tmp = GenXfaTag(data_provider);

      // in 30% of cases, add attributes
      std::string attributeString = "";
      if (data_provider->ConsumeIntegralInRange(1, 100) > 70) {
        int attributeCount = data_provider->ConsumeIntegralInRange(1, 5);
        for (int ac = 0; ac < attributeCount; ac++) {
          attributeString += getXfaElemAttributes(data_provider);
        }
      }
      xfa_string += attributeString;
      xfa_string += tmp + ">";

      // If needed, add a body to the tag
      if (tmp == "script") {
        xfa_string += GenXfacript(data_provider);
      }

      // Push the tag to the stack so we can close it when done
      xmlStack.push_front(tmp);
    }
    for (auto& s : xmlStack) {
      xfa_string += "</" + s + ">";
    }
  }
  xfa_string += "</xdp>";
  return xfa_string;
}

const char kSimplePdfTemplate[] = R"(%PDF-1.7
1 0 obj
<</Type /Catalog /Pages 2 0 R /AcroForm <</XFA 30 0 R>> /NeedsRendering true>>
endobj
2 0 obj
<</Type /Pages /Kids [3 0 R] /Count 1>>
endobj
3 0 obj
<</Type /Page /Parent 2 0 R /MediaBox [0 0 3 3]>>
endobj
30 0 obj
<</Length $1>>
stream
$2
endstream
endobj
trailer
<</Root 1 0 R /Size 31>>
%%EOF)";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  std::string xfa_string = GenXfaTree(&data_provider);

  // Add 1 for newline before endstream.
  std::string xfa_stream_len = std::to_string(xfa_string.size() + 1);

  // Compose the fuzzer
  std::string xfa_final_str = std::string(kSimplePdfTemplate);
  xfa_final_str.replace(xfa_final_str.find("$1"), 2, xfa_stream_len);
  xfa_final_str.replace(xfa_final_str.find("$2"), 2, xfa_string);

  if (getenv("PDFIUM_FUZZER_DUMP")) {
    for (unsigned long i = 0; i < xfa_final_str.size(); i++) {
      putc(xfa_final_str[i], stdout);
    }
  }

  PDFiumXFAFuzzer fuzzer;
  fuzzer.RenderPdf(reinterpret_cast<const char*>(xfa_final_str.c_str()),
                   xfa_final_str.size());
  return 0;
}
