// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

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
  static const char* xfa_script_funcs[] = {
      "Abs",       "Apr",        "At",           "Avg",          "Ceil",
      "Choose",    "Concat",     "Count",        "Cterm",        "Date",
      "Date2Num",  "DateFmt",    "Decode",       "Encode",       "Eval",
      "Exists",    "Floor",      "Format",       "FV",           "Get",
      "HasValue",  "If",         "Ipmt",         "IsoDate2Num",  "IsoTime2Num",
      "Left",      "Len",        "LocalDateFmt", "LocalTimeFmt", "Lower",
      "Ltrim",     "Max",        "Min",          "Mod",          "NPV",
      "Num2Date",  "Num2GMTime", "Num2Time",     "Oneof",        "Parse",
      "Pmt",       "Post",       "PPmt",         "Put",          "PV",
      "Rate",      "Ref",        "Replace",      "Right",        "Round",
      "Rtrim",     "Space",      "Str",          "Stuff",        "Substr",
      "Sum",       "Term",       "Time",         "Time2Num",     "TimeFmt",
      "Translate", "UnitType",   "UnitValue",    "Upper",        "Uuid",
      "Within",    "WordNum",
  };

  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, sizeof(xfa_script_funcs) / sizeof(xfa_script_funcs[0]) - 1);
  return xfa_script_funcs[elem_selector];
}

// Possible arguments to a XFA script function
std::string GenXfaScriptParam(FuzzedDataProvider* data_provider) {
  static const char* xfa_func_params[] = {
      "$",
      "-0",
      "04/13/2019",
      ".05",
      "-1",
      "1",
      " 1 | 0",
      "10 * 10 * 10 * 9 * 123",
      "1024",
      "10 * a + 9",
      "1.2131",
      "[1,2,3]",
      "%123",
      "[1,2,3][0]",
      "123124",
      "123342123",
      "13:13:13",
      "13:13:13 GMT",
      "19960315T20:20:20",
      "1 and 1",
      "1 and 2",
      "2",
      "20000201",
      "2009-06-01T13:45:30",
      "2009-06-15T01:45:30",
      "2009-06-15T13:45:30-07:00",
      "2009-06-15T13:45:30.5275000",
      " 2 < 3 + 1",
      "2 + 3 + 9",
      "3",
      "3 * 1",
      "3 -9",
      "5 < 5",
      "-99",
      "99",
      "9999999",
      "99999999999",
      "A",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "ÁÂÃÄÅÆ",
      "<a><b></b></a>",
      "&Acirc;",
      "&AElig;&Aacute;&Acirc;&Aacute;",
      "Amount[*]",
      "~!@#$%^&amp;*()_+",
      "&amp;|",
      "&apos",
      "apr",
      "april",
      "B",
      "<br>",
      "C",
      "de_DE",
      "es_ES",
      "feb",
      "febuary",
      "HH:MM:SS",
      "<html>",
      "html",
      "HTML",
      "jan",
      "january",
      "json",
      "lkdjfglsdkfgj",
      "mar",
      "march",
      "name[0]",
      "name1",
      "name2",
      "name3",
      "name4",
      "name[*].numAmount",
      "&quot;",
      "Space",
      "Str",
      "url",
      "xhtml",
      "xml",
      "XML&quot;",
  };

  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, sizeof(xfa_func_params) / sizeof(xfa_func_params[0]));
  std::string xfa_string = xfa_func_params[elem_selector];

  // Maybe add quotation
  if (data_provider->ConsumeIntegralInRange<uint32_t>(0, 100) < 20) {
    xfa_string = "\"" + xfa_string + "\"";
  }
  return xfa_string;
}

// Possible XFA tags
std::string GenXfaTag(FuzzedDataProvider* data_provider) {
  static const char* xfa_elem_tags[] = {
      "accessibleContent",
      "acrobat",
      "acrobat",
      "acrobat7",
      "ADBE_JSConsole",
      "ADBE_JSDebugger",
      "addSilentPrint",
      "addViewerPreferences",
      "adjustData",
      "adobeExtensionLevel",
      "agent",
      "alwaysEmbed",
      "amd",
      "appearanceFilter",
      "arc",
      "area",
      "assist",
      "attributes",
      "autoSave",
      "barcode",
      "base",
      "batchOutput",
      "behaviorOverride",
      "bind",
      "bindItems",
      "bookend",
      "boolean",
      "border",
      "break",
      "breakAfter",
      "breakBefore",
      "button",
      "cache",
      "calculate",
      "calendarSymbols",
      "caption",
      "certificate",
      "certificates",
      "change",
      "checkButton",
      "choiceList",
      "color",
      "comb",
      "command",
      "common",
      "compress",
      "compression",
      "compressLogicalStructure",
      "compressObjectStream",
      "config",
      "config",
      "conformance",
      "connect",
      "connectionSet",
      "connectString",
      "contentArea",
      "contentCopy",
      "copies",
      "corner",
      "creator",
      "currencySymbol",
      "currencySymbols",
      "currentPage",
      "data",
      "dataGroup",
      "dataModel",
      "dataValue",
      "dataWindow",
      "date",
      "datePattern",
      "datePatterns",
      "dateTime",
      "dateTimeEdit",
      "dateTimeSymbols",
      "day",
      "dayNames",
      "debug",
      "decimal",
      "defaultTypeface",
      "defaultUi",
      "delete",
      "delta",
      "deltas",
      "desc",
      "destination",
      "digestMethod",
      "digestMethods",
      "documentAssembly",
      "draw",
      "driver",
      "dSigData",
      "duplexOption",
      "dynamicRender",
      "edge",
      "effectiveInputPolicy",
      "effectiveOutputPolicy",
      "embed",
      "encoding",
      "encodings",
      "encrypt",
      "encryption",
      "encryptionLevel",
      "encryptionMethod",
      "encryptionMethods",
      "enforce",
      "equate",
      "equateRange",
      "era",
      "eraNames",
      "event",
      "eventPseudoModel",
      "exclGroup",
      "exclude",
      "excludeNS",
      "exData",
      "execute",
      "exObject",
      "extras",
      "field",
      "fill",
      "filter",
      "flipLabel",
      "float",
      "font",
      "fontInfo",
      "form",
      "format",
      "formFieldFilling",
      "groupParent",
      "handler",
      "hostPseudoModel",
      "hyphenation",
      "ifEmpty",
      "image",
      "imageEdit",
      "includeXDPContent",
      "incrementalLoad",
      "incrementalMerge",
      "insert",
      "instanceManager",
      "integer",
      "interactive",
      "issuers",
      "items",
      "jog",
      "keep",
      "keyUsage",
      "labelPrinter",
      "layout",
      "layoutPseudoModel",
      "level",
      "line",
      "linear",
      "linearized",
      "list",
      "locale",
      "localeSet",
      "lockDocument",
      "log",
      "logPseudoModel",
      "manifest",
      "map",
      "margin",
      "mdp",
      "medium",
      "mediumInfo",
      "meridiem",
      "meridiemNames",
      "message",
      "messaging",
      "mode",
      "modifyAnnots",
      "month",
      "monthNames",
      "msgId",
      "nameAttr",
      "neverEmbed",
      "numberOfCopies",
      "numberPattern",
      "numberPatterns",
      "numberSymbol",
      "numberSymbols",
      "numericEdit",
      "object",
      "occur",
      "oid",
      "oids",
      "openAction",
      "operation",
      "output",
      "outputBin",
      "outputXSL",
      "overflow",
      "overprint",
      "packet",
      "packets",
      "pageArea",
      "pageOffset",
      "pageRange",
      "pageSet",
      "pagination",
      "paginationOverride",
      "para",
      "part",
      "password",
      "passwordEdit",
      "pattern",
      "pcl",
      "pdf",
      "pdfa",
      "permissions",
      "pickTrayByPDFSize",
      "picture",
      "plaintextMetadata",
      "presence",
      "present",
      "present",
      "print",
      "printerName",
      "printHighQuality",
      "printScaling",
      "producer",
      "proto",
      "ps",
      "psMap",
      "query",
      "radial",
      "range",
      "reason",
      "reasons",
      "record",
      "recordSet",
      "rectangle",
      "ref",
      "relevant",
      "rename",
      "renderPolicy",
      "rootElement",
      "runScripts",
      "script",
      "scriptModel",
      "select",
      "setProperty",
      "severity",
      "signature",
      "signatureProperties",
      "signaturePseudoModel",
      "signData",
      "signing",
      "silentPrint",
      "soapAction",
      "soapAddress",
      "solid",
      "source",
      "sourceSet",
      "speak",
      "staple",
      "startNode",
      "startPage",
      "stipple",
      "subform",
      "subform",
      "subformSet",
      "subjectDN",
      "subjectDNs",
      "submit",
      "submitFormat",
      "submitUrl",
      "subsetBelow",
      "suppressBanner",
      "tagged",
      "template",
      "template",
      "templateCache",
      "#text",
      "text",
      "textedit",
      "textEdit",
      "threshold",
      "time",
      "timePattern",
      "timePatterns",
      "timeStamp",
      "to",
      "toolTip",
      "trace",
      "transform",
      "traversal",
      "traverse",
      "treeList",
      "type",
      "typeface",
      "typefaces",
      "ui",
      "update",
      "uri",
      "user",
      "validate",
      "validate",
      "validateApprovalSignatures",
      "validationMessaging",
      "value",
      "variables",
      "version",
      "versionControl",
      "viewerPreferences",
      "webClient",
      "whitespace",
      "window",
      "wsdlAddress",
      "wsdlConnection",
      "xdc",
      "xdp",
      "xfa",
      "#xHTML",
      "#xml",
      "xmlConnection",
      "xsdConnection",
      "xsl",
      "zpl",
  };

  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, sizeof(xfa_elem_tags) / sizeof(xfa_elem_tags[0]) - 1);
  return xfa_elem_tags[elem_selector];
}

// Possible Xfa attributes values
std::string GenXfaTagValue(FuzzedDataProvider* data_provider) {
  std::vector<std::string> xfa_tag_vals = {
      "0",         "0pt",          "-1",
      "123",       "1pt",          "203.2mm",
      "22.1404mm", "255",          "256",
      "321",       "5431.21mm",    "6.35mm",
      "8in",       "8pt",          "application/x-javascript",
      "bold",      "bold",         "consumeData",
      "en_US",     "form1",        "initialize",
      "italic",    "middle",       "name2",
      "name3",     "name4",        "name5",
      "Page1",     "RadioList[0]", "subform_1",
      "tb",        "Verdana",      "Verdana",
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
      "activity",    "activity",    "baselineShift",
      "contentType", "h",           "id",
      "layout",      "layout",      "leftInset",
      "locale",      "long",        "marginLeft",
      "marginRight", "marginRight", "mergeMode",
      "name",        "ref",         "scriptTest",
      "short",       "size",        "spaceAbove",
      "spaceBelow",  "startNew",    "stock",
      "tetIndent",   "timeStamp",   "typeface",
      "uuid",        "vAlign",      "value",
      "w",           "weight",      "x",
      "y",
  };
  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, xfa_tag_names.size() - 1);
  return xfa_tag_names[elem_selector];
}

// Will create a simple XFA script that calls a single function.
std::string GenXfacript(FuzzedDataProvider* data_provider) {
  std::string xfa_string = GenXfaScriptFuncName(data_provider);
  xfa_string += "(";

  int numParams = data_provider->ConsumeIntegralInRange(0, 3);
  // 0 case we do nothing.
  if (numParams == 1) {
    xfa_string += GenXfaScriptParam(data_provider);
  }
  if (numParams == 2) {
    xfa_string += GenXfaScriptParam(data_provider);
    xfa_string += ",";
    xfa_string += GenXfaScriptParam(data_provider);
  }
  if (numParams == 3) {
    xfa_string += GenXfaScriptParam(data_provider);
    xfa_string += ",";
    xfa_string += GenXfaScriptParam(data_provider);
    xfa_string += ",";
    xfa_string += GenXfaScriptParam(data_provider);
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
    int elem_count = data_provider->ConsumeIntegralInRange(1, 6);
    std::vector<std::string> xml_stack;
    xml_stack.reserve(elem_count);
    for (int i = 0; i < elem_count; i++) {
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
      xml_stack.push_back(tmp);
    }
    for (int i = elem_count - 1; i >= 0; i--) {
      xfa_string += "</" + xml_stack[i] + ">";
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
    for (size_t i = 0; i < xfa_final_str.size(); i++) {
      putc(xfa_final_str[i], stdout);
    }
  }

  PDFiumXFAFuzzer fuzzer;
  fuzzer.RenderPdf(xfa_final_str.c_str(), xfa_final_str.size());
  return 0;
}
