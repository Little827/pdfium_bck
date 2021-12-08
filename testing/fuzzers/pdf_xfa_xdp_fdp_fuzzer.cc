// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <string>

#include "public/fpdf_formfill.h"
#include "testing/fuzzers/pdf_fuzzer_templates.h"
#include "testing/fuzzers/pdfium_fuzzer_helper.h"
#include "third_party/base/containers/adapters.h"
#include "third_party/base/cxx17_backports.h"

class PDFiumXDPFuzzer : public PDFiumFuzzerHelper {
 public:
  PDFiumXDPFuzzer() = default;
  ~PDFiumXDPFuzzer() override = default;

  int GetFormCallbackVersion() const override { return 2; }

  bool OnFormFillEnvLoaded(FPDF_DOCUMENT doc) override {
    int form_type = FPDF_GetFormType(doc);
    if (form_type != FORMTYPE_XFA_FULL && form_type != FORMTYPE_XFA_FOREGROUND)
      return false;
    return FPDF_LoadXFA(doc);
  }
};

std::string CreateObject(std::string num, std::string body) {
  std::string obj_template = R""($1 0 obj
<</Length $2>>
stream
$3
endstream
endobj
)"";

  obj_template.replace(obj_template.find("$1"), 2, num);
  obj_template.replace(obj_template.find("$2"), 2,
                       std::to_string(body.size() + 1));
  obj_template.replace(obj_template.find("$3"), 2, body);

  return obj_template;
}

std::string GenXDPTagBody(std::string tag_name,
                          FuzzedDataProvider* data_provider) {
  std::string tag_content = data_provider->ConsumeRandomLengthString();

  if (tag_name == "config") {
    return R""(<xfa:config xmlns:xfa="http://www.xfa.org/schema/xci/3.1/">)"" +
           tag_content + "</xfa:config>";
  } else if (tag_name == "template") {
    return R""(<template xmlns="http://www.xfa.org/schema/xfa-template/2.6/">)"" +
           tag_content + "</template>)";
  } else if (tag_name == "sourceSet") {
    return R""(<sourceSet xmlns="http://www.xfa.org/schema/xfa-source-set/2.7/">)"" +
           tag_content + "</sourceSet>)";
  } else if (tag_name == "localeSet") {
    return R""(<localeSet xmlns="http://www.xfa.org/schema/xfa-locale-set/2.7/">)"" +
           tag_content + "</localeSet>)";
  } else if (tag_name == "dataSet") {
    return R""(<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">)"" +
           tag_content + "</xfa:datasets>";
  } else if (tag_name == "connectionSet") {
    return R""(<connectionSet xmlns="http://www.xfa.org/schema/xfa-connection-set/2.8/">)"" +
           tag_content + "</connectionSet>";
  } else if (tag_name == "xdc") {
    return R""(<xsl:xdc xmlns:xdc="http://www.xfa.org/schema/xdc/1.0/">)"" +
           tag_content + "</xsl:xdc>";
  } else if (tag_name == "signature") {
    return R""(<signature xmlns="http://www.w3.org/2000/09/xmldsig#">)"" +
           tag_content + "</signature>";
  } else if (tag_name == "stylesheet") {
    return R""(<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" id="identifier">)"" +
           tag_content + "</stylesheet>";
  } else if (tag_name == "xfdf") {
    return R""(<xfdf xmlns="http://ns.adobe.com/xfdf/" xml:space="preserve">)"" +
           tag_content + "</xfdf>";
  } else if (tag_name == "xmpmeta") {
    return R""(<xmpmeta xmlns="http://ns.adobe.com/xmpmeta/" xml:space="preserve">)"" +
           tag_content + "</xmpmeta>";
  }
  return "";
}

std::string GenXDPTag(FuzzedDataProvider* data_provider) {
  static const char* const kXDPTags[] = {
      "config",     "template",      "sourceSet", "localeSet",
      "dataSet",    "connectionSet", "xdc",       "signature",
      "stylesheet", "xfdf",          "xmpmeta",
  };
  size_t elem_selector = data_provider->ConsumeIntegralInRange<size_t>(
      0, pdfium::size(kXDPTags) - 1);
  return kXDPTags[elem_selector];
}

std::string GenXDPPdfFile(FuzzedDataProvider* data_provider) {
  std::string xfa_string = kSimpleXDPPdfTemplate;

  std::string tag1 = GenXDPTag(data_provider);
  std::string tag2 = GenXDPTag(data_provider);
  std::string tag3 = GenXDPTag(data_provider);
  xfa_string.replace(xfa_string.find("$1"), 2, tag1);
  xfa_string.replace(xfa_string.find("$2"), 2, tag2);
  xfa_string.replace(xfa_string.find("$3"), 2, tag3);

  // preamble
  std::string preamble =
      R""(<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/" timeStamp="2021-12-14T14:14:14Z" uuid="11111111-1ab1-11b1-aa1a-1aaaaaaa11a1">)"";
  std::string obj5 = CreateObject("5", preamble);

  std::string obj6 = CreateObject("6", GenXDPTagBody(tag1, data_provider));
  std::string obj7 = CreateObject("7", GenXDPTagBody(tag2, data_provider));
  std::string obj8 = CreateObject("8", GenXDPTagBody(tag3, data_provider));

  // postamble
  std::string obj9 = CreateObject("9", "</xdp:xdp>");

  // Create the xref table by first calculating offsets and then appending
  // strings.
  size_t xref_0 = 0;
  size_t xref_1 = xref_0 + 15;
  size_t xref_2 = xref_1 + 150;
  size_t xref_3 = xref_2 + 115 + tag1.size() + tag2.size() + tag3.size();
  size_t xref_4 = xref_3 + 55;
  size_t xref_5 = xref_4 + 69;
  size_t xref_6 = xref_5 + obj5.size();
  size_t xref_7 = xref_6 + obj6.size();
  size_t xref_8 = xref_7 + obj7.size();
  size_t xref_9 = xref_8 + obj8.size();
  size_t xref_start = xref_9 + obj9.size();

  std::string xref = R""(xref
0 10
)"";

  xref += std::string(10 - std::to_string(xref_0).size(), '0') +
          std::to_string(xref_0) + "\n";
  xref += std::string(10 - std::to_string(xref_1).size(), '0') +
          std::to_string(xref_1) + "\n";
  xref += std::string(10 - std::to_string(xref_2).size(), '0') +
          std::to_string(xref_2) + "\n";
  xref += std::string(10 - std::to_string(xref_3).size(), '0') +
          std::to_string(xref_3) + "\n";
  xref += std::string(10 - std::to_string(xref_4).size(), '0') +
          std::to_string(xref_4) + "\n";
  xref += std::string(10 - std::to_string(xref_5).size(), '0') +
          std::to_string(xref_5) + "\n";
  xref += std::string(10 - std::to_string(xref_6).size(), '0') +
          std::to_string(xref_6) + "\n";
  xref += std::string(10 - std::to_string(xref_7).size(), '0') +
          std::to_string(xref_7) + "\n";
  xref += std::string(10 - std::to_string(xref_8).size(), '0') +
          std::to_string(xref_8) + "\n";
  xref += std::string(10 - std::to_string(xref_9).size(), '0') +
          std::to_string(xref_9) + "\n";

  std::string footer = R""(trailer
<</Root 1 0 R /Size 10>>
startxref
$1
%%EOF)"";
  footer.replace(footer.find("$1"), 2, std::to_string(xref_start));

  // Return all the strings combined, which together makes up an entire PDF
  // file>
  return xfa_string + preamble + obj5 + obj6 + obj7 + obj8 + obj9 + xref +
         footer;
}

bool IsValidForFuzzing(const uint8_t* data, size_t size) {
  if (size > 2048) {
    return false;
  }
  const char* ptr = reinterpret_cast<const char*>(data);
  for (size_t i = 0; i < size; i++) {
    if (!std::isspace(ptr[i]) && !std::isprint(ptr[i])) {
      return false;
    }
  }
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!IsValidForFuzzing(data, size)) {
    return 0;
  }

  FuzzedDataProvider data_provider(data, size);
  std::string xfa_final_str = GenXDPPdfFile(&data_provider);

  PDFiumXDPFuzzer fuzzer;
  fuzzer.RenderPdf(xfa_final_str.c_str(), xfa_final_str.size());
  return 0;
}
