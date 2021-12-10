// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <string>
#include <vector>

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

std::string CreateObject(int obj_num, std::string body) {
  std::string obj_template = R""($1 0 obj
$2
endobj
)"";

  obj_template.replace(obj_template.find("$1"), 2, std::to_string(obj_num));
  obj_template.replace(obj_template.find("$2"), 2, body);
  return obj_template;
}

std::string CreateStreamObject(int obj_num, std::string body) {
  std::string obj_template = R""($1 0 obj
<</Length $2>>
stream
$3
endstream
endobj
)"";

  obj_template.replace(obj_template.find("$1"), 2, std::to_string(obj_num));
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
  }
  if (tag_name == "template") {
    return R""(<template xmlns="http://www.xfa.org/schema/xfa-template/2.6/">)"" +
           tag_content + "</template>)";
  }
  if (tag_name == "sourceSet") {
    return R""(<sourceSet xmlns="http://www.xfa.org/schema/xfa-source-set/2.7/">)"" +
           tag_content + "</sourceSet>)";
  }
  if (tag_name == "localeSet") {
    return R""(<localeSet xmlns="http://www.xfa.org/schema/xfa-locale-set/2.7/">)"" +
           tag_content + "</localeSet>)";
  }
  if (tag_name == "dataSet") {
    return R""(<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">)"" +
           tag_content + "</xfa:datasets>";
  }
  if (tag_name == "connectionSet") {
    return R""(<connectionSet xmlns="http://www.xfa.org/schema/xfa-connection-set/2.8/">)"" +
           tag_content + "</connectionSet>";
  }
  if (tag_name == "xdc") {
    return R""(<xsl:xdc xmlns:xdc="http://www.xfa.org/schema/xdc/1.0/">)"" +
           tag_content + "</xsl:xdc>";
  }
  if (tag_name == "signature") {
    return R""(<signature xmlns="http://www.w3.org/2000/09/xmldsig#">)"" +
           tag_content + "</signature>";
  }
  if (tag_name == "stylesheet") {
    return R""(<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" id="identifier">)"" +
           tag_content + "</stylesheet>";
  }
  if (tag_name == "xfdf") {
    return R""(<xfdf xmlns="http://ns.adobe.com/xfdf/" xml:space="preserve">)"" +
           tag_content + "</xfdf>";
  }
  if (tag_name == "xmpmeta") {
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
  return data_provider->PickValueInArray(kXDPTags);
}

std::string GenXrefEntry(size_t offset) {
  return std::string(10 - std::to_string(offset).size(), '0') +
         std::to_string(offset) + " 00000 n\n";
}

std::string GenXDPPdfFile(FuzzedDataProvider* data_provider) {
  std::vector<std::string> pdf_objects;
  std::string pdf_header =
      std::string(reinterpret_cast<const char*>(kSimplePdfHeader),
                  sizeof(kSimplePdfHeader));

  std::string obj1 = CreateObject(1, kSimpleAcroForm);
  pdf_objects.push_back(obj1);

  std::string obj2 = kSimpleXfaObjWrapper;
  std::string tag1 = GenXDPTag(data_provider);
  std::string tag2 = GenXDPTag(data_provider);
  std::string tag3 = GenXDPTag(data_provider);
  obj2.replace(obj2.find("$1"), 2, tag1);
  obj2.replace(obj2.find("$2"), 2, tag2);
  obj2.replace(obj2.find("$3"), 2, tag3);
  obj2 = CreateObject(2, obj2);
  pdf_objects.push_back(obj2);

  std::string obj3 = CreateObject(3, kSimplePagesObj);
  pdf_objects.push_back(obj3);

  std::string obj4 = CreateObject(4, kSimplePageObj);
  pdf_objects.push_back(obj4);

  // preamble
  std::string obj5 = CreateStreamObject(5, kSimplePreamble);
  pdf_objects.push_back(obj5);

  std::string obj6 = CreateStreamObject(6, GenXDPTagBody(tag1, data_provider));
  pdf_objects.push_back(obj6);
  std::string obj7 = CreateStreamObject(7, GenXDPTagBody(tag2, data_provider));
  pdf_objects.push_back(obj7);
  std::string obj8 = CreateStreamObject(8, GenXDPTagBody(tag3, data_provider));
  pdf_objects.push_back(obj8);

  // postamble
  std::string obj9 = CreateStreamObject(9, kSimplePostamble);
  pdf_objects.push_back(obj9);

  // Create the xref table
  std::string xref = R""(xref
0 10
0000000000 65535 f
)"";

  // Add xref entries
  size_t curr_offset = pdf_header.size();
  for (auto& ostr : pdf_objects) {
    xref += GenXrefEntry(curr_offset);
    curr_offset += ostr.size();
  }

  std::string footer = R""(trailer
<</Root 1 0 R /Size 10>>
startxref
$1
%%EOF)"";
  footer.replace(footer.find("$1"), 2, std::to_string(curr_offset));

  std::string pdf_core;
  for (auto& ostr : pdf_objects) {
    pdf_core += ostr;
  }
  // Return the full PDF
  return pdf_header + pdf_core + xref + footer;
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

#ifdef PDFIUM_FUZZER_DUMP
  for (size_t i = 0; i < xfa_final_str.size(); i++) {
    putc(xfa_final_str[i], stdout);
  }
#endif

  PDFiumXDPFuzzer fuzzer;
  fuzzer.RenderPdf(xfa_final_str.c_str(), xfa_final_str.size());
  return 0;
}
