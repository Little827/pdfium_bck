// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/parser/cpdf_parser.h"

#include <algorithm>
#include <utility>
#include <vector>

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_cross_ref_parser.h"
#include "core/fpdfapi/parser/cpdf_crypto_handler.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_linearized_header.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_object_stream.h"
#include "core/fpdfapi/parser/cpdf_read_validator.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "core/fpdfapi/parser/cpdf_security_handler.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "core/fpdfapi/parser/cpdf_stream_acc.h"
#include "core/fpdfapi/parser/cpdf_syntax_parser.h"
#include "core/fpdfapi/parser/fpdf_parser_utility.h"
#include "core/fxcrt/autorestorer.h"
#include "core/fxcrt/cfx_memorystream.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_safe_types.h"
#include "third_party/base/ptr_util.h"
#include "third_party/base/stl_util.h"

namespace {

// "%PDF-1.7\n"
constexpr FX_FILESIZE kPDFHeaderSize = 9;

class ObjectsHolderStub : public CPDF_Parser::ParsedObjectsHolder {
 public:
  ObjectsHolderStub() = default;
  ~ObjectsHolderStub() override = default;
  bool TryInit() override { return true; }
};

}  // namespace

CPDF_Parser::CPDF_Parser(ParsedObjectsHolder* holder)
    : m_pSyntax(pdfium::MakeUnique<CPDF_SyntaxParser>()),
      m_pObjectsHolder(holder),
      m_bHasParsed(false),
      m_bXRefStream(false),
      m_FileVersion(0),
      m_CrossRefTable(pdfium::MakeUnique<CPDF_CrossRefTable>()) {
  if (!holder) {
    m_pOwnedObjectsHolder = pdfium::MakeUnique<ObjectsHolderStub>();
    m_pObjectsHolder = m_pOwnedObjectsHolder.get();
  }
}

CPDF_Parser::CPDF_Parser() : CPDF_Parser(nullptr) {}

CPDF_Parser::~CPDF_Parser() {
  ReleaseEncryptHandler();
}

uint32_t CPDF_Parser::GetLastObjNum() const {
  const uint32_t size = m_CrossRefTable->GetSize();
  return size ? size - 1 : 0;
}

bool CPDF_Parser::IsValidObjectNumber(uint32_t objnum) const {
  return objnum <= GetLastObjNum();
}

FX_FILESIZE CPDF_Parser::GetObjectPositionOrZero(uint32_t objnum) const {
  const auto* info = m_CrossRefTable->GetObjectInfo(objnum);
  return (info && info->type == ObjectType::kNormal) ? info->pos : 0;
}

CPDF_Parser::ObjectType CPDF_Parser::GetObjectType(uint32_t objnum) const {
  ASSERT(IsValidObjectNumber(objnum));
  const auto* info = m_CrossRefTable->GetObjectInfo(objnum);
  return info ? info->type : ObjectType::kFree;
}

uint16_t CPDF_Parser::GetObjectGenNum(uint32_t objnum) const {
  ASSERT(IsValidObjectNumber(objnum));
  const auto* info = m_CrossRefTable->GetObjectInfo(objnum);
  return (info && info->type == ObjectType::kNormal) ? info->gennum : 0;
}

bool CPDF_Parser::IsObjectFreeOrNull(uint32_t objnum) const {
  switch (GetObjectType(objnum)) {
    case ObjectType::kFree:
    case ObjectType::kNull:
      return true;
    case ObjectType::kNotCompressed:
    case ObjectType::kCompressed:
      return false;
  }
  NOTREACHED();
  return false;
}

bool CPDF_Parser::IsObjectFree(uint32_t objnum) const {
  return GetObjectType(objnum) == ObjectType::kFree;
}

bool CPDF_Parser::InitSyntaxParser(
    const RetainPtr<CPDF_ReadValidator>& validator) {
  const int32_t header_offset = GetHeaderOffset(validator);
  if (header_offset == kInvalidHeaderOffset)
    return false;
  if (validator->GetSize() < header_offset + kPDFHeaderSize)
    return false;

  m_pSyntax->InitParserWithValidator(validator, header_offset);
  return ParseFileVersion();
}

bool CPDF_Parser::ParseFileVersion() {
  m_FileVersion = 0;
  uint8_t ch;
  if (!m_pSyntax->GetCharAt(5, ch))
    return false;

  if (std::isdigit(ch))
    m_FileVersion = FXSYS_DecimalCharToInt(static_cast<wchar_t>(ch)) * 10;

  if (!m_pSyntax->GetCharAt(7, ch))
    return false;

  if (std::isdigit(ch))
    m_FileVersion += FXSYS_DecimalCharToInt(static_cast<wchar_t>(ch));
  return true;
}

CPDF_Parser::Error CPDF_Parser::StartParse(
    const RetainPtr<IFX_SeekableReadStream>& pFileAccess,
    const char* password) {
  return StartParseWithValidator(
      pdfium::MakeRetain<CPDF_ReadValidator>(pFileAccess, nullptr), password);
}

CPDF_Parser::Error CPDF_Parser::StartParseWithValidator(
    const RetainPtr<CPDF_ReadValidator>& validator,
    const char* password) {
  if (!InitSyntaxParser(validator))
    return FORMAT_ERROR;

  SetPassword(password);
  return StartParseInternal();
}

CPDF_Parser::Error CPDF_Parser::StartParseInternal() {
  ASSERT(!m_bHasParsed);
  m_bHasParsed = true;
  m_bXRefStream = false;

  bool bXRefRebuilt = false;
  if (!ParseFileStructure()) {
    bXRefRebuilt = true;
    if (!RebuildCrossRef())
      return FORMAT_ERROR;
  }

  if (!bXRefRebuilt && !m_pLinearized) {
    const CPDF_Parser::Error ret = LoadPrevMainXRefTables();
    if (ret != SUCCESS) {
      bXRefRebuilt = true;
      if (!RebuildCrossRef())
        return FORMAT_ERROR;
    }
  }
  if (!bXRefRebuilt && !VerifyCrossRef()) {
    if (!RebuildCrossRef())
      return FORMAT_ERROR;

    bXRefRebuilt = true;
    m_LastXRefOffset = 0;
  }

  Error eRet = SetEncryptHandler();
  if (eRet != SUCCESS)
    return eRet;

  if (!GetRoot() || !m_pObjectsHolder->TryInit()) {
    if (bXRefRebuilt)
      return FORMAT_ERROR;

    ReleaseEncryptHandler();
    if (!RebuildCrossRef())
      return FORMAT_ERROR;

    eRet = SetEncryptHandler();
    if (eRet != SUCCESS)
      return eRet;

    m_pObjectsHolder->TryInit();
    if (!GetRoot())
      return FORMAT_ERROR;
  }
  if (GetRootObjNum() == CPDF_Object::kInvalidObjNum) {
    ReleaseEncryptHandler();
    if (!RebuildCrossRef() || GetRootObjNum() == CPDF_Object::kInvalidObjNum)
      return FORMAT_ERROR;

    eRet = SetEncryptHandler();
    if (eRet != SUCCESS)
      return eRet;
  }
  if (m_pSecurityHandler && !m_pSecurityHandler->IsMetadataEncrypted()) {
    CPDF_Reference* pMetadata =
        ToReference(GetRoot()->GetObjectFor("Metadata"));
    if (pMetadata)
      m_MetadataObjnum = pMetadata->GetRefObjNum();
  }
  return SUCCESS;
}

FX_FILESIZE CPDF_Parser::ParseStartXRef() {
  static constexpr char kStartXRefKeyword[] = "startxref";
  m_pSyntax->SetPos(m_pSyntax->GetDocumentSize() - strlen(kStartXRefKeyword));
  if (!m_pSyntax->BackwardsSearchToWord(kStartXRefKeyword, 4096))
    return 0;

  // Skip "startxref" keyword.
  m_pSyntax->GetKeyword();

  // Read XRef offset.
  bool bNumber;
  const ByteString xrefpos_str = m_pSyntax->GetNextWord(&bNumber);
  if (!bNumber || xrefpos_str.IsEmpty())
    return 0;

  const FX_SAFE_FILESIZE result = FXSYS_atoi64(xrefpos_str.c_str());
  if (!result.IsValid() || result.ValueOrDie() >= m_pSyntax->GetDocumentSize())
    return 0;

  return result.ValueOrDie();
}

CPDF_Parser::Error CPDF_Parser::SetEncryptHandler() {
  ReleaseEncryptHandler();
  if (!GetTrailer())
    return FORMAT_ERROR;

  const CPDF_Dictionary* pEncryptDict = GetEncryptDict();
  if (!pEncryptDict)
    return SUCCESS;

  if (pEncryptDict->GetStringFor("Filter") != "Standard")
    return HANDLER_ERROR;

  std::unique_ptr<CPDF_SecurityHandler> pSecurityHandler =
      pdfium::MakeUnique<CPDF_SecurityHandler>();
  if (!pSecurityHandler->OnInit(pEncryptDict, GetIDArray(), m_Password))
    return PASSWORD_ERROR;

  m_pSecurityHandler = std::move(pSecurityHandler);
  return SUCCESS;
}

void CPDF_Parser::ReleaseEncryptHandler() {
  m_pSecurityHandler.reset();
}

// Ideally, all the cross reference entries should be verified.
// In reality, we rarely see well-formed cross references don't match
// with the objects. crbug/602650 showed a case where object numbers
// in the cross reference table are all off by one.
bool CPDF_Parser::VerifyCrossRef() {
  if (!m_CrossRefTable || !m_CrossRefTable->trailer())
    return false;
  // For verification we can use any known object. The root object num is
  // suitable.
  uint32_t obj_num = GetRootObjNum();
  if (!obj_num)
    return false;

  const CPDF_CrossRefTable::ObjectInfo* info =
      GetCrossRefTable()->GetObjectInfo(obj_num);
  if (!info || info->type == CPDF_CrossRefTable::ObjectType::kFree)
    return false;

  if (info->type == CPDF_CrossRefTable::ObjectType::kCompressed) {
    obj_num = info->archive_obj_num;
    info = GetCrossRefTable()->GetObjectInfo(obj_num);
    if (!info || info->type != CPDF_CrossRefTable::ObjectType::kObjStream)
      return false;
  }

  const FX_FILESIZE SavedPos = m_pSyntax->GetPos();
  m_pSyntax->SetPos(info->pos);
  bool is_num = false;
  ByteString num_str = m_pSyntax->GetNextWord(&is_num);
  m_pSyntax->SetPos(SavedPos);
  if (!is_num || num_str.IsEmpty() || FXSYS_atoui(num_str.c_str()) != obj_num) {
    // If the object number read doesn't match the one stored,
    // something is wrong with the cross reference table.
    return false;
  }
  return true;
}

bool CPDF_Parser::RebuildCrossRef() {
  CPDF_CrossRefParser parser(m_pSyntax.get());
  std::unique_ptr<CPDF_CrossRefTable> cross_ref_table =
      parser.RebuildCrossRef();
  if (!cross_ref_table)
    return false;

  m_CrossRefTable = CPDF_CrossRefTable::MergeUp(std::move(m_CrossRefTable),
                                                std::move(cross_ref_table));
  return GetTrailer() && !m_CrossRefTable->objects_info().empty();
}

const CPDF_Array* CPDF_Parser::GetIDArray() const {
  return GetTrailer() ? GetTrailer()->GetArrayFor("ID") : nullptr;
}

CPDF_Dictionary* CPDF_Parser::GetRoot() const {
  CPDF_Object* obj =
      m_pObjectsHolder->GetOrParseIndirectObject(GetRootObjNum());
  return obj ? obj->GetDict() : nullptr;
}

const CPDF_Dictionary* CPDF_Parser::GetEncryptDict() const {
  if (!GetTrailer())
    return nullptr;

  const CPDF_Object* pEncryptObj = GetTrailer()->GetObjectFor("Encrypt");
  if (!pEncryptObj)
    return nullptr;

  if (pEncryptObj->IsDictionary())
    return ToDictionary(pEncryptObj);

  if (pEncryptObj->IsReference()) {
    return ToDictionary(m_pObjectsHolder->GetOrParseIndirectObject(
        pEncryptObj->AsReference()->GetRefObjNum()));
  }
  return nullptr;
}

const CPDF_Dictionary* CPDF_Parser::GetTrailer() const {
  return m_CrossRefTable->trailer();
}

std::unique_ptr<CPDF_Dictionary> CPDF_Parser::GetCombinedTrailer() const {
  return m_CrossRefTable->trailer()
             ? ToDictionary(m_CrossRefTable->trailer()->Clone())
             : std::unique_ptr<CPDF_Dictionary>();
}

uint32_t CPDF_Parser::GetInfoObjNum() const {
  const CPDF_Reference* pRef =
      ToReference(m_CrossRefTable->trailer()
                      ? m_CrossRefTable->trailer()->GetObjectFor("Info")
                      : nullptr);
  return pRef ? pRef->GetRefObjNum() : CPDF_Object::kInvalidObjNum;
}

uint32_t CPDF_Parser::GetRootObjNum() const {
  const CPDF_Reference* pRef =
      ToReference(m_CrossRefTable->trailer()
                      ? m_CrossRefTable->trailer()->GetObjectFor("Root")
                      : nullptr);
  return pRef ? pRef->GetRefObjNum() : CPDF_Object::kInvalidObjNum;
}

std::unique_ptr<CPDF_Object> CPDF_Parser::ParseIndirectObject(
    uint32_t objnum) {
  if (!IsValidObjectNumber(objnum))
    return nullptr;

  // Prevent circular parsing the same object.
  if (pdfium::ContainsKey(m_ParsingObjNums, objnum))
    return nullptr;

  pdfium::ScopedSetInsertion<uint32_t> local_insert(&m_ParsingObjNums, objnum);
  if (GetObjectType(objnum) == ObjectType::kNotCompressed) {
    FX_FILESIZE pos = GetObjectPositionOrZero(objnum);
    if (pos <= 0)
      return nullptr;
    return ParseIndirectObjectAt(pos, objnum);
  }
  if (GetObjectType(objnum) != ObjectType::kCompressed)
    return nullptr;

  const CPDF_ObjectStream* pObjStream =
      GetObjectStream(m_CrossRefTable->GetObjectInfo(objnum)->archive_obj_num);
  if (!pObjStream)
    return nullptr;

  return pObjStream->ParseObject(m_pObjectsHolder.Get(), objnum);
}

const CPDF_ObjectStream* CPDF_Parser::GetObjectStream(uint32_t object_number) {
  // Prevent circular parsing the same object.
  if (pdfium::ContainsKey(m_ParsingObjNums, object_number))
    return nullptr;

  pdfium::ScopedSetInsertion<uint32_t> local_insert(&m_ParsingObjNums,
                                                    object_number);

  auto it = m_ObjectStreamMap.find(object_number);
  if (it != m_ObjectStreamMap.end())
    return it->second.get();

  const auto* info = m_CrossRefTable->GetObjectInfo(object_number);
  if (!info || info->type != ObjectType::kObjStream)
    return nullptr;

  const FX_FILESIZE object_pos = info->pos;
  if (object_pos <= 0)
    return nullptr;

  std::unique_ptr<CPDF_Object> object =
      ParseIndirectObjectAt(object_pos, object_number);
  if (!object)
    return nullptr;

  std::unique_ptr<CPDF_ObjectStream> objs_stream =
      CPDF_ObjectStream::Create(ToStream(object.get()));
  const CPDF_ObjectStream* result = objs_stream.get();
  m_ObjectStreamMap[object_number] = std::move(objs_stream);

  return result;
}

std::unique_ptr<CPDF_Object> CPDF_Parser::ParseIndirectObjectAt(
    FX_FILESIZE pos,
    uint32_t objnum) {
  const FX_FILESIZE saved_pos = m_pSyntax->GetPos();
  m_pSyntax->SetPos(pos);
  auto result = m_pSyntax->GetIndirectObject(
      m_pObjectsHolder.Get(), CPDF_SyntaxParser::ParseType::kLoose);

  m_pSyntax->SetPos(saved_pos);

  if (result && objnum && result->GetObjNum() != objnum)
    return nullptr;

  const bool should_decrypt = m_pSecurityHandler &&
                              m_pSecurityHandler->GetCryptoHandler() &&
                              objnum != m_MetadataObjnum;
  if (should_decrypt)
    result = m_pSecurityHandler->GetCryptoHandler()->DecryptObjectTree(
        std::move(result));

  return result;
}

uint32_t CPDF_Parser::GetFirstPageNo() const {
  return m_pLinearized ? m_pLinearized->GetFirstPageNo() : 0;
}

void CPDF_Parser::SetLinearizedHeader(
    std::unique_ptr<CPDF_LinearizedHeader> pLinearized) {
  m_pLinearized = std::move(pLinearized);
}

uint32_t CPDF_Parser::GetPermissions() const {
  return m_pSecurityHandler ? m_pSecurityHandler->GetPermissions() : 0xFFFFFFFF;
}

std::unique_ptr<CPDF_LinearizedHeader> CPDF_Parser::ParseLinearizedHeader() {
  return CPDF_LinearizedHeader::Parse(m_pSyntax.get());
}

bool CPDF_Parser::ParseFileStructure() {
  if (!m_pSyntax->GetValidator()->IsWholeFileAvailable())
    m_pLinearized = ParseLinearizedHeader();

  m_LastXRefOffset =
      m_pLinearized ? m_pLinearized->GetLastXRefOffset() : ParseStartXRef();

  CPDF_CrossRefParser parser(m_pSyntax.get());
  m_CrossRefTable =
      parser.ParseCrossRef(m_LastXRefOffset, m_pObjectsHolder.Get());
  return !!m_CrossRefTable;
}

CPDF_Parser::Error CPDF_Parser::LoadPrevMainXRefTables() {
  if (!m_CrossRefTable || !m_CrossRefTable->trailer())
    return FORMAT_ERROR;

  CPDF_CrossRefParser parser(m_pSyntax.get());

  std::set<FX_FILESIZE> seen_xrefpos;
  while (true) {
    const FX_SAFE_FILESIZE prev_xref_table_offset =
        m_CrossRefTable->trailer()->GetIntegerFor("Prev");
    if (!prev_xref_table_offset.IsValid())
      return FORMAT_ERROR;

    if (prev_xref_table_offset.ValueOrDie() == 0)
      return SUCCESS;

    // Check for circular references.
    if (pdfium::ContainsKey(seen_xrefpos, prev_xref_table_offset.ValueOrDie()))
      return FORMAT_ERROR;

    seen_xrefpos.insert(prev_xref_table_offset.ValueOrDie());
    std::unique_ptr<CPDF_CrossRefTable> prev_xref_table = parser.ParseCrossRef(
        prev_xref_table_offset.ValueOrDie(), m_pObjectsHolder.Get());
    if (!prev_xref_table) {
      m_LastXRefOffset = 0;
      return FORMAT_ERROR;
    }
    m_CrossRefTable = CPDF_CrossRefTable::MergeUp(std::move(prev_xref_table),
                                                  std::move(m_CrossRefTable));
  }
  return SUCCESS;
}
