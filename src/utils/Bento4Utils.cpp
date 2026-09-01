/*
 *  Copyright (C) 2026 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "Bento4Utils.h"

#include "utils/log.h"

using namespace UTILS::BENTO4;

std::vector<CencSeigGroupEntry> UTILS::BENTO4::FMP4SgpdAtom::GetSeigEntries()
{
  if (m_GroupingType != AP4_ATOM_TYPE('s', 'e', 'i', 'g'))
    return {};

  // The SEIG entry body is identical for sgpd v0/v1. (Bento4's AP4_SgpdAtom
  // rejects v2+ during parsing anyway, so v2 never reaches this code.)
  if (m_Version > 1)
  {
    LOG::LogF(LOGERROR, "Unsupported TRAF/SGPD box version %u", m_Version);
    return {};
  }

  std::vector<CencSeigGroupEntry> entries;

  for (AP4_List<AP4_DataBuffer>::Item* item = m_Entries.FirstItem(); item; item = item->GetNext())
  {
    AP4_DataBuffer* data = item->GetData();
    AP4_MemoryByteStream stream(data->GetData(), data->GetDataSize());
    BENTO4::CencSeigGroupEntry entry;

    // First byte: multi_key_flag (1 bit) + reserved (7 bit)
    AP4_UI08 firstByte;
    AP4_Result res = stream.ReadUI08(firstByte);
    if (AP4_FAILED(res))
    {
      LOG::LogF(LOGERROR, "Failed to parse multi_key_flag from SEIG group desc entry");
      continue;
    }
    entry.multiKeyFlag = (firstByte & 0x80) != 0; // Bit 7 (MSB)
    // Bits 0-6 are reserved; per spec a decoder ignores them rather than
    // rejecting the entry (some muxers set them), so we only note it.
    if ((firstByte & 0x7F) != 0)
      LOG::LogF(LOGDEBUG, "Non-zero reserved bits in SEIG group desc entry");

    // Second byte: crypt_byte_block (4 bit MSB) + skip_byte_block (4 bit LSB)
    AP4_UI08 secondByte;
    res = stream.ReadUI08(secondByte);
    if (AP4_FAILED(res))
    {
      LOG::LogF(LOGERROR,
                "Failed to parse crypt_byte_block/skip_byte_block from SEIG group desc entry");
      continue;
    }
    entry.cryptByteBlock = (secondByte >> 4) & 0x0F;
    entry.skipByteBlock = secondByte & 0x0F;

    // Third byte: isProtected (8 bit)
    res = stream.ReadUI08(entry.isProtected);
    if (AP4_FAILED(res))
    {
      LOG::LogF(LOGERROR, "Failed to parse isProtected from SEIG group desc entry");
      continue;
    }

    // Key count
    uint16_t keyCount = 1;
    if (entry.multiKeyFlag)
    {
      AP4_UI16 value; // 16 bit
      res = stream.ReadUI16(value);
      if (AP4_FAILED(res))
      {
        LOG::LogF(LOGERROR, "Failed to parse key count from SEIG group desc entry");
        continue;
      }
      keyCount = value;
    }

    // Read key sets. On any short read the remaining bytes of this entry are
    // gone, so stop reading further key sets (break, not continue).
    for (uint16_t k = 0; k < keyCount; ++k)
    {
      BENTO4::CencSeigKeySet kset;

      res = stream.ReadUI08(kset.perSampleIvSize);
      if (AP4_FAILED(res))
      {
        LOG::LogF(LOGERROR, "Failed to parse Per_Sample_IV_Size from SEIG group desc entry");
        break;
      }

      kset.kid.resize(16, 0);
      res = stream.Read(kset.kid.data(), 16);
      if (AP4_FAILED(res))
      {
        LOG::LogF(LOGERROR, "Failed to parse KID from SEIG group desc entry");
        break;
      }

      // constant_IV is present only for protected key sets with no per-sample IV
      // (ISO/IEC 23001-7). For multi-key entries the per-set flag governs it.
      if (kset.perSampleIvSize == 0 && (entry.multiKeyFlag || entry.isProtected != 0))
      {
        res = stream.ReadUI08(kset.constantIvSize);
        if (AP4_FAILED(res))
        {
          LOG::LogF(LOGERROR, "Failed to parse constant_IV_size from SEIG group desc entry");
          break;
        }

        if (kset.constantIvSize > 0)
        {
          kset.constantIv.resize(kset.constantIvSize);
          res = stream.Read(kset.constantIv.data(), kset.constantIvSize);
          if (AP4_FAILED(res))
          {
            LOG::LogF(LOGERROR, "Failed to parse constant_IV from SEIG group desc entry");
            break;
          }
        }
      }

      entry.keySets.emplace_back(kset);
    }

    entries.emplace_back(entry);
  }

  return entries;
}
