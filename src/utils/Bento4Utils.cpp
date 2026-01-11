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
    uint8_t reserved = firstByte & 0x7F; // Bit 0-6
    if (reserved != 0)
    {
      LOG::LogF(LOGDEBUG, "Skipped reserved SEIG group desc entry");
      continue;
    }

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

    // Read key sets
    for (uint16_t k = 0; k < keyCount; ++k)
    {
      BENTO4::CencSeigKeySet kset;

      res = stream.ReadUI08(kset.perSampleIvSize);
      if (AP4_FAILED(res))
      {
        LOG::LogF(LOGERROR, "Failed to parse Per_Sample_IV_Size from SEIG group desc entry");
        continue;
      }

      kset.kid.resize(16, 0);
      res = stream.Read(kset.kid.data(), 16);
      if (AP4_FAILED(res))
      {
        LOG::LogF(LOGERROR, "Failed to parse KID from SEIG group desc entry");
        continue;
      }

      if (kset.perSampleIvSize == 0)
      {
        res = stream.ReadUI08(kset.constantIvSize);
        if (AP4_FAILED(res))
        {
          LOG::LogF(LOGERROR, "Failed to parse constant_IV_size from SEIG group desc entry");
          continue;
        }

        if (kset.constantIvSize > 0)
        {
          kset.constantIv.resize(kset.constantIvSize);
          res = stream.Read(kset.constantIv.data(), kset.constantIvSize);
          if (AP4_FAILED(res))
          {
            LOG::LogF(LOGERROR, "Failed to parse constant_IV from SEIG group desc entry");
            continue;
          }
        }
      }

      entry.keySets.emplace_back(kset);
    }

    entries.emplace_back(entry);
  }

  return entries;
}
