/*
 *  Copyright (C) 2025 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#ifdef INPUTSTREAM_TEST_BUILD
#include "test/KodiStubs.h"
#else
#include <kodi/AddonBase.h>
#endif

#include <bento4/Ap4.h>

namespace UTILS
{
namespace BENTO4
{

// \brief Accessory for accessing AP4_UnknownUuidAtom data
class ATTR_DLL_LOCAL FMP4UnknownUuidAtom : public AP4_UnknownUuidAtom
{
public:
  const AP4_DataBuffer& GetData() { return m_Data; }
};

} // namespace BASE64
} // namespace UTILS
