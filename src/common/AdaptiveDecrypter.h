/*
 *  Copyright (C) 2022 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "decrypters/DrmEngineDefines.h"
#include "utils/CryptoUtils.h"
#include "utils/ResultType.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <bento4/Ap4.h>

class Adaptive_CencSingleSampleDecrypter : public AP4_CencSingleSampleDecrypter
{
public:
  Adaptive_CencSingleSampleDecrypter() : AP4_CencSingleSampleDecrypter(0){};

  /*! \brief Add a Key ID to the current session
   *  \param keyId The KID
   */
  virtual void AddKeyId(const std::vector<uint8_t>& keyId)
  {
    throw std::logic_error("AddKeyId method not implemented.");
  };

  /*! \brief Set a Key ID as default
   *  \param keyId The KID
   */
  virtual void SetDefaultKeyId(const std::vector<uint8_t>& keyId)
  {
    throw std::logic_error("SetDefaultKeyId method not implemented.");
  };

  virtual AP4_Result SetFragmentInfo(AP4_UI32 poolId,
                                     const std::vector<uint8_t>& keyId,
                                     const AP4_UI08 nalLengthSize,
                                     const std::vector<uint8_t>& annexbSpsPps,
                                     DRM::Capabilities caps,
                                     CryptoInfo cryptoInfo) = 0;

  virtual AP4_Result DecryptSampleData(AP4_UI32 poolId,
                                       AP4_DataBuffer& dataIn,
                                       AP4_DataBuffer& dataOut,
                                       const AP4_UI08* iv,
                                       unsigned int subsampleCount,
                                       const AP4_UI16* bytesOfCleartextData,
                                       const AP4_UI32* bytesOfEncryptedData,
                                       DRM::DRMMediaType streamType) = 0;

  virtual AP4_UI32 AddPool() { return 0; }
  virtual void RemovePool(AP4_UI32 poolId) {}

  /*
   * \brief Create a DRM session.
   * \param pssh[OPT] A PSSH to make the license request, its use depends on DRM.
   * \param licenseUrl[OPT] A license URL or URI to make the license request, its use depends on DRM.
   * \param skipSessionMessage[OPT] Skip the session message to avoid make a license request, by default should be set false.
   * \return SResult::Ok on success, otherwise a SResult failed status.
   */
  virtual SResult CreateSession(const std::vector<uint8_t>& pssh,
                                std::string_view licenseUrl,
                                bool skipSessionMessage) = 0;

  /*!
   * \brief The session ID, is mandatory to distinguish sessions.
   */
  virtual std::string GetSessionId() = 0;
};
