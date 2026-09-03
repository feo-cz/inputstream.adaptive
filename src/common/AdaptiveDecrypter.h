/*
 *  Copyright (C) 2022 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "utils/CryptoUtils.h"

#include <stdexcept>
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

  /*! \brief In-band key rotation: make sure the CDM holds a usable key for keyId.
   *         If it does not, request a new license from the per-segment PSSH.
   *  \param keyId    the rotated KID read from the SEIG box of the current fragment
   *  \param psshData Widevine PSSH proto payload (the Data field of the moof pssh
   *                  box), or empty if the segment carries no Widevine PSSH
   *  The request is served asynchronously; the reader keeps calling NeedsKeyRenewal
   *  on later fragments until the key is actually usable, so there is nothing to
   *  return. Default: no-op, so decrypters without in-band rotation (ClearKey,
   *  widevineandroid) keep their unchanged behaviour.
   */
  virtual void RenewSessionForKey(const std::vector<uint8_t>& keyId,
                                  const std::vector<uint8_t>& psshData)
  {
  }

  /*! \brief In-band key rotation: should the reader (re)request a license for keyId?
   *  True when there is no usable key yet AND the renewal for this KID has not been
   *  permanently given up. Default false, so decrypters without in-band rotation
   *  (ClearKey etc.) never trigger re-requests.
   */
  virtual bool NeedsKeyRenewal(const std::vector<uint8_t>& keyId) { return false; }

  virtual AP4_Result SetFragmentInfo(AP4_UI32 poolId,
                                     const std::vector<uint8_t>& keyId,
                                     const AP4_UI08 nalLengthSize,
                                     AP4_DataBuffer& annexbSpsPps,
                                     AP4_UI32 flags,
                                     CryptoInfo cryptoInfo) = 0;

  virtual AP4_Result DecryptSampleData(AP4_UI32 poolId,
                                       AP4_DataBuffer& dataIn,
                                       AP4_DataBuffer& dataOut,
                                       const AP4_UI08* iv,
                                       unsigned int subsampleCount,
                                       const AP4_UI16* bytesOfCleartextData,
                                       const AP4_UI32* bytesOfEncryptedData) = 0;

  virtual AP4_UI32 AddPool() { return 0; }
  virtual void RemovePool(AP4_UI32 poolId) {}
  virtual const char* GetSessionId() { return nullptr; }
};
