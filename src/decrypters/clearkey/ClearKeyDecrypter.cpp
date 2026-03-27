/*
 *  Copyright (C) 2024 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "ClearKeyDecrypter.h"

#include "ClearKeyCencSingleSampleDecrypter.h"
#include "decrypters/Helpers.h"
#include "utils/log.h"

bool CClearKeyDecrypter::IsKeySystemSupported(std::string_view keySystem)
{
  return keySystem == KS_CLEARKEY;
}

std::shared_ptr<Adaptive_CencSingleSampleDecrypter> CClearKeyDecrypter::CreateSingleSampleDecrypter(
    const DRM::Config& config,
    const std::vector<uint8_t>& defaultkeyid,
    CryptoMode cryptoMode)
{
  if (cryptoMode != CryptoMode::AES_CTR && cryptoMode != CryptoMode::AES_CBC)
  {
    LOG::LogF(LOGERROR,
              "Cannot initialize ClearKey DRM. Only \"cenc\" and \"cbcs\" encryption supported.");
    return nullptr;
  }

  return std::make_shared<CClearKeyCencSingleSampleDecrypter>(defaultkeyid, this);
}

std::optional<bool> CClearKeyDecrypter::HasLicenseKey(
    std::shared_ptr<Adaptive_CencSingleSampleDecrypter> decrypter,
    const std::vector<uint8_t>& keyId)
{
  if (decrypter)
  {
    auto clearKeyDecrypter =
        std::dynamic_pointer_cast<CClearKeyCencSingleSampleDecrypter>(decrypter);

    if (clearKeyDecrypter)
      return clearKeyDecrypter->HasKeyId(keyId);
    else
      LOG::LogF(LOGFATAL, "Cannot cast the decrypter shared pointer.");
  }
  return std::nullopt;
}
