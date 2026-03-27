/*
 *  Copyright (C) 2023 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "WVDecrypter.h"

#include "WVCdmAdapter.h"
#include "WVCencSingleSampleDecrypter.h"
#include "common/AdaptiveDecrypter.h"
#include "decrypters/Helpers.h"
#include "utils/Base64Utils.h"
#include "utils/StringUtils.h"
#include "utils/GUIUtils.h"
#include "utils/log.h"

#include <androidjni/ClassLoader.h>
#include <androidjni/UUID.h>

using namespace DRM;
using namespace UTILS;

namespace
{
kodi::platform::CInterfaceAndroidSystem* ANDROID_SYSTEM{nullptr};
} // unnamed namespace

CWVDecrypterA::CWVDecrypterA()
{
  // CInterfaceAndroidSystem need to be initialized at runtime
  // then we have to set it to global variable just now
  ANDROID_SYSTEM = &m_androidSystem;
};

CWVDecrypterA::~CWVDecrypterA()
{
  m_wvAdapters.clear();

#ifdef DRMTHREAD
  m_jniCondition.notify_one();
  m_jniWorker->join();
#endif
};

#ifdef DRMTHREAD
void JNIThread(JavaVM* vm)
{
  m_jniCondition.notify_one();
  std::unique_lock<std::mutex> lk(m_jniMutex);
  m_jniCondition.wait(lk);

  LOG::Log(SSDDEBUG, "JNI thread terminated");
}
#endif

bool CWVDecrypterA::IsKeySystemSupported(std::string_view keySystem)
{
  return CWVCdmAdapterA::IsKeySystemSupported(keySystem);
}

std::shared_ptr<Adaptive_CencSingleSampleDecrypter> CWVDecrypterA::CreateSingleSampleDecrypter(
    const DRM::Config& config,
    const std::vector<uint8_t>& defaultKeyId,
    CryptoMode cryptoMode)
{
  const std::string& keySystem = config.keySystem;
  std::shared_ptr<CWVCdmAdapterA> wvAdapter;

  // Reuse existing adapters
  if (STRING::KeyExists(m_wvAdapters, keySystem))
  {
    wvAdapter = m_wvAdapters[keySystem];
  }
  else
  {
    wvAdapter = std::make_shared<CWVCdmAdapterA>(keySystem, config, m_classLoader, this);

    if (!wvAdapter->GetCDM())
    {
      LOG::LogF(LOGERROR, "Widevine adapter not created");
      return nullptr;
    }

    m_wvAdapters.emplace(keySystem, wvAdapter);
  }

  return std::make_shared<CWVCencSingleSampleDecrypterA>(wvAdapter.get(), defaultKeyId);
}

void CWVDecrypterA::GetCapabilities(std::shared_ptr<Adaptive_CencSingleSampleDecrypter> decrypter,
                                    const std::vector<uint8_t>& keyId,
                                    DRM::DecrypterCapabilites& caps,
                                    DRM::DRMMediaType mediaType)
{
  if (!decrypter)
  {
    caps = {0, 0, 0};
    return;
  }

  auto wvDecrypter = std::dynamic_pointer_cast<CWVCencSingleSampleDecrypterA>(decrypter);
  if (wvDecrypter)
  {
    wvDecrypter->GetCapabilities(keyId, caps);
  }
  else
    LOG::LogF(LOGFATAL, "Cannot cast the decrypter shared pointer.");
}

std::optional<bool> CWVDecrypterA::HasLicenseKey(
    std::shared_ptr<Adaptive_CencSingleSampleDecrypter> decrypter,
    const std::vector<uint8_t>& keyId)
{
  auto wvDecrypter = std::dynamic_pointer_cast<CWVCencSingleSampleDecrypterA>(decrypter);
  if (wvDecrypter)
  {
    return wvDecrypter->HasKeyId(keyId);
  }
  else
    LOG::LogF(LOGFATAL, "Cannot cast the decrypter shared pointer.");

  return std::nullopt;
}

std::string CWVDecrypterA::GetChallengeB64Data(std::shared_ptr<Adaptive_CencSingleSampleDecrypter> decrypter)
{
  auto wvDecrypter = std::dynamic_pointer_cast<CWVCencSingleSampleDecrypterA>(decrypter);
  if (wvDecrypter)
  {
    const std::vector<uint8_t> challengeData = wvDecrypter->GetChallengeData();
    return BASE64::Encode(challengeData);
  }
  else
    LOG::LogF(LOGFATAL, "Cannot cast the decrypter shared pointer.");

  return "";
}

bool CWVDecrypterA::Initialize()
{
#ifdef DRMTHREAD
  std::unique_lock<std::mutex> lk(m_jniMutex);
  m_jniWorker = std::make_unique<std::thread>(
      &CWVDecrypterA::JNIThread, this, reinterpret_cast<JavaVM*>(m_androidSystem.GetJNIEnv()));
  m_jniCondition.wait(lk);
#endif
  if (xbmc_jnienv()->ExceptionCheck())
  {
    LOG::LogF(LOGERROR, "Failed to load MediaDrmOnEventListener");
    xbmc_jnienv()->ExceptionDescribe();
    xbmc_jnienv()->ExceptionClear();
    return false;
  }

  LOG::Log(LOGDEBUG, "WVDecrypter JNI, SDK version: %d, Base class name: %s",
           m_androidSystem.GetSDKVersion(), m_androidSystem.GetClassName().c_str());

  CJNIBase::SetSDKVersion(m_androidSystem.GetSDKVersion());
  CJNIBase::SetBaseClassName(m_androidSystem.GetClassName());

  const char* apkPath = getenv("XBMC_ANDROID_APK");
  if (!apkPath)
    apkPath = getenv("KODI_ANDROID_APK");

  if (!apkPath)
  {
    LOG::LogF(LOGERROR, "Cannot get enviroment XBMC_ANDROID_APK/KODI_ANDROID_APK value");
    return false;
  }

  m_classLoader = std::make_shared<CJNIClassLoader>(apkPath);
  if (xbmc_jnienv()->ExceptionCheck())
  {
    LOG::LogF(LOGERROR, "Failed to create ClassLoader");
    xbmc_jnienv()->ExceptionDescribe();
    xbmc_jnienv()->ExceptionClear();

    return false;
  }

  return true;
}

// Definition for the xbmc_jnienv method of the jni utils (jutils.hpp)
JNIEnv* xbmc_jnienv()
{
  return static_cast<JNIEnv*>(ANDROID_SYSTEM->GetJNIEnv());
}
