/*
 *  Copyright (C) 2023 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "CdmBuffer.h"

#include "cdm/media/cdm/cdm_adapter.h"
#include <bento4/Ap4.h>
#include <kodi/addon-instance/VideoCodec.h>

#include <mutex>

class CWVDecrypter;
class CWVCencSingleSampleDecrypter;

class ATTR_DLL_LOCAL CWVCdmAdapter : public media::CdmAdapterClient
{
public:
  CWVCdmAdapter(std::string_view licenseURL,
                const std::vector<uint8_t>& serverCert,
                const uint8_t config,
                CWVDecrypter* host);
  virtual ~CWVCdmAdapter();

  virtual void OnCDMMessage(const char* session,
                            uint32_t session_size,
                            CDMADPMSG msg,
                            const uint8_t* data,
                            size_t data_size,
                            uint32_t status) override;

  virtual cdm::Buffer* AllocateBuffer(size_t sz) override;

  void insertssd(CWVCencSingleSampleDecrypter* ssd)
  {
    std::lock_guard<std::mutex> lock(m_ssdsLock);
    ssds.push_back(ssd);
  };
  void removessd(CWVCencSingleSampleDecrypter* ssd)
  {
    // Held for the whole of OnCDMMessage too, so a decrypter being destroyed waits
    // for any in-flight CDM callback to finish before it is removed - otherwise an
    // async renewal session's late kSessionMessage/kSessionKeysChange could touch a
    // decrypter that is being torn down (use-after-free).
    std::lock_guard<std::mutex> lock(m_ssdsLock);
    std::vector<CWVCencSingleSampleDecrypter*>::iterator res(
        std::find(ssds.begin(), ssds.end(), ssd));
    if (res != ssds.end())
      ssds.erase(res);
  };

  media::CdmAdapter* GetCdmAdapter() { return wv_adapter.get(); };
  const std::string& GetLicenseURL() { return m_licenseUrl; };

  // Serializes CDM session-management entries against each other and against the
  // timer callback (CreateSession/UpdateSession/CloseSession/TimerExpired) - all run
  // off the decode thread. Decoding (Decrypt/DecryptAndDecodeFrame) deliberately does
  // NOT take this lock, so a ~1 s renewal never stalls playback (see DecryptAndDecodeFrame).
  // Must NOT be held across the license HTTP round-trip.
  std::mutex& GetCdmLock() { return m_cdmLock; }
  std::mutex* GetCdmMutex() override { return &m_cdmLock; } // guards the timer callback too

  // CDM session-management entry points, each serialized by m_cdmLock against
  // decoding and against each other. Callers must NOT hold m_cdmLock across the
  // license HTTP round-trip - only the individual CDM call is guarded.
  void CdmCreateSessionAndGenerateRequest(uint32_t promiseId,
                                          cdm::SessionType sessionType,
                                          cdm::InitDataType initDataType,
                                          const uint8_t* initData,
                                          uint32_t initDataSize)
  {
    std::lock_guard<std::mutex> lock(m_cdmLock);
    wv_adapter->CreateSessionAndGenerateRequest(promiseId, sessionType, initDataType, initData,
                                                initDataSize);
  }
  void CdmUpdateSession(uint32_t promiseId,
                        const char* sessionId,
                        uint32_t sessionIdSize,
                        const uint8_t* response,
                        uint32_t responseSize)
  {
    std::lock_guard<std::mutex> lock(m_cdmLock);
    wv_adapter->UpdateSession(promiseId, sessionId, sessionIdSize, response, responseSize);
  }
  void CdmCloseSession(uint32_t promiseId, const char* sessionId, uint32_t sessionIdSize)
  {
    std::lock_guard<std::mutex> lock(m_cdmLock);
    wv_adapter->CloseSession(promiseId, sessionId, sessionIdSize);
  }
  cdm::Status DecryptAndDecodeFrame(cdm::InputBuffer_2& cdm_in,
                                    media::CdmVideoFrame* frame,
                                    kodi::addon::CInstanceVideoCodec* codecInstance)
  {
    // DecryptAndDecodeFrame calls CdmAdapter::Allocate which calls Host->GetBuffer
    // that cast hostInstance to CInstanceVideoCodec to get the frame buffer
    // so we have temporary set the host instance
    //
    // Intentionally NOT holding m_cdmLock (see GetCdmLock): decode must not stall on a
    // ~1 s in-band renewal. The CDM's own decrypt_mutex_ still serializes decode.
    m_codecInstance = codecInstance;
    cdm::Status ret = wv_adapter->DecryptAndDecodeFrame(cdm_in, frame);
    m_codecInstance = nullptr;
    return ret;
  }

private:
  std::shared_ptr<media::CdmAdapter> wv_adapter;
  std::string m_licenseUrl;
  kodi::addon::CInstanceVideoCodec* m_codecInstance;
  CWVDecrypter* m_host;
  std::vector<CWVCencSingleSampleDecrypter*> ssds;
  std::mutex m_ssdsLock; // guards ssds and serializes OnCDMMessage against removessd
  std::mutex m_cdmLock; // serializes all entries into the single-threaded CDM
};
