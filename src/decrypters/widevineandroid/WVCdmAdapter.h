/*
 *  Copyright (C) 2023 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "decrypters/HelperWv.h"
#include "decrypters/IDecrypter.h"

#include <androidjni/ClassLoader.h>
#include <androidjni/MediaDrm.h>
#include <androidjni/MediaDrmOnEventListener.h>
#include <androidjni/MediaDrmOnKeyStatusChangeListener.h>

#ifdef INPUTSTREAM_TEST_BUILD
#include "test/KodiStubs.h"
#else
#include <kodi/AddonBase.h>
#endif

#include <list>
#include <mutex>

class CWVDecrypterA;

class CMediaDrmOnEventCallback
{
public:
  CMediaDrmOnEventCallback() = default;
  virtual ~CMediaDrmOnEventCallback() = default;

  virtual void OnMediaDrmEvent(const CJNIMediaDrm& mediaDrm,
                               const std::vector<char>& sessionId,
                               int event,
                               int extra,
                               const std::vector<char>& data) = 0;
};

/*!
 * \brief This class is derived from CJNIMediaDrmOnEventListener to allow us
 *        to initialize the base class at later time, since the constructors
 *        of CJNIMediaDrmOnEventListener need to access to the global
 *        xbmc_jnienv method immediately.
 */
class CMediaDrmOnEventListener : public CJNIMediaDrmOnEventListener
{
public:
  CMediaDrmOnEventListener(CMediaDrmOnEventCallback* decrypterEventCallback,
                           std::shared_ptr<CJNIClassLoader> classLoader);
  virtual ~CMediaDrmOnEventListener() = default;

  virtual void onEvent(const CJNIMediaDrm& mediaDrm,
                       const std::vector<char>& sessionId,
                       int event,
                       int extra,
                       const std::vector<char>& data) override;

private:
  CMediaDrmOnEventCallback* m_decrypterEventCallback;
};

class CMediaDrmOnKeyStatusChangeCallback
{
public:
  CMediaDrmOnKeyStatusChangeCallback() = default;
  virtual ~CMediaDrmOnKeyStatusChangeCallback() = default;

  virtual void OnKeyStatusChange(const CJNIMediaDrm& mediaDrm,
                                 const std::vector<char>& sessionId,
                                 const CJNIList<CJNIMediaDrmKeyStatus>& keyInformation,
                                 bool hasNewUsableKey) = 0;
};

/*!
 * \brief This class is derived from CJNIMediaDrmOnKeyStatusChangeListener to allow us
 *        to initialize the base class at later time, since the constructors
 *        of CJNIMediaDrmOnKeyStatusChangeListener need to access to the global
 *        xbmc_jnienv method immediately.
 */
class CMediaDrmOnKeyStatusChangeListener : public CJNIMediaDrmOnKeyStatusChangeListener
{
public:
  CMediaDrmOnKeyStatusChangeListener(
      CMediaDrmOnKeyStatusChangeCallback* decrypterOnKeyStatusChangeCallback,
      std::shared_ptr<CJNIClassLoader> classLoader);
  virtual ~CMediaDrmOnKeyStatusChangeListener() = default;

  virtual void onKeyStatusChange(const CJNIMediaDrm& mediaDrm,
                                 const std::vector<char>& sessionId,
                                 const CJNIList<CJNIMediaDrmKeyStatus>& keyInformation,
                                 bool hasNewUsableKey) override;

private:
  CMediaDrmOnKeyStatusChangeCallback* m_decrypterOnKeyStatusChangeCallback;
};

class ATTR_DLL_LOCAL CWVCdmAdapterA : public CMediaDrmOnEventCallback,
                                      public CMediaDrmOnKeyStatusChangeCallback,
                                      public IWVCdmAdapter<CJNIMediaDrm>
{
public:
  CWVCdmAdapterA(std::string_view keySystem,
                 const DRM::Config& config,
                 std::shared_ptr<CJNIClassLoader> jniClassLoader,
                 CWVDecrypterA* host);
  ~CWVCdmAdapterA();

  // IWVCdmAdapter interface methods

  std::shared_ptr<CJNIMediaDrm> GetCDM() override { return m_cdmAdapter; }
  const DRM::Config& GetConfig() override;
  std::string_view GetKeySystem() override;
  std::string_view GetLibraryPath() const override;
  void SaveServiceCertificate() override;

  // IWVSubject interface methods

  void AttachObserver(IWVObserver* observer) override;
  void DetachObserver(IWVObserver* observer) override;
  void NotifyObservers(const CdmMessage& message) override;
  void NotifyOnKeyStatusChange(const std::string& sessionId,
                               const std::vector<DRM::KeyInfo>& keysInfo) override;

  static bool IsKeySystemSupported(std::string_view keySystem);

private:
  void LoadServiceCertificate();

  // CMediaDrmOnEventCallback interface methods
  void OnMediaDrmEvent(const CJNIMediaDrm& mediaDrm,
                       const std::vector<char>& sessionId,
                       int event,
                       int extra,
                       const std::vector<char>& data) override;

  // CMediaDrmOnKeyStatusChangeCallback interface methods
  void OnKeyStatusChange(const CJNIMediaDrm& mediaDrm,
                         const std::vector<char>& sessionId,
                         const CJNIList<CJNIMediaDrmKeyStatus>& keyInformation,
                         bool hasNewUsableKey) override;

  DRM::Config m_config;
  std::shared_ptr<CJNIMediaDrm> m_cdmAdapter;
  std::list<IWVObserver*> m_observers;
  std::mutex m_observer_mutex;

  std::string m_keySystem;
  std::unique_ptr<CMediaDrmOnEventListener> m_mediaDrmEventListener;
  std::unique_ptr<CMediaDrmOnKeyStatusChangeListener> m_mediaDrmOnKeyChangeListener;
  std::string m_strBasePath;
  CWVDecrypterA* m_host;
};
