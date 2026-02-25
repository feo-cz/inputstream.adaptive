/*
 *  Copyright (C) 2022 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "ChooserTest.h"

#include "AdaptationSet.h"
#include "CompKodiProps.h"
#include "CompSettings.h"
#include "ReprSelector.h"
#include "Representation.h"
#include "SrvBroker.h"
#include "utils/log.h"

using namespace ADP;
using namespace CHOOSER;
using namespace PLAYLIST;

CRepresentationChooserTest::CRepresentationChooserTest()
{
  LOG::Log(LOGDEBUG, "[Repr. chooser] Type: Test");
}

void CRepresentationChooserTest::Initialize(const ADP::KODI_PROPS::ChooserProps& props)
{
  auto& settings = CSrvBroker::GetSettings();

  SETTINGS::StreamSelMode manualSelMode = settings.GetStreamSelMode();

  if (manualSelMode == SETTINGS::StreamSelMode::MANUAL_VIDEO)
    m_streamSelectionMode = StreamSelection::MANUAL_VIDEO_ONLY;
  else
    m_streamSelectionMode = StreamSelection::MANUAL;

  std::string testMode = settings.GetChooserTestMode();

  if (testMode == "switch-segments")
    m_testMode = TestMode::SWITCH_SEGMENTS;
  else // Fallback
    m_testMode = TestMode::SWITCH_SEGMENTS;

  std::string logDetails;

  if (m_testMode == TestMode::SWITCH_SEGMENTS)
  {
    m_segmentsCountByType[StreamType::VIDEO] = settings.GetChooserTestSegsVideo();
    m_segmentsCountByType[StreamType::AUDIO] = settings.GetChooserTestSegsAudio();
    logDetails = kodi::tools::StringUtils::Format(
        "Segments count video: %i, Segments count audio: %i",
        m_segmentsCountByType[StreamType::VIDEO], m_segmentsCountByType[StreamType::AUDIO]);
  }

  LOG::Log(LOGDEBUG,
           "[Repr. chooser] Configuration\n"
           "Test mode: %s\n%s",
           testMode.c_str(), logDetails.c_str());
}

void CRepresentationChooserTest::PostInit()
{
}

PLAYLIST::CRepresentation* CRepresentationChooserTest::GetNextRepresentation(
    PLAYLIST::CAdaptationSet* adp, PLAYLIST::CRepresentation* currentRep)
{
  CRepresentationSelector selector(m_screenCurrentWidth, m_screenCurrentHeight);
  CRepresentation* nextRep{currentRep};
  const StreamType streamType{adp->GetStreamType()};

  if (!currentRep) // Startup or new period
  {
    if (m_testMode == TestMode::SWITCH_SEGMENTS)
    {
      if (streamType == StreamType::VIDEO || streamType == StreamType::AUDIO)
        m_segmentsElapsedByType[streamType] = 1;

      nextRep = selector.Lowest(adp);
    }
    else
    {
      LOG::LogF(LOGERROR, "Unhandled test mode");
    }
  }
  else
  {
    if (m_testMode == TestMode::SWITCH_SEGMENTS)
    {
      if (streamType != StreamType::VIDEO && streamType != StreamType::AUDIO)
        return currentRep;

      const int maxSegCount{m_segmentsCountByType[streamType]};

      if (maxSegCount == 0)
        return currentRep;

      if (m_segmentsElapsedByType[streamType] == maxSegCount)
      {
        m_segmentsElapsedByType[streamType] = 1;
        nextRep = selector.Higher(adp, currentRep);
        // If there are no next representations, start again from the lowest
        if (nextRep == currentRep)
          nextRep = selector.Lowest(adp);
      }
      else
        ++m_segmentsElapsedByType[streamType];
    }
  }

  if (currentRep && (streamType == StreamType::VIDEO || streamType == StreamType::AUDIO))
    LogDetails(currentRep, nextRep);

  return nextRep;
}
