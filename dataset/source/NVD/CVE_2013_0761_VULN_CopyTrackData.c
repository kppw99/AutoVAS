  void CVE_2013_0761_VULN_CopyTrackData(uint32_t aMapIndex, GraphTime aFrom, GraphTime aTo,
                     bool* aOutputTrackFinished)
  {
    TrackMapEntry* map = &mTrackMap[aMapIndex];
    StreamBuffer::Track* inputTrack = map->mInputTrack;
    StreamBuffer::Track* outputTrack = map->mOutputTrack;
    TrackRate rate = outputTrack->GetRate();
    MediaSegment* segment = map->mSegment;
    MediaStream* source = map->mInputPort->GetSource();

    NS_ASSERTION(!outputTrack->IsEnded(), "Can't copy to ended track");

    GraphTime next;
    *aOutputTrackFinished = false;
    for (GraphTime t = aFrom; t < aTo; t = next) {
      MediaInputPort::InputInterval interval = map->mInputPort->GetNextInputInterval(t);
      interval.mEnd = NS_MIN(interval.mEnd, aTo);
      if (interval.mStart >= interval.mEnd)
        break;
      next = interval.mEnd;

      // Ticks >= startTicks and < endTicks are in the interval
      StreamTime outputEnd = GraphTimeToStreamTime(interval.mEnd);
      TrackTicks startTicks = outputTrack->GetEnd();
#ifdef DEBUG
      StreamTime outputStart = GraphTimeToStreamTime(interval.mStart);
#endif
      NS_ASSERTION(startTicks == TimeToTicksRoundUp(rate, outputStart),
                   "Samples missing");
      TrackTicks endTicks = TimeToTicksRoundUp(rate, outputEnd);
      TrackTicks ticks = endTicks - startTicks;
      // StreamTime inputStart = source->GraphTimeToStreamTime(interval.mStart);
      StreamTime inputEnd = source->GraphTimeToStreamTime(interval.mEnd);
      TrackTicks inputTrackEndPoint = TRACK_TICKS_MAX;

      if (inputTrack->IsEnded()) {
        TrackTicks inputEndTicks = inputTrack->TimeToTicksRoundDown(inputEnd);
        if (inputTrack->GetEnd() <= inputEndTicks) {
          inputTrackEndPoint = inputTrack->GetEnd();
          *aOutputTrackFinished = true;
        }
      }

      if (interval.mInputIsBlocked) {
        // Maybe the input track ended?
        segment->AppendNullData(ticks);
        LOG(PR_LOG_DEBUG, ("TrackUnionStream %p appending %lld ticks of null data to track %d",
            this, (long long)ticks, outputTrack->GetID()));
      } else {
        // Figuring out which samples to use from the input stream is tricky
        // because its start time and our start time may differ by a fraction
        // of a tick. Assuming the input track hasn't ended, we have to ensure
        // that 'ticks' samples are gathered, even though a tick boundary may
        // occur between outputStart and outputEnd but not between inputStart
        // and inputEnd.
        // We'll take the latest samples we can.
        TrackTicks inputEndTicks = TimeToTicksRoundUp(rate, inputEnd);
        TrackTicks inputStartTicks = inputEndTicks - ticks;
        segment->AppendSlice(*inputTrack->GetSegment(),
                             NS_MIN(inputTrackEndPoint, inputStartTicks),
                             NS_MIN(inputTrackEndPoint, inputEndTicks));
        LOG(PR_LOG_DEBUG, ("TrackUnionStream %p appending %lld ticks of input data to track %d",
            this, (long long)(NS_MIN(inputTrackEndPoint, inputEndTicks) - NS_MIN(inputTrackEndPoint, inputStartTicks)),
            outputTrack->GetID()));
      }
      for (uint32_t j = 0; j < mListeners.Length(); ++j) {
        MediaStreamListener* l = mListeners[j];
        l->NotifyQueuedTrackChanges(Graph(), outputTrack->GetID(),
                                    outputTrack->GetRate(), startTicks, 0,
                                    *segment);
      }
      outputTrack->GetSegment()->AppendFrom(segment);
    }
  }
