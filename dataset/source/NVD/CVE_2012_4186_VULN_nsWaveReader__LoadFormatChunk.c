bool
CVE_2012_4186_VULN_nsWaveReader::LoadFormatChunk()
{
  PRUint32 fmtSize, rate, channels, frameSize, sampleFormat;
  char waveFormat[WAVE_FORMAT_CHUNK_SIZE];
  const char* p = waveFormat;

  // RIFF chunks are always word (two byte) aligned.
  NS_ABORT_IF_FALSE(mDecoder->GetCurrentStream()->Tell() % 2 == 0,
                    "LoadFormatChunk called with unaligned stream");

  // The "format" chunk may not directly follow the "riff" chunk, so skip
  // over any intermediate chunks.
  if (!ScanForwardUntil(FRMT_CHUNK_MAGIC, &fmtSize)) {
    return false;
  }

  if (!ReadAll(waveFormat, sizeof(waveFormat))) {
    return false;
  }

  PR_STATIC_ASSERT(sizeof(PRUint16) +
                   sizeof(PRUint16) +
                   sizeof(PRUint32) +
                   4 +
                   sizeof(PRUint16) +
                   sizeof(PRUint16) <= sizeof(waveFormat));
  if (ReadUint16LE(&p) != WAVE_FORMAT_ENCODING_PCM) {
    NS_WARNING("WAVE is not uncompressed PCM, compressed encodings are not supported");
    return false;
  }

  channels = ReadUint16LE(&p);
  rate = ReadUint32LE(&p);

  // Skip over average bytes per second field.
  p += 4;

  frameSize = ReadUint16LE(&p);

  sampleFormat = ReadUint16LE(&p);

  // PCM encoded WAVEs are not expected to have an extended "format" chunk,
  // but I have found WAVEs that have a extended "format" chunk with an
  // extension size of 0 bytes.  Be polite and handle this rather than
  // considering the file invalid.  This code skips any extension of the
  // "format" chunk.
  if (fmtSize > WAVE_FORMAT_CHUNK_SIZE) {
    char extLength[2];
    const char* p = extLength;

    if (!ReadAll(extLength, sizeof(extLength))) {
      return false;
    }

    PR_STATIC_ASSERT(sizeof(PRUint16) <= sizeof(extLength));
    PRUint16 extra = ReadUint16LE(&p);
    if (fmtSize - (WAVE_FORMAT_CHUNK_SIZE + 2) != extra) {
      NS_WARNING("Invalid extended format chunk size");
      return false;
    }
    extra += extra % 2;

    if (extra > 0) {
      PR_STATIC_ASSERT(PR_UINT16_MAX + (PR_UINT16_MAX % 2) < UINT_MAX / sizeof(char));
      nsAutoArrayPtr<char> chunkExtension(new char[extra]);
      if (!ReadAll(chunkExtension.get(), extra)) {
        return false;
      }
    }
  }

  // RIFF chunks are always word (two byte) aligned.
  NS_ABORT_IF_FALSE(mDecoder->GetCurrentStream()->Tell() % 2 == 0,
                    "LoadFormatChunk left stream unaligned");

  // Make sure metadata is fairly sane.  The rate check is fairly arbitrary,
  // but the channels check is intentionally limited to mono or stereo
  // because that's what the audio backend currently supports.
  if (rate < 100 || rate > 96000 ||
      channels < 1 || channels > MAX_CHANNELS ||
      (frameSize != 1 && frameSize != 2 && frameSize != 4) ||
      (sampleFormat != 8 && sampleFormat != 16)) {
    NS_WARNING("Invalid WAVE metadata");
    return false;
  }

  ReentrantMonitorAutoEnter monitor(mDecoder->GetReentrantMonitor());
  mSampleRate = rate;
  mChannels = channels;
  mFrameSize = frameSize;
  if (sampleFormat == 8) {
    mSampleFormat = nsAudioStream::FORMAT_U8;
  } else {
    mSampleFormat = nsAudioStream::FORMAT_S16_LE;
  }
  return true;
}
