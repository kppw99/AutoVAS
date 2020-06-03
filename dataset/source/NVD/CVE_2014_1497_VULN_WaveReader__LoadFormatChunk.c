bool
CVE_2014_1497_VULN_WaveReader::LoadFormatChunk(uint32_t aChunkSize)
{
  uint32_t rate, channels, frameSize, sampleFormat;
  char waveFormat[WAVE_FORMAT_CHUNK_SIZE];
  const char* p = waveFormat;

  // RIFF chunks are always word (two byte) aligned.
  NS_ABORT_IF_FALSE(mDecoder->GetResource()->Tell() % 2 == 0,
                    "LoadFormatChunk called with unaligned resource");

  if (!ReadAll(waveFormat, sizeof(waveFormat))) {
    return false;
  }

  static_assert(sizeof(uint16_t) +
                sizeof(uint16_t) +
                sizeof(uint32_t) +
                4 +
                sizeof(uint16_t) +
                sizeof(uint16_t) <= sizeof(waveFormat),
                "Reads would overflow waveFormat buffer.");
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
  if (aChunkSize > WAVE_FORMAT_CHUNK_SIZE) {
    char extLength[2];
    const char* p = extLength;

    if (!ReadAll(extLength, sizeof(extLength))) {
      return false;
    }

    static_assert(sizeof(uint16_t) <= sizeof(extLength),
                  "Reads would overflow extLength buffer.");
    uint16_t extra = ReadUint16LE(&p);
    if (aChunkSize - (WAVE_FORMAT_CHUNK_SIZE + 2) != extra) {
      NS_WARNING("Invalid extended format chunk size");
      return false;
    }
    extra += extra % 2;

    if (extra > 0) {
      static_assert(UINT16_MAX + (UINT16_MAX % 2) < UINT_MAX / sizeof(char),
                    "chunkExtension array too large for iterator.");
      nsAutoArrayPtr<char> chunkExtension(new char[extra]);
      if (!ReadAll(chunkExtension.get(), extra)) {
        return false;
      }
    }
  }

  // RIFF chunks are always word (two byte) aligned.
  NS_ABORT_IF_FALSE(mDecoder->GetResource()->Tell() % 2 == 0,
                    "LoadFormatChunk left resource unaligned");

  // Make sure metadata is fairly sane.  The rate check is fairly arbitrary,
  // but the channels check is intentionally limited to mono or stereo
  // when the media is intended for direct playback because that's what the
  // audio backend currently supports.
  unsigned int actualFrameSize = sampleFormat == 8 ? 1 : 2 * channels;
  if (rate < 100 || rate > 96000 ||
      (((channels < 1 || channels > MAX_CHANNELS) ||
       (frameSize != 1 && frameSize != 2 && frameSize != 4)) &&
       !mIgnoreAudioOutputFormat) ||
       (sampleFormat != 8 && sampleFormat != 16) ||
      frameSize != actualFrameSize) {
    NS_WARNING("Invalid WAVE metadata");
    return false;
  }

  ReentrantMonitorAutoEnter monitor(mDecoder->GetReentrantMonitor());
  mSampleRate = rate;
  mChannels = channels;
  mFrameSize = frameSize;
  if (sampleFormat == 8) {
    mSampleFormat = FORMAT_U8;
  } else {
    mSampleFormat = FORMAT_S16;
  }
  return true;
}
