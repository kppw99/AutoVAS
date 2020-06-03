NS_IMETHODIMP CVE_2012_4207_VULN_nsHZToUnicode::ConvertNoBuff(
  const char* aSrc, 
  PRInt32 * aSrcLength, 
  PRUnichar *aDest, 
  PRInt32 * aDestLength)
{
  PRInt32 i=0;
  PRInt32 iSrcLength = *aSrcLength;
  PRInt32 iDestlen = 0;
  *aSrcLength=0;
  nsresult res = NS_OK;
  char oddByte = mOddByte;

  for (i=0; i<iSrcLength; i++) {
    if (iDestlen >= (*aDestLength)) {
      res = NS_OK_UDEC_MOREOUTPUT;
      break;
    }

    char srcByte = *aSrc++;
    (*aSrcLength)++;
    
    if (!HZ_ODD_BYTE_STATE) {
      if (srcByte == HZLEAD1 || 
          (HZ_ENCODING_STATE == HZ_STATE_GB && 
           (UINT8_IN_RANGE(0x21, srcByte, 0x7E) ||
            UINT8_IN_RANGE(0x81, srcByte, 0xFE)))) {
        oddByte = srcByte;
        mHZState |= HZ_STATE_ODD_BYTE_FLAG;
      } else {
        *aDest++ = (srcByte & 0x80) ? UCS2_NO_MAPPING :
                                      CAST_CHAR_TO_UNICHAR(srcByte);
        iDestlen++;
      }
    } else {
      if (oddByte & 0x80) {
        // Accept legal 8-bit GB 2312-80 sequences in GB mode only
        NS_ASSERTION(HZ_ENCODING_STATE == HZ_STATE_GB,
                     "Invalid lead byte in ASCII mode");                    
        *aDest++ = (UINT8_IN_RANGE(0x81, oddByte, 0xFE) &&
                    UINT8_IN_RANGE(0x40, srcByte, 0xFE)) ?
                     mUtil.GBKCharToUnicode(oddByte, srcByte) : UCS2_NO_MAPPING;
        mRunLength++;
        iDestlen++;
      // otherwise, it is a 7-bit byte 
      // The source will be an ASCII or a 7-bit HZ code depending on oddByte
      } else if (oddByte == HZLEAD1) { // if it is lead by '~'
        switch (srcByte) {
          case HZLEAD2: 
            // we got a '~{'
            // we are switching to HZ state
            mHZState = HZ_STATE_GB;
            mRunLength = 0;
            break;

          case HZLEAD3: 
            // we got a '~}'
            // we are switching to ASCII state
            mHZState = HZ_STATE_ASCII;
            if (mRunLength == 0) {
              *aDest++ = UCS2_NO_MAPPING;
              iDestlen++;
            }
            mRunLength = 0;
            break;

          case HZLEAD1: 
            // we got a '~~', process like an ASCII, but no state change
            *aDest++ = CAST_CHAR_TO_UNICHAR(srcByte);
            iDestlen++;
            mRunLength++;
            break;

          default:
            // Undefined ESC sequence '~X': treat as an error if X is a
            // printable character or we are in ASCII mode, and resynchronize
            // on the second character.
            // 
            // N.B. For compatibility with other implementations, we treat '~\n'
            // as an illegal sequence even though RFC1843 permits it, and for
            // the same reason we pass through control characters including '\n'
            // and ' ' even in GB mode.
            if (srcByte > 0x20 || HZ_ENCODING_STATE == HZ_STATE_ASCII) {
              *aDest++ = UCS2_NO_MAPPING;
            }
            aSrc--;
            (*aSrcLength)--;
            iDestlen++;
            break;
        }
      } else if (HZ_ENCODING_STATE == HZ_STATE_GB) {
        *aDest++ = (UINT8_IN_RANGE(0x21, oddByte, 0x7E) &&
                    UINT8_IN_RANGE(0x21, srcByte, 0x7E)) ?
                     mUtil.GBKCharToUnicode(oddByte|0x80, srcByte|0x80) :
                     UCS2_NO_MAPPING;
        mRunLength++;
        iDestlen++;
      } else {
        NS_NOTREACHED("2-byte sequence that we don't know how to handle");
        *aDest++ = UCS2_NO_MAPPING;
        iDestlen++;
      }
      oddByte = 0;
      mHZState &= ~HZ_STATE_ODD_BYTE_FLAG;
    }
  } // for loop
  mOddByte = HZ_ODD_BYTE_STATE ? oddByte : 0;
  *aDestLength = iDestlen;
  return res;
}
