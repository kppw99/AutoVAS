NS_IMETHODIMP CVE_2012_0471_VULN_nsGBKToUnicode::ConvertNoBuff(const char* aSrc,
                                            PRInt32 * aSrcLength,
                                            PRUnichar *aDest,
                                            PRInt32 * aDestLength)
{
  PRInt32 i=0;
  PRInt32 iSrcLength = (*aSrcLength);
  PRInt32 iDestlen = 0;
  nsresult rv=NS_OK;
  *aSrcLength = 0;
  
  for (i=0;i<iSrcLength;i++)
  {
    if ( iDestlen >= (*aDestLength) )
    {
      rv = NS_OK_UDEC_MOREOUTPUT;
      break;
    }
    // The valid range for the 1st byte is [0x81,0xFE] 
    if(LEGAL_GBK_MULTIBYTE_FIRST_BYTE(*aSrc))
    {
      if(i+1 >= iSrcLength) 
      {
        rv = NS_OK_UDEC_MOREINPUT;
        break;
      }
      // To make sure, the second byte has to be checked as well.
      // In GBK, the second byte range is [0x40,0x7E] and [0x80,0XFE]
      if(LEGAL_GBK_2BYTE_SECOND_BYTE(aSrc[1]))
      {
        // Valid GBK code
        *aDest = mUtil.GBKCharToUnicode(aSrc[0], aSrc[1]);
        if(UCS2_NO_MAPPING == *aDest)
        { 
          // We cannot map in the common mapping, let's call the
          // delegate 2 byte decoder to decode the gbk or gb18030 unique 
          // 2 byte mapping
          if(! TryExtensionDecoder(aSrc, aDest))
          {
            *aDest = UCS2_NO_MAPPING;
          }
        }
        aSrc += 2;
        i++;
      }
      else if (LEGAL_GBK_4BYTE_SECOND_BYTE(aSrc[1]))
      {
        // from the first 2 bytes, it looks like a 4 byte GB18030
        if(i+3 >= iSrcLength)  // make sure we got 4 bytes
        {
          rv = NS_OK_UDEC_MOREINPUT;
          break;
        }
        // 4 bytes patten
        // [0x81-0xfe][0x30-0x39][0x81-0xfe][0x30-0x39]
        // preset the 
 
        if (LEGAL_GBK_4BYTE_THIRD_BYTE(aSrc[2]) &&
            LEGAL_GBK_4BYTE_FORTH_BYTE(aSrc[3]))
        {
           if ( ! FIRST_BYTE_IS_SURROGATE(aSrc[0])) 
           {
             // let's call the delegated 4 byte gb18030 converter to convert it
             if(! Try4BytesDecoder(aSrc, aDest))
               *aDest = UCS2_NO_MAPPING;
           } else {
              // let's try supplement mapping
             if ( (iDestlen+1) < (*aDestLength) )
             {
               if(DecodeToSurrogate(aSrc, aDest))
               {
                 // surrogte two PRUnichar
                 iDestlen++;
                 aDest++;
               }  else {
                 *aDest = UCS2_NO_MAPPING;
              }
             } else {
               if (*aDestLength < 2) {
                 NS_ERROR("insufficient space in output buffer");
                 *aDest = UCS2_NO_MAPPING;
               } else {
                 rv = NS_OK_UDEC_MOREOUTPUT;
                 break;
               }
             }
           }
        } else {
          *aDest = UCS2_NO_MAPPING; 
        }
        aSrc += 4;
        i+=3;
      }
      else if ((PRUint8) aSrc[0] == (PRUint8)0xA0 )
      {
        // stand-alone (not followed by a valid second byte) 0xA0 !
        // treat it as valid a la Netscape 4.x
        *aDest = CAST_CHAR_TO_UNICHAR(*aSrc);
        aSrc++;
      } else {
        // Invalid GBK code point (second byte should be 0x40 or higher)
        *aDest = UCS2_NO_MAPPING;
        aSrc++;
      }
    } else {
      if(IS_ASCII(*aSrc))
      {
        // The source is an ASCII
        *aDest = CAST_CHAR_TO_UNICHAR(*aSrc);
        aSrc++;
      } else {
        if(IS_GBK_EURO(*aSrc)) {
          *aDest = UCS2_EURO;
        } else {
          *aDest = UCS2_NO_MAPPING;
        }
        aSrc++;
      }
    }
    iDestlen++;
    aDest++;
    *aSrcLength = i+1;
  }
  *aDestLength = iDestlen;
  return rv;
}
