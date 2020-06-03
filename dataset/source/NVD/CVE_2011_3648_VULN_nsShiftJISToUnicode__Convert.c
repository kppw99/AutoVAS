NS_IMETHODIMP CVE_2011_3648_VULN_nsShiftJISToUnicode::Convert(
   const char * aSrc, PRInt32 * aSrcLen,
     PRUnichar * aDest, PRInt32 * aDestLen)
{
   static const PRUint8 sbIdx[256] =
   {
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x00 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x08 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x10 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x18 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x20 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x28 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x30 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /* 0x38 */
        0,    1,    2,    3,    4,    5,    6,    7,  /* 0x40 */
        8,    9,   10,   11,   12,   13,   14,   15,  /* 0x48 */
       16,   17,   18,   19,   20,   21,   22,   23,  /* 0x50 */
       24,   25,   26,   27,   28,   29,   30,   31,  /* 0x58 */
       32,   33,   34,   35,   36,   37,   38,   39,  /* 0x60 */
       40,   41,   42,   43,   44,   45,   46,   47,  /* 0x68 */
       48,   49,   50,   51,   52,   53,   54,   55,  /* 0x70 */
       56,   57,   58,   59,   60,   61,   62, 0xFF,  /* 0x78 */
       63,   64,   65,   66,   67,   68,   69,   70,  /* 0x80 */
       71,   72,   73,   74,   75,   76,   77,   78,  /* 0x88 */
       79,   80,   81,   82,   83,   84,   85,   86,  /* 0x90 */
       87,   88,   89,   90,   91,   92,   93,   94,  /* 0x98 */
       95,   96,   97,   98,   99,  100,  101,  102,  /* 0xa0 */
      103,  104,  105,  106,  107,  108,  109,  110,  /* 0xa8 */
      111,  112,  113,  114,  115,  116,  117,  118,  /* 0xb0 */
      119,  120,  121,  122,  123,  124,  125,  126,  /* 0xb8 */
      127,  128,  129,  130,  131,  132,  133,  134,  /* 0xc0 */
      135,  136,  137,  138,  139,  140,  141,  142,  /* 0xc8 */
      143,  144,  145,  146,  147,  148,  149,  150,  /* 0xd0 */
      151,  152,  153,  154,  155,  156,  157,  158,  /* 0xd8 */
      159,  160,  161,  162,  163,  164,  165,  166,  /* 0xe0 */
      167,  168,  169,  170,  171,  172,  173,  174,  /* 0xe8 */
      175,  176,  177,  178,  179,  180,  181,  182,  /* 0xf0 */
      183,  184,  185,  186,  187, 0xFF, 0xFF, 0xFF,  /* 0xf8 */
   };

   const unsigned char* srcEnd = (unsigned char*)aSrc + *aSrcLen;
   const unsigned char* src =(unsigned char*) aSrc;
   PRUnichar* destEnd = aDest + *aDestLen;
   PRUnichar* dest = aDest;
   while((src < srcEnd))
   {
       switch(mState)
       {

          case 0:
          if(*src & 0x80)
          {
            mData = SJIS_INDEX[*src & 0x7F];
            if(mData < 0xE000 )
            {
               mState = 1; // two bytes 
            } else {
               if( mData > 0xFF00)
               {
                 if(0xFFFD == mData) {
                   // IE-compatible handling of undefined codepoints:
                   // 0x80 --> U+0080
                   // 0xa0 --> U+F8F0
                   // 0xfd --> U+F8F1
                   // 0xfe --> U+F8F2
                   // 0xff --> U+F8F3
                   switch (*src) {
                     case 0x80:
                       *dest++ = (PRUnichar) *src;
                       break;

                     case 0xa0:
                       *dest++ = (PRUnichar) 0xf8f0;
                       break;

                     case 0xfd:
                     case 0xfe:
                     case 0xff:
                       *dest++ = (PRUnichar) 0xf8f1 + 
                                   (*src - (unsigned char)(0xfd));
                       break;

                     default:
                       if (mErrBehavior == kOnError_Signal)
                         goto error_invalidchar;
                       *dest++ = SJIS_UNMAPPED;
                   }
                   if(dest >= destEnd)
                     goto error1;
                 } else {
                   *dest++ = mData; // JIS 0201
                   if(dest >= destEnd)
                     goto error1;
                 }
               } else {
                 mState = 2; // EUDC
               }
            }
          } else {
            // ASCII
            *dest++ = (PRUnichar) *src;
            if(dest >= destEnd)
              goto error1;
          }
          break;

          case 1: // Index to table
          {
            PRUint8 off = sbIdx[*src];
            if(0xFF == off) {
               if (mErrBehavior == kOnError_Signal)
                 goto error_invalidchar;
               *dest++ = SJIS_UNMAPPED;
            } else {
               PRUnichar ch = gJapaneseMap[mData+off];
               if(ch == 0xfffd) {
                 if (mErrBehavior == kOnError_Signal)
                   goto error_invalidchar;
                 ch = SJIS_UNMAPPED;
               }
               *dest++ = ch;
            }
            mState = 0;
            if(dest >= destEnd)
              goto error1;
          }
          break;

          case 2: // EUDC
          {
            PRUint8 off = sbIdx[*src];
            if(0xFF == off) {
               if (mErrBehavior == kOnError_Signal)
                 goto error_invalidchar;

               *dest++ = SJIS_UNMAPPED;
            } else {
               *dest++ = mData + off;
            }
            mState = 0;
            if(dest >= destEnd)
              goto error1;
          }
          break;

       }
       src++;
   }
   *aDestLen = dest - aDest;
   return NS_OK;
error_invalidchar:
   *aDestLen = dest - aDest;
   *aSrcLen = src - (const unsigned char*)aSrc;
   return NS_ERROR_ILLEGAL_INPUT;
error1:
   *aDestLen = dest - aDest;
   src++;
   if ((mState == 0) && (src == srcEnd)) {
     return NS_OK;
   }
   *aSrcLen = src - (const unsigned char*)aSrc;
   return NS_OK_UDEC_MOREOUTPUT;
}
