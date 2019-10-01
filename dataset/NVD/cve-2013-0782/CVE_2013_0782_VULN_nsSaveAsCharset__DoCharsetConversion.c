NS_IMETHODIMP
CVE_2013_0782_VULN_nsSaveAsCharset::DoCharsetConversion(const PRUnichar *inString, char **outString)
{
  NS_ENSURE_ARG_POINTER(outString);

  *outString = nullptr;

  nsresult rv;
  int32_t inStringLength = NS_strlen(inString);       // original input string length
  int32_t bufferLength;                               // allocated buffer length
  int32_t srcLength = inStringLength;
  int32_t dstLength;
  int32_t pos1, pos2;
  nsresult saveResult = NS_OK;                         // to remember NS_ERROR_UENC_NOMAPPING

  // estimate and allocate the target buffer (reserve extra memory for fallback)
  rv = mEncoder->GetMaxLength(inString, inStringLength, &dstLength);
  if (NS_FAILED(rv)) return rv;

  bufferLength = dstLength + 512; // reserve 512 byte for fallback.
  char *dstPtr = (char *) PR_Malloc(bufferLength);
  
  for (pos1 = 0, pos2 = 0; pos1 < inStringLength;) {
    // convert from unicode
    dstLength = bufferLength - pos2;
    rv = mEncoder->Convert(&inString[pos1], &srcLength, &dstPtr[pos2], &dstLength);

    pos1 += srcLength ? srcLength : 1;
    pos2 += dstLength;
    dstPtr[pos2] = '\0';

    // break: this is usually the case (no error) OR unrecoverable error
    if (NS_ERROR_UENC_NOMAPPING != rv) break;

    // remember this happened and reset the result
    saveResult = rv;
    rv = NS_OK;

    // finish encoder, give it a chance to write extra data like escape sequences
    dstLength = bufferLength - pos2;
    rv = mEncoder->Finish(&dstPtr[pos2], &dstLength);
    if (NS_SUCCEEDED(rv)) {
      pos2 += dstLength;
      dstPtr[pos2] = '\0';
    }

    srcLength = inStringLength - pos1;

    // do the fallback
    if (!ATTR_NO_FALLBACK(mAttribute)) {
      uint32_t unMappedChar;
      if (NS_IS_HIGH_SURROGATE(inString[pos1-1]) && 
          inStringLength > pos1 && NS_IS_LOW_SURROGATE(inString[pos1])) {
        unMappedChar = SURROGATE_TO_UCS4(inString[pos1-1], inString[pos1]);
        pos1++;
      } else {
        unMappedChar = inString[pos1-1];
      }

      rv = mEncoder->GetMaxLength(inString+pos1, inStringLength-pos1, &dstLength);
      if (NS_FAILED(rv)) 
        break;

      rv = HandleFallBack(unMappedChar, &dstPtr, &bufferLength, &pos2, dstLength);
      if (NS_FAILED(rv)) 
        break;
      dstPtr[pos2] = '\0';
    }
  }

  if (NS_SUCCEEDED(rv)) {
    // finish encoder, give it a chance to write extra data like escape sequences
    dstLength = bufferLength - pos2;
    rv = mEncoder->Finish(&dstPtr[pos2], &dstLength);
    if (NS_SUCCEEDED(rv)) {
      pos2 += dstLength;
      dstPtr[pos2] = '\0';
    }
  }

  if (NS_FAILED(rv)) {
    PR_FREEIF(dstPtr);
    return rv;
  }

  *outString = dstPtr;      // set the result string

  // set error code so that the caller can do own fall back
  if (NS_ERROR_UENC_NOMAPPING == saveResult) {
    rv = NS_ERROR_UENC_NOMAPPING;
  }

  return rv;
}
