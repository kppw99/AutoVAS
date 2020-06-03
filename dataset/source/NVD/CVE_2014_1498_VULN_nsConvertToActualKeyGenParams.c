static void*
CVE_2014_1498_VULN_nsConvertToActualKeyGenParams(PRUint32 keyGenMech, char *params,
                              PRUint32 paramLen, PRInt32 keySize,
                              nsKeyPairInfo *keyPairInfo)
{
  void *returnParams = nsnull;


  switch (keyGenMech) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
  {
    // For RSA, we don't support passing in key generation arguments from
    // the JS code just yet.
    if (params)
      return nsnull;

    PK11RSAGenParams *rsaParams;
    rsaParams = static_cast<PK11RSAGenParams*>
                           (nsMemory::Alloc(sizeof(PK11RSAGenParams)));
                              
    if (rsaParams == nsnull) {
      return nsnull;
    }
    /* I'm just taking the same parameters used in 
     * certdlgs.c:GenKey
     */
    if (keySize > 0) {
      rsaParams->keySizeInBits = keySize;
    } else {
      rsaParams->keySizeInBits = 1024;
    }
    rsaParams->pe = DEFAULT_RSA_KEYGEN_PE;
    returnParams = rsaParams;
    break;
  }
  case CKM_EC_KEY_PAIR_GEN:
  {
    /*
     * keygen params for generating EC keys must be composed of name=value pairs,
     * multiple pairs allowed, separated using semicolon ;
     *
     * Either param "curve" or param "popcert" must be specified.
     * curve=name-of-curve
     * popcert=base64-encoded-cert
     *
     * When both params are specified, popcert will be used.
     * If no popcert param is given, or if popcert can not be decoded,
     * we will fall back to the curve param.
     *
     * Additional name=value pairs may be defined in the future.
     *
     * If param popcert is present and valid, the given certificate will be used
     * to determine the key generation params. In addition the certificate
     * will be used to produce a dhMac based Proof of Posession,
     * using the cert's public key, subject and issuer names,
     * as specified in RFC 2511 section 4.3 paragraph 2 and Appendix A.
     *
     * If neither param popcert nor param curve could be used,
     * tse a curve based on the keysize param.
     * NOTE: Here keysize is used only as an indication of
     * High/Medium/Low strength; elliptic curve
     * cryptography uses smaller keys than RSA to provide
     * equivalent security.
     */

    char *curve = nsnull;

    {
      // extract components of name=value list

      char *next_input = params;
      char *name = nsnull;
      char *value = nsnull;
      int name_len = 0;
      int value_len = 0;
  
      while (getNextNameValueFromECKeygenParamString(
              next_input, name, name_len, value, value_len,
              next_input))
      {
        if (PL_strncmp(name, "curve", NS_MIN(name_len, 5)) == 0)
        {
          curve = PL_strndup(value, value_len);
        }
        else if (PL_strncmp(name, "popcert", NS_MIN(name_len, 7)) == 0)
        {
          char *certstr = PL_strndup(value, value_len);
          if (certstr) {
            keyPairInfo->ecPopCert = CERT_ConvertAndDecodeCertificate(certstr);
            PL_strfree(certstr);

            if (keyPairInfo->ecPopCert)
            {
              keyPairInfo->ecPopPubKey = CERT_ExtractPublicKey(keyPairInfo->ecPopCert);
            }
          }
        }
      }
    }

    // first try to use the params of the provided CA cert
    if (keyPairInfo->ecPopPubKey)
    {
      returnParams = SECITEM_DupItem(&keyPairInfo->ecPopPubKey->u.ec.DEREncodedParams);
    }

    // if we did not yet find good params, do we have a curve name?
    if (!returnParams && curve)
    {
      returnParams = decode_ec_params(curve);
    }

    // if we did not yet find good params, do something based on keysize
    if (!returnParams)
    {
      switch (keySize) {
      case 512:
      case 1024:
          returnParams = decode_ec_params("secp256r1");
          break;
      case 2048:
      default:
          returnParams = decode_ec_params("secp384r1");
          break;
      }
    }

    if (curve)
      PL_strfree(curve);

    break;
  }
  case CKM_DSA_KEY_PAIR_GEN:
  {
    // For DSA, we don't support passing in key generation arguments from
    // the JS code just yet.
    if (params)
      return nsnull;

    PQGParams *pqgParams = nsnull;
    PQGVerify *vfy = nsnull;
    SECStatus  rv;
    int        index;
       
    index = PQG_PBITS_TO_INDEX(keySize);
    if (index == -1) {
      returnParams = nsnull;
      break;
    }
    rv = PK11_PQG_ParamGen(0, &pqgParams, &vfy);
    if (vfy) {
      PK11_PQG_DestroyVerify(vfy);
    }
    if (rv != SECSuccess) {
      if (pqgParams) {
        PK11_PQG_DestroyParams(pqgParams);
      }
      return nsnull;
    }
    returnParams = pqgParams;
    break;
  }
  default:
    returnParams = nsnull;
  }
  return returnParams;
}
