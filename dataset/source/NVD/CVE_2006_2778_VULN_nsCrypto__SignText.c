NS_IMETHODIMP
CVE_2006_2778_VULN_nsCrypto::SignText(const nsAString& aStringToSign, const nsAString& aCaOption,
                   nsAString& aResult)
{
  // XXX This code should return error codes, but we're keeping this
  //     backwards compatible with NS4.x and so we can't throw exceptions.
  NS_NAMED_LITERAL_STRING(internalError, "error:internalError");

  aResult.Truncate();

  nsCOMPtr<nsIXPCNativeCallContext> ncc;
  nsCOMPtr<nsIXPConnect> xpc(do_GetService(nsIXPConnect::GetCID()));
  if (xpc) {
    xpc->GetCurrentNativeCallContext(getter_AddRefs(ncc));
  }

  if (!ncc) {
    aResult.Append(internalError);

    return NS_OK;
  }

  PRUint32 argc;
  ncc->GetArgc(&argc);

  JSContext *cx;
  ncc->GetJSContext(&cx);
  if (!cx) {
    aResult.Append(internalError);

    return NS_OK;
  }

  if (!aCaOption.Equals(NS_LITERAL_STRING("auto")) &&
      !aCaOption.Equals(NS_LITERAL_STRING("ask"))) {
    JS_ReportError(cx, "%s%s\n", JS_ERROR, "caOption argument must be ask or auto");

    aResult.Append(internalError);

    return NS_OK;
  }

  // It was decided to always behave as if "ask" were specified.
  // XXX Should we warn in the JS Console for auto?

  nsCOMPtr<nsIInterfaceRequestor> uiContext = new PipUIContext;
  if (!uiContext) {
    aResult.Append(internalError);

    return NS_OK;
  }

  PRBool bestOnly = PR_TRUE;
  PRBool validOnly = PR_TRUE;
  CERTCertList* certList =
    CERT_FindUserCertsByUsage(CERT_GetDefaultCertDB(), certUsageEmailSigner,
                              bestOnly, validOnly, uiContext);

  PRUint32 numCAs = argc - 2;
  if (numCAs > 0) {
    nsAutoArrayPtr<char*> caNames(new char*[numCAs]);
    if (!caNames) {
      aResult.Append(internalError);

      return NS_OK;
    }

    jsval *argv = nsnull;
    ncc->GetArgvPtr(&argv);

    PRUint32 i;
    for (i = 2; i < argc; ++i) {
      JSString *caName = JS_ValueToString(cx, argv[i]);
      if (!caName) {
        aResult.Append(internalError);

        return NS_OK;
      }
      caNames[i] = JS_GetStringBytes(caName);
    }

    if (certList &&
        CERT_FilterCertListByCANames(certList, numCAs, caNames,
                                     certUsageEmailSigner) != SECSuccess) {
      aResult.Append(internalError);

      return NS_OK;
    }
  }

  if (!certList || CERT_LIST_EMPTY(certList)) {
    aResult.Append(NS_LITERAL_STRING("error:noMatchingCert"));

    return NS_OK;
  }

  nsCOMPtr<nsIFormSigningDialog> fsd =
    do_CreateInstance(NS_FORMSIGNINGDIALOG_CONTRACTID);
  if (!fsd) {
    aResult.Append(internalError);

    return NS_OK;
  }

  nsCOMPtr<nsIProxyObjectManager> proxyman =
    do_GetService(NS_XPCOMPROXY_CONTRACTID);
  if (!proxyman) {
    aResult.Append(internalError);

    return NS_OK;
  }

  nsCOMPtr<nsIFormSigningDialog> proxied_fsd;
  nsresult rv = proxyman->GetProxyForObject(NS_UI_THREAD_EVENTQ,
                                            NS_GET_IID(nsIFormSigningDialog), 
                                            fsd, PROXY_SYNC,
                                            getter_AddRefs(proxied_fsd));
  if (NS_FAILED(rv)) {
    aResult.Append(internalError);

    return NS_OK;
  }

  nsCOMPtr<nsIDocument> document;
  GetDocumentFromContext(cx, getter_AddRefs(document));
  if (!document) {
    aResult.Append(internalError);

    return NS_OK;
  }

  // Get the hostname from the URL of the document.
  nsIURI* uri = document->GetDocumentURI();
  if (!uri) {
    aResult.Append(internalError);

    return NS_OK;
  }

  nsCString host;
  rv = uri->GetHost(host);
  if (NS_FAILED(rv)) {
    aResult.Append(internalError);

    return NS_OK;
  }

  PRInt32 numberOfCerts = 0;
  CERTCertListNode* node;
  for (node = CERT_LIST_HEAD(certList); !CERT_LIST_END(node, certList);
       node = CERT_LIST_NEXT(node)) {
    ++numberOfCerts;
  }

  CERTCertNicknames* nicknames =
    CERT_NicknameStringsFromCertList(certList, NICKNAME_EXPIRED_STRING,
                                     NICKNAME_NOT_YET_VALID_STRING);
  if (!nicknames) {
    aResult.Append(internalError);

    return NS_OK;
  }

  CERTCertNicknamesCleaner cnc(nicknames);

  NS_ASSERTION(nicknames->numnicknames == numberOfCerts,
               "nicknames->numnicknames != numberOfCerts");

  nsAutoArrayPtr<PRUnichar*> certNicknameList(new PRUnichar*[nicknames->numnicknames * 2]);
  if (!certNicknameList) {
    aResult.Append(internalError);

    return NS_OK;
  }

  PRUnichar** certDetailsList = certNicknameList.get() + nicknames->numnicknames;

  PRInt32 certsToUse;
  for (node = CERT_LIST_HEAD(certList), certsToUse = 0;
       !CERT_LIST_END(node, certList) && certsToUse < nicknames->numnicknames;
       node = CERT_LIST_NEXT(node)) {
    nsRefPtr<nsNSSCertificate> tempCert = new nsNSSCertificate(node->cert);
    if (tempCert) {
      nsAutoString nickWithSerial, details;
      rv = tempCert->FormatUIStrings(NS_ConvertUTF8toUTF16(nicknames->nicknames[certsToUse]),
                                     nickWithSerial, details);
      if (NS_SUCCEEDED(rv)) {
        certNicknameList[certsToUse] = ToNewUnicode(nickWithSerial);
        if (certNicknameList[certsToUse]) {
          certDetailsList[certsToUse] = ToNewUnicode(details);
          if (!certDetailsList[certsToUse]) {
            nsMemory::Free(certNicknameList[certsToUse]);
            continue;
          }
          ++certsToUse;
        }
      }
    }
  }

  if (certsToUse == 0) {
    aResult.Append(internalError);

    return NS_OK;
  }

  NS_ConvertUTF8toUTF16 utf16Host(host);

  CERTCertificate *signingCert = nsnull;
  PRBool tryAgain, canceled;
  nsAutoString password;
  do {
    // Throw up the form signing confirmation dialog and get back the index
    // of the selected cert.
    PRInt32 selectedIndex = -1;
    rv = proxied_fsd->ConfirmSignText(uiContext, utf16Host, aStringToSign,
                                      NS_CONST_CAST(const PRUnichar**, certNicknameList.get()),
                                      NS_CONST_CAST(const PRUnichar**, certDetailsList),
                                      certsToUse, &selectedIndex, password,
                                      &canceled);
    if (NS_FAILED(rv) || canceled) {
      break; // out of tryAgain loop
    }

    PRInt32 j = 0;
    for (node = CERT_LIST_HEAD(certList); !CERT_LIST_END(node, certList);
         node = CERT_LIST_NEXT(node)) {
      if (j == selectedIndex) {
        signingCert = CERT_DupCertificate(node->cert);
        break; // out of cert list iteration loop
      }
      ++j;
    }

    if (!signingCert) {
      rv = NS_ERROR_FAILURE;
      break; // out of tryAgain loop
    }

    NS_ConvertUTF16toUTF8 pwUtf8(password);

    tryAgain =
      PK11_CheckUserPassword(signingCert->slot,
                             NS_CONST_CAST(char *, pwUtf8.get())) != SECSuccess;
    // XXX we should show an error dialog before retrying
  } while (tryAgain);

  PRInt32 k;
  for (k = 0; k < certsToUse; ++k) {
    nsMemory::Free(certNicknameList[k]);
    nsMemory::Free(certDetailsList[k]);
  }

  if (NS_FAILED(rv)) { // something went wrong inside the tryAgain loop
    aResult.Append(internalError);

    return NS_OK;
  }

  if (canceled) {
    aResult.Append(NS_LITERAL_STRING("error:userCancel"));

    return NS_OK;
  }

  SECKEYPrivateKey* privKey = PK11_FindKeyByAnyCert(signingCert, uiContext);
  if (!privKey) {
    aResult.Append(internalError);

    return NS_OK;
  }

  nsCAutoString charset(document->GetDocumentCharacterSet());

  // XXX Doing what nsFormSubmission::GetEncoder does (see
  //     http://bugzilla.mozilla.org/show_bug.cgi?id=81203).
  if (charset.Equals(NS_LITERAL_CSTRING("ISO-8859-1"))) {
    charset.Assign(NS_LITERAL_CSTRING("windows-1252"));
  }

  nsCOMPtr<nsISaveAsCharset> encoder =
    do_CreateInstance(NS_SAVEASCHARSET_CONTRACTID);
  if (encoder) {
    rv = encoder->Init(charset.get(),
                       (nsISaveAsCharset::attr_EntityAfterCharsetConv + 
                       nsISaveAsCharset::attr_FallbackDecimalNCR),
                       0);
  }

  nsXPIDLCString buffer;
  if (aStringToSign.Length() > 0) {
    if (encoder && NS_SUCCEEDED(rv)) {
      rv = encoder->Convert(PromiseFlatString(aStringToSign).get(),
                            getter_Copies(buffer));
      if (NS_FAILED(rv)) {
        aResult.Append(internalError);

        return NS_OK;
      }
    }
    else {
      AppendUTF16toUTF8(aStringToSign, buffer);
    }
  }

  HASHContext *hc = HASH_Create(HASH_AlgSHA1);
  if (!hc) {
    aResult.Append(internalError);

    return NS_OK;
  }

  unsigned char hash[SHA1_LENGTH];

  SECItem digest;
  digest.data = hash;

  HASH_Begin(hc);
  HASH_Update(hc, NS_REINTERPRET_CAST(const unsigned char*, buffer.get()),
              buffer.Length());
  HASH_End(hc, digest.data, &digest.len, SHA1_LENGTH);
  HASH_Destroy(hc);

  nsCString p7;
  SECStatus srv = SECFailure;

  SEC_PKCS7ContentInfo *ci = SEC_PKCS7CreateSignedData(signingCert,
                                                       certUsageEmailSigner,
                                                       nsnull, SEC_OID_SHA1,
                                                       &digest, nsnull, uiContext);
  if (ci) {
    srv = SEC_PKCS7IncludeCertChain(ci, nsnull);
    if (srv == SECSuccess) {
      srv = SEC_PKCS7AddSigningTime(ci);
      if (srv == SECSuccess) {
        srv = SEC_PKCS7Encode(ci, signTextOutputCallback, &p7, nsnull, nsnull,
                              uiContext);
      }
    }

    SEC_PKCS7DestroyContentInfo(ci);
  }

  if (srv != SECSuccess) {
    aResult.Append(internalError);

    return NS_OK;
  }

  SECItem binary_item;
  binary_item.data = NS_REINTERPRET_CAST(unsigned char*,
                                         NS_CONST_CAST(char*, p7.get()));
  binary_item.len = p7.Length();

  char *result = NSSBase64_EncodeItem(nsnull, nsnull, 0, &binary_item);
  if (result) {
    AppendASCIItoUTF16(result, aResult);
  }
  else {
    aResult.Append(internalError);
  }

  PORT_Free(result);

  return NS_OK;
}
