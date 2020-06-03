SECStatus
CVE_2013_0791_VULN_CERT_DecodeCertPackage(char *certbuf,
		       int certlen,
		       CERTImportCertificateFunc f,
		       void *arg)
{
    unsigned char *cp;
    unsigned char *bincert = NULL;
    char *         ascCert = NULL;
    SECStatus      rv;
    
    if ( certbuf == NULL ) {
	return(SECFailure);
    }
    
    cp = (unsigned char *)certbuf;

    /* is a DER encoded certificate of some type? */
    if ( ( *cp  & 0x1f ) == SEC_ASN1_SEQUENCE ) {
	SECItem certitem;
	SECItem *pcertitem = &certitem;
	int seqLen, seqLenLen;

	cp++;
	
	if ( *cp & 0x80) {
	    /* Multibyte length */
	    seqLenLen = cp[0] & 0x7f;
	    
	    switch (seqLenLen) {
	      case 4:
		seqLen = ((unsigned long)cp[1]<<24) |
		    ((unsigned long)cp[2]<<16) | (cp[3]<<8) | cp[4];
		break;
	      case 3:
		seqLen = ((unsigned long)cp[1]<<16) | (cp[2]<<8) | cp[3];
		break;
	      case 2:
		seqLen = (cp[1]<<8) | cp[2];
		break;
	      case 1:
		seqLen = cp[1];
		break;
	      default:
		/* indefinite length */
		seqLen = 0;
	    }
	    cp += ( seqLenLen + 1 );

	} else {
	    seqLenLen = 0;
	    seqLen = *cp;
	    cp++;
	}

	/* check entire length if definite length */
	if ( seqLen || seqLenLen ) {
	    if ( certlen != ( seqLen + seqLenLen + 2 ) ) {
		if (certlen > ( seqLen + seqLenLen + 2 ))
		    PORT_SetError(SEC_ERROR_EXTRA_INPUT);
		else 
		    PORT_SetError(SEC_ERROR_INPUT_LEN);
		goto notder;
	    }
	}
	
	/* check the type string */
	/* netscape wrapped DER cert */
	if ( ( cp[0] == SEC_ASN1_OCTET_STRING ) &&
	    ( cp[1] == CERTIFICATE_TYPE_LEN ) &&
	    ( PORT_Strcmp((char *)&cp[2], CERTIFICATE_TYPE_STRING) ) ) {
	    
	    cp += ( CERTIFICATE_TYPE_LEN + 2 );

	    /* it had better be a certificate by now!! */
	    certitem.data = cp;
	    certitem.len = certlen - ( cp - (unsigned char *)certbuf );
	    
	    rv = (* f)(arg, &pcertitem, 1);
	    
	    return(rv);
	} else if ( cp[0] == SEC_ASN1_OBJECT_ID ) {
	    SECOidData *oiddata;
	    SECItem oiditem;
	    /* XXX - assume DER encoding of OID len!! */
	    oiditem.len = cp[1];
	    oiditem.data = (unsigned char *)&cp[2];
	    oiddata = SECOID_FindOID(&oiditem);
	    if ( oiddata == NULL ) {
		return(SECFailure);
	    }

	    certitem.data = (unsigned char*)certbuf;
	    certitem.len = certlen;
	    
	    switch ( oiddata->offset ) {
	      case SEC_OID_PKCS7_SIGNED_DATA:
		return(SEC_ReadPKCS7Certs(&certitem, f, arg));
		break;
	      case SEC_OID_NS_TYPE_CERT_SEQUENCE:
		return(SEC_ReadCertSequence(&certitem, f, arg));
		break;
	      default:
		break;
	    }
	    
	} else {
	    /* it had better be a certificate by now!! */
	    certitem.data = (unsigned char*)certbuf;
	    certitem.len = certlen;
	    
	    rv = (* f)(arg, &pcertitem, 1);
	    return(rv);
	}
    }

    /* now look for a netscape base64 ascii encoded cert */
notder:
  {
    unsigned char *certbegin = NULL; 
    unsigned char *certend   = NULL;
    char          *pc;
    int cl;

    /* Convert the ASCII data into a nul-terminated string */
    ascCert = (char *)PORT_Alloc(certlen + 1);
    if (!ascCert) {
        rv = SECFailure;
	goto loser;
    }

    PORT_Memcpy(ascCert, certbuf, certlen);
    ascCert[certlen] = '\0';

    pc = PORT_Strchr(ascCert, '\n');  /* find an EOL */
    if (!pc) { /* maybe this is a MAC file */
	pc = ascCert;
	while (*pc && NULL != (pc = PORT_Strchr(pc, '\r'))) {
	    *pc++ = '\n';
	}
    }

    cp = (unsigned char *)ascCert;
    cl = certlen;

    /* find the beginning marker */
    while ( cl > NS_CERT_HEADER_LEN ) {
	int found = 0;
	if ( !PORT_Strncasecmp((char *)cp, NS_CERT_HEADER,
			        NS_CERT_HEADER_LEN) ) {
	    cl -= NS_CERT_HEADER_LEN;
	    cp += NS_CERT_HEADER_LEN;
	    found = 1;
	}
	
	/* skip to next eol */
	while ( cl && ( *cp != '\n' )) {
	    cp++;
	    cl--;
	} 

	/* skip all blank lines */
	while ( cl && ( *cp == '\n' || *cp == '\r' )) {
	    cp++;
	    cl--;
	}
	if (cl && found) {
	    certbegin = cp;
	    break;
    	}
    }

    if ( certbegin ) {
	/* find the ending marker */
	while ( cl >= NS_CERT_TRAILER_LEN ) {
	    if ( !PORT_Strncasecmp((char *)cp, NS_CERT_TRAILER,
				   NS_CERT_TRAILER_LEN) ) {
		certend = cp;
		break;
	    }

	    /* skip to next eol */
	    while ( cl && ( *cp != '\n' )) {
		cp++;
		cl--;
	    }

	    /* skip all blank lines */
	    while ( cl && ( *cp == '\n' || *cp == '\r' )) {
		cp++;
		cl--;
	    }
	}
    }

    if ( certbegin && certend ) {
	unsigned int binLen;

	*certend = 0;
	/* convert to binary */
	bincert = ATOB_AsciiToData((char *)certbegin, &binLen);
	if (!bincert) {
	    rv = SECFailure;
	    goto loser;
	}

	/* now recurse to decode the binary */
	rv = CVE_2013_0791_VULN_CERT_DecodeCertPackage((char *)bincert, binLen, f, arg);
	
    } else {
	PORT_SetError(SEC_ERROR_BAD_DER);
	rv = SECFailure;
    }
  }

loser:

    if ( bincert ) {
	PORT_Free(bincert);
    }

    if ( ascCert ) {
	PORT_Free(ascCert);
    }

    return(rv);
}
