inline PRBool
CVE_2010_3774_VULN_NS_SecurityCompareURIs(nsIURI* aSourceURI,
                       nsIURI* aTargetURI,
                       PRBool aStrictFileOriginPolicy)
{
    // Note that this is not an Equals() test on purpose -- for URIs that don't
    // support host/port, we want equality to basically be object identity, for
    // security purposes.  Otherwise, for example, two javascript: URIs that
    // are otherwise unrelated could end up "same origin", which would be
    // unfortunate.
    if (aSourceURI && aSourceURI == aTargetURI)
    {
        return PR_TRUE;
    }

    if (!aTargetURI || !aSourceURI)
    {
        return PR_FALSE;
    }

    // If either URI is a nested URI, get the base URI
    nsCOMPtr<nsIURI> sourceBaseURI = NS_GetInnermostURI(aSourceURI);
    nsCOMPtr<nsIURI> targetBaseURI = NS_GetInnermostURI(aTargetURI);

    if (!sourceBaseURI || !targetBaseURI)
        return PR_FALSE;

    // Compare schemes
    nsCAutoString targetScheme;
    PRBool sameScheme = PR_FALSE;
    if (NS_FAILED( targetBaseURI->GetScheme(targetScheme) ) ||
        NS_FAILED( sourceBaseURI->SchemeIs(targetScheme.get(), &sameScheme) ) ||
        !sameScheme)
    {
        // Not same-origin if schemes differ
        return PR_FALSE;
    }

    // special handling for file: URIs
    if (targetScheme.EqualsLiteral("file"))
    {
        // in traditional unsafe behavior all files are the same origin
        if (!aStrictFileOriginPolicy)
            return PR_TRUE;

        nsCOMPtr<nsIFileURL> sourceFileURL(do_QueryInterface(sourceBaseURI));
        nsCOMPtr<nsIFileURL> targetFileURL(do_QueryInterface(targetBaseURI));

        if (!sourceFileURL || !targetFileURL)
            return PR_FALSE;

        nsCOMPtr<nsIFile> sourceFile, targetFile;

        sourceFileURL->GetFile(getter_AddRefs(sourceFile));
        targetFileURL->GetFile(getter_AddRefs(targetFile));

        if (!sourceFile || !targetFile)
            return PR_FALSE;

        // Otherwise they had better match
        PRBool filesAreEqual = PR_FALSE;
        nsresult rv = sourceFile->Equals(targetFile, &filesAreEqual);
        return NS_SUCCEEDED(rv) && filesAreEqual;
    }

    // Special handling for mailnews schemes
    if (targetScheme.EqualsLiteral("imap") ||
        targetScheme.EqualsLiteral("mailbox") ||
        targetScheme.EqualsLiteral("news"))
    {
        // Each message is a distinct trust domain; use the
        // whole spec for comparison
        nsCAutoString targetSpec;
        nsCAutoString sourceSpec;
        return ( NS_SUCCEEDED( targetBaseURI->GetSpec(targetSpec) ) &&
                 NS_SUCCEEDED( sourceBaseURI->GetSpec(sourceSpec) ) &&
                 targetSpec.Equals(sourceSpec) );
    }

    // Compare hosts
    nsCAutoString targetHost;
    nsCAutoString sourceHost;
    if (NS_FAILED( targetBaseURI->GetAsciiHost(targetHost) ) ||
        NS_FAILED( sourceBaseURI->GetAsciiHost(sourceHost) ))
    {
        return PR_FALSE;
    }

#ifdef MOZILLA_INTERNAL_API
    if (!targetHost.Equals(sourceHost, nsCaseInsensitiveCStringComparator() ))
#else
    if (!targetHost.Equals(sourceHost, CaseInsensitiveCompare))
#endif
    {
        return PR_FALSE;
    }

    return NS_GetRealPort(targetBaseURI) == NS_GetRealPort(sourceBaseURI);
}
