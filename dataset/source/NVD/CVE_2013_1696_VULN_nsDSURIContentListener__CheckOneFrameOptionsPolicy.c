bool CVE_2013_1696_VULN_nsDSURIContentListener::CheckOneFrameOptionsPolicy(nsIRequest *request,
                                                        const nsAString& policy) {
    static const char allowFrom[] = "allow-from ";
    const uint32_t allowFromLen = ArrayLength(allowFrom) - 1;
    bool isAllowFrom =
        StringHead(policy, allowFromLen).LowerCaseEqualsLiteral(allowFrom);

    // return early if header does not have one of the values with meaning
    if (!policy.LowerCaseEqualsLiteral("deny") &&
        !policy.LowerCaseEqualsLiteral("sameorigin") &&
        !isAllowFrom)
        return true;

    nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(request);
    if (!httpChannel) {
        return true;
    }

    nsCOMPtr<nsIURI> uri;
    httpChannel->GetURI(getter_AddRefs(uri));

    // XXXkhuey when does this happen?  Is returning true safe here?
    if (!mDocShell) {
        return true;
    }

    // We need to check the location of this window and the location of the top
    // window, if we're not the top.  X-F-O: SAMEORIGIN requires that the
    // document must be same-origin with top window.  X-F-O: DENY requires that
    // the document must never be framed.
    nsCOMPtr<nsIDOMWindow> thisWindow = do_GetInterface(static_cast<nsIDocShell*>(mDocShell));
    // If we don't have DOMWindow there is no risk of clickjacking
    if (!thisWindow)
        return true;

    // GetScriptableTop, not GetTop, because we want this to respect
    // <iframe mozbrowser> boundaries.
    nsCOMPtr<nsIDOMWindow> topWindow;
    thisWindow->GetScriptableTop(getter_AddRefs(topWindow));

    // if the document is in the top window, it's not in a frame.
    if (thisWindow == topWindow)
        return true;

    // Find the top docshell in our parent chain that doesn't have the system
    // principal and use it for the principal comparison.  Finding the top
    // content-type docshell doesn't work because some chrome documents are
    // loaded in content docshells (see bug 593387).
    nsCOMPtr<nsIDocShellTreeItem> thisDocShellItem(do_QueryInterface(
                                                   static_cast<nsIDocShell*> (mDocShell)));
    nsCOMPtr<nsIDocShellTreeItem> parentDocShellItem,
                                  curDocShellItem = thisDocShellItem;
    nsCOMPtr<nsIDocument> topDoc;
    nsresult rv;
    nsCOMPtr<nsIScriptSecurityManager> ssm =
        do_GetService(NS_SCRIPTSECURITYMANAGER_CONTRACTID, &rv);
    if (!ssm) {
        MOZ_CRASH();
    }

    // Traverse up the parent chain and stop when we see a docshell whose
    // parent has a system principal, or a docshell corresponding to
    // <iframe mozbrowser>.
    while (NS_SUCCEEDED(curDocShellItem->GetParent(getter_AddRefs(parentDocShellItem))) &&
           parentDocShellItem) {

        nsCOMPtr<nsIDocShell> curDocShell = do_QueryInterface(curDocShellItem);
        if (curDocShell && curDocShell->GetIsBrowserOrApp()) {
          break;
        }

        bool system = false;
        topDoc = do_GetInterface(parentDocShellItem);
        if (topDoc) {
            if (NS_SUCCEEDED(ssm->IsSystemPrincipal(topDoc->NodePrincipal(),
                                                    &system)) && system) {
                // Found a system-principled doc: last docshell was top.
                break;
            }
        }
        else {
            return false;
        }
        curDocShellItem = parentDocShellItem;
    }

    // If this document has the top non-SystemPrincipal docshell it is not being
    // framed or it is being framed by a chrome document, which we allow.
    if (curDocShellItem == thisDocShellItem)
        return true;

    // If the value of the header is DENY, and the previous condition is
    // not met (current docshell is not the top docshell), prohibit the
    // load.
    if (policy.LowerCaseEqualsLiteral("deny")) {
        ReportXFOViolation(curDocShellItem, uri, eDENY);
        return false;
    }

    topDoc = do_GetInterface(curDocShellItem);
    nsCOMPtr<nsIURI> topUri;
    topDoc->NodePrincipal()->GetURI(getter_AddRefs(topUri));

    // If the X-Frame-Options value is SAMEORIGIN, then the top frame in the
    // parent chain must be from the same origin as this document.
    if (policy.LowerCaseEqualsLiteral("sameorigin")) {
        rv = ssm->CheckSameOriginURI(uri, topUri, true);
        if (NS_FAILED(rv)) {
            ReportXFOViolation(curDocShellItem, uri, eSAMEORIGIN);
            return false; /* wasn't same-origin */
        }
    }

    // If the X-Frame-Options value is "allow-from [uri]", then the top
    // frame in the parent chain must be from that origin
    if (isAllowFrom) {
        rv = NS_NewURI(getter_AddRefs(uri),
                       Substring(policy, allowFromLen));
        if (NS_FAILED(rv))
          return false;

        rv = ssm->CheckSameOriginURI(uri, topUri, true);
        if (NS_FAILED(rv)) {
            ReportXFOViolation(curDocShellItem, uri, eALLOWFROM);
            return false;
        }
    }

    return true;
}
