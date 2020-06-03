bool CVE_2012_1961_VULN_nsDSURIContentListener::CheckFrameOptions(nsIRequest* request)
{
    // If X-Frame-Options checking is disabled, return true unconditionally.
    if (sIgnoreXFrameOptions) {
        return true;
    }

    nsCAutoString xfoHeaderValue;

    nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(request);
    if (!httpChannel) {
        return true;
    }

    httpChannel->GetResponseHeader(NS_LITERAL_CSTRING("X-Frame-Options"),
                                   xfoHeaderValue);

    // return early if header does not have one of the two values with meaning
    if (!xfoHeaderValue.LowerCaseEqualsLiteral("deny") &&
        !xfoHeaderValue.LowerCaseEqualsLiteral("sameorigin"))
        return true;

    if (mDocShell) {
        // We need to check the location of this window and the location of the top
        // window, if we're not the top.  X-F-O: SAMEORIGIN requires that the
        // document must be same-origin with top window.  X-F-O: DENY requires that
        // the document must never be framed.
        nsCOMPtr<nsIDOMWindow> thisWindow = do_GetInterface(static_cast<nsIDocShell*>(mDocShell));
        // If we don't have DOMWindow there is no risk of clickjacking
        if (!thisWindow)
            return true;

        nsCOMPtr<nsIDOMWindow> topWindow;
        thisWindow->GetTop(getter_AddRefs(topWindow));

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
        if (!ssm)
            return false;

        // Traverse up the parent chain to the top docshell that doesn't have
        // a system principal
        while (NS_SUCCEEDED(curDocShellItem->GetParent(getter_AddRefs(parentDocShellItem))) &&
               parentDocShellItem) {
            bool system = false;
            topDoc = do_GetInterface(parentDocShellItem);
            if (topDoc) {
                if (NS_SUCCEEDED(ssm->IsSystemPrincipal(topDoc->NodePrincipal(),
                                                        &system)) && system) {
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

        // If the X-Frame-Options value is SAMEORIGIN, then the top frame in the
        // parent chain must be from the same origin as this document.
        if (xfoHeaderValue.LowerCaseEqualsLiteral("sameorigin")) {
            nsCOMPtr<nsIURI> uri;
            httpChannel->GetURI(getter_AddRefs(uri));
            topDoc = do_GetInterface(curDocShellItem);
            nsCOMPtr<nsIURI> topUri;
            topDoc->NodePrincipal()->GetURI(getter_AddRefs(topUri));
            rv = ssm->CheckSameOriginURI(uri, topUri, true);
            if (NS_SUCCEEDED(rv))
                return true;
        }

        else {
            // If the value of the header is DENY, then the document
            // should never be permitted to load as a subdocument.
            NS_ASSERTION(xfoHeaderValue.LowerCaseEqualsLiteral("deny"),
                         "How did we get here with some random header value?");
        }

        // cancel the load and display about:blank
        httpChannel->Cancel(NS_BINDING_ABORTED);
        nsCOMPtr<nsIWebNavigation> webNav(do_QueryObject(mDocShell));
        if (webNav) {
            webNav->LoadURI(NS_LITERAL_STRING("about:blank").get(),
                            0, nsnull, nsnull, nsnull);
        }
        return false;
    }

    return true;
}
