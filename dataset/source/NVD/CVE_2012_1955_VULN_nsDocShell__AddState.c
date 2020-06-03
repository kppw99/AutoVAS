NS_IMETHODIMP
CVE_2012_1955_VULN_nsDocShell::AddState(nsIVariant *aData, const nsAString& aTitle,
                     const nsAString& aURL, bool aReplace, JSContext* aCx)
{
    // Implements History.pushState and History.replaceState

    // Here's what we do, roughly in the order specified by HTML5:
    // 1. Serialize aData using structured clone.
    // 2. If the third argument is present,
    //     a. Resolve the url, relative to the first script's base URL
    //     b. If (a) fails, raise a SECURITY_ERR
    //     c. Compare the resulting absolute URL to the document's address.  If
    //        any part of the URLs difer other than the <path>, <query>, and
    //        <fragment> components, raise a SECURITY_ERR and abort.
    // 3. If !aReplace:
    //     Remove from the session history all entries after the current entry,
    //     as we would after a regular navigation, and save the current
    //     entry's scroll position (bug 590573).
    // 4. As apropriate, either add a state object entry to the session history
    //    after the current entry with the following properties, or modify the
    //    current session history entry to set
    //      a. cloned data as the state object,
    //      b. if the third argument was present, the absolute URL found in
    //         step 2
    //    Also clear the new history entry's POST data (see bug 580069).
    // 5. If aReplace is false (i.e. we're doing a pushState instead of a
    //    replaceState), notify bfcache that we've navigated to a new page.
    // 6. If the third argument is present, set the document's current address
    //    to the absolute URL found in step 2.
    //
    // It's important that this function not run arbitrary scripts after step 1
    // and before completing step 5.  For example, if a script called
    // history.back() before we completed step 5, bfcache might destroy an
    // active content viewer.  Since EvictOutOfRangeContentViewers at the end of
    // step 5 might run script, we can't just put a script blocker around the
    // critical section.
    //
    // Note that we completely ignore the aTitle parameter.

    nsresult rv;

    nsCOMPtr<nsIDocument> document = do_GetInterface(GetAsSupports(this));
    NS_ENSURE_TRUE(document, NS_ERROR_FAILURE);

    // Step 1: Serialize aData using structured clone.
    nsCOMPtr<nsIStructuredCloneContainer> scContainer;

    // scContainer->Init might cause arbitrary JS to run, and this code might
    // navigate the page we're on, potentially to a different origin! (bug
    // 634834)  To protect against this, we abort if our principal changes due
    // to the InitFromVariant() call.
    {
        nsCOMPtr<nsIDocument> origDocument =
            do_GetInterface(GetAsSupports(this));
        if (!origDocument)
            return NS_ERROR_DOM_SECURITY_ERR;
        nsCOMPtr<nsIPrincipal> origPrincipal = origDocument->NodePrincipal();

        scContainer = new nsStructuredCloneContainer();
        JSContext *cx = aCx;
        if (!cx) {
            cx = nsContentUtils::GetContextFromDocument(document);
        }
        rv = scContainer->InitFromVariant(aData, cx);

        // If we're running in the document's context and the structured clone
        // failed, clear the context's pending exception.  See bug 637116.
        if (NS_FAILED(rv) && !aCx) {
            JS_ClearPendingException(aCx);
        }
        NS_ENSURE_SUCCESS(rv, rv);

        nsCOMPtr<nsIDocument> newDocument =
            do_GetInterface(GetAsSupports(this));
        if (!newDocument)
            return NS_ERROR_DOM_SECURITY_ERR;
        nsCOMPtr<nsIPrincipal> newPrincipal = newDocument->NodePrincipal();

        bool principalsEqual = false;
        origPrincipal->Equals(newPrincipal, &principalsEqual);
        NS_ENSURE_TRUE(principalsEqual, NS_ERROR_DOM_SECURITY_ERR);
    }

    // Check that the state object isn't too long.
    // Default max length: 640k bytes.
    PRInt32 maxStateObjSize =
        Preferences::GetInt("browser.history.maxStateObjectSize", 0xA0000);
    if (maxStateObjSize < 0) {
        maxStateObjSize = 0;
    }

    PRUint64 scSize;
    rv = scContainer->GetSerializedNBytes(&scSize);
    NS_ENSURE_SUCCESS(rv, rv);

    NS_ENSURE_TRUE(scSize <= (PRUint32)maxStateObjSize,
                   NS_ERROR_ILLEGAL_VALUE);

    // Step 2: Resolve aURL
    bool equalURIs = true;
    nsCOMPtr<nsIURI> oldURI = mCurrentURI;
    nsCOMPtr<nsIURI> newURI;
    if (aURL.Length() == 0) {
        newURI = mCurrentURI;
    }
    else {
        // 2a: Resolve aURL relative to mURI

        nsIURI* docBaseURI = document->GetDocBaseURI();
        if (!docBaseURI)
            return NS_ERROR_FAILURE;

        nsCAutoString spec;
        docBaseURI->GetSpec(spec);

        nsCAutoString charset;
        rv = docBaseURI->GetOriginCharset(charset);
        NS_ENSURE_SUCCESS(rv, NS_ERROR_FAILURE);

        rv = NS_NewURI(getter_AddRefs(newURI), aURL,
                       charset.get(), docBaseURI);

        // 2b: If 2a fails, raise a SECURITY_ERR
        if (NS_FAILED(rv)) {
            return NS_ERROR_DOM_SECURITY_ERR;
        }

        // 2c: Same-origin check.
        if (!nsContentUtils::URIIsLocalFile(newURI)) {
            // In addition to checking that the security manager says that
            // the new URI has the same origin as our current URI, we also
            // check that the two URIs have the same userpass. (The
            // security manager says that |http://foo.com| and
            // |http://me@foo.com| have the same origin.)  mCurrentURI
            // won't contain the password part of the userpass, so this
            // means that it's never valid to specify a password in a
            // pushState or replaceState URI.

            nsCOMPtr<nsIScriptSecurityManager> secMan =
                do_GetService(NS_SCRIPTSECURITYMANAGER_CONTRACTID);
            NS_ENSURE_TRUE(secMan, NS_ERROR_FAILURE);

            // It's very important that we check that newURI is of the same
            // origin as mCurrentURI, not docBaseURI, because a page can
            // set docBaseURI arbitrarily to any domain.
            nsCAutoString currentUserPass, newUserPass;
            NS_ENSURE_SUCCESS(mCurrentURI->GetUserPass(currentUserPass),
                              NS_ERROR_FAILURE);
            NS_ENSURE_SUCCESS(newURI->GetUserPass(newUserPass),
                              NS_ERROR_FAILURE);
            if (NS_FAILED(secMan->CheckSameOriginURI(mCurrentURI,
                                                     newURI, true)) ||
                !currentUserPass.Equals(newUserPass)) {

                return NS_ERROR_DOM_SECURITY_ERR;
            }
        }
        else {
            // It's a file:// URI
            nsCOMPtr<nsIScriptObjectPrincipal> docScriptObj =
                do_QueryInterface(document);

            if (!docScriptObj) {
                return NS_ERROR_DOM_SECURITY_ERR;
            }

            nsCOMPtr<nsIPrincipal> principal = docScriptObj->GetPrincipal();

            if (!principal ||
                NS_FAILED(principal->CheckMayLoad(newURI, true))) {

                return NS_ERROR_DOM_SECURITY_ERR;
            }
        }

        mCurrentURI->Equals(newURI, &equalURIs);

    } // end of same-origin check

    nsCOMPtr<nsISHistory> sessionHistory = mSessionHistory;
    if (!sessionHistory) {
        // Get the handle to SH from the root docshell
        GetRootSessionHistory(getter_AddRefs(sessionHistory));
    }
    NS_ENSURE_TRUE(sessionHistory, NS_ERROR_FAILURE);

    nsCOMPtr<nsISHistoryInternal> shInternal =
        do_QueryInterface(sessionHistory, &rv);
    NS_ENSURE_SUCCESS(rv, rv);

    // Step 3: Create a new entry in the session history. This will erase
    // all SHEntries after the new entry and make this entry the current
    // one.  This operation may modify mOSHE, which we need later, so we
    // keep a reference here.
    NS_ENSURE_TRUE(mOSHE, NS_ERROR_FAILURE);
    nsCOMPtr<nsISHEntry> oldOSHE = mOSHE;

    mLoadType = LOAD_PUSHSTATE;

    nsCOMPtr<nsISHEntry> newSHEntry;
    if (!aReplace) {
        // Save the current scroll position (bug 590573).
        nscoord cx = 0, cy = 0;
        GetCurScrollPos(ScrollOrientation_X, &cx);
        GetCurScrollPos(ScrollOrientation_Y, &cy);
        mOSHE->SetScrollPosition(cx, cy);

        // Since we're not changing which page we have loaded, pass
        // true for aCloneChildren.
        rv = AddToSessionHistory(newURI, nsnull, nsnull, true,
                                 getter_AddRefs(newSHEntry));
        NS_ENSURE_SUCCESS(rv, rv);

        NS_ENSURE_TRUE(newSHEntry, NS_ERROR_FAILURE);

        // Link the new SHEntry to the old SHEntry's BFCache entry, since the
        // two entries correspond to the same document.
        NS_ENSURE_SUCCESS(newSHEntry->AdoptBFCacheEntry(oldOSHE),
                          NS_ERROR_FAILURE);

        // Set the new SHEntry's title (bug 655273).
        nsString title;
        mOSHE->GetTitle(getter_Copies(title));
        newSHEntry->SetTitle(title);

        // AddToSessionHistory may not modify mOSHE.  In case it doesn't,
        // we'll just set mOSHE here.
        mOSHE = newSHEntry;

    } else {
        newSHEntry = mOSHE;
        newSHEntry->SetURI(newURI);
    }

    // Step 4: Modify new/original session history entry and clear its POST
    // data, if there is any.
    newSHEntry->SetStateData(scContainer);
    newSHEntry->SetPostData(nsnull);

    // If this push/replaceState changed the document's current URI and the new
    // URI differs from the old URI in more than the hash, or if the old
    // SHEntry's URI was modified in this way by a push/replaceState call
    // set URIWasModified to true for the current SHEntry (bug 669671).
    bool sameExceptHashes = true, oldURIWasModified = false;
    newURI->EqualsExceptRef(mCurrentURI, &sameExceptHashes);
    oldOSHE->GetURIWasModified(&oldURIWasModified);
    newSHEntry->SetURIWasModified(!sameExceptHashes || oldURIWasModified);

    // Step 5: If aReplace is false, indicating that we're doing a pushState
    // rather than a replaceState, notify bfcache that we've added a page to
    // the history so it can evict content viewers if appropriate.
    if (!aReplace) {
        nsCOMPtr<nsISHistory> rootSH;
        GetRootSessionHistory(getter_AddRefs(rootSH));
        NS_ENSURE_TRUE(rootSH, NS_ERROR_UNEXPECTED);

        nsCOMPtr<nsISHistoryInternal> internalSH =
            do_QueryInterface(rootSH);
        NS_ENSURE_TRUE(internalSH, NS_ERROR_UNEXPECTED);

        PRInt32 curIndex = -1;
        rv = rootSH->GetIndex(&curIndex);
        if (NS_SUCCEEDED(rv) && curIndex > -1) {
            internalSH->EvictOutOfRangeContentViewers(curIndex);
        }
    }

    // Step 6: If the document's URI changed, update document's URI and update
    // global history.
    //
    // We need to call FireOnLocationChange so that the browser's address bar
    // gets updated and the back button is enabled, but we only need to
    // explicitly call FireOnLocationChange if we're not calling SetCurrentURI,
    // since SetCurrentURI will call FireOnLocationChange for us.
    //
    // Both SetCurrentURI(...) and FireDummyOnLocationChange() pass
    // nsnull for aRequest param to FireOnLocationChange(...). Such an update
    // notification is allowed only when we know docshell is not loading a new
    // document and it requires LOCATION_CHANGE_SAME_DOCUMENT flag. Otherwise,
    // FireOnLocationChange(...) breaks security UI.
    if (!equalURIs) {
        SetCurrentURI(newURI, nsnull, true, LOCATION_CHANGE_SAME_DOCUMENT);
        document->SetDocumentURI(newURI);

        AddURIVisit(newURI, oldURI, oldURI, 0);

        // AddURIVisit doesn't set the title for the new URI in global history,
        // so do that here.
        if (mUseGlobalHistory) {
            nsCOMPtr<IHistory> history = services::GetHistoryService();
            if (history) {
                history->SetURITitle(newURI, mTitle);
            }
            else if (mGlobalHistory) {
                mGlobalHistory->SetPageTitle(newURI, mTitle);
            }
        }

        // Inform the favicon service that our old favicon applies to this new
        // URI.
        CopyFavicon(oldURI, newURI);
    }
    else {
        FireDummyOnLocationChange();
    }
    document->SetStateObject(scContainer);

    return NS_OK;
}
