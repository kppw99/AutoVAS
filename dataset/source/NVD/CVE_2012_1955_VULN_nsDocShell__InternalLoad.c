NS_IMETHODIMP
CVE_2012_1955_VULN_nsDocShell::InternalLoad(nsIURI * aURI,
                         nsIURI * aReferrer,
                         nsISupports * aOwner,
                         PRUint32 aFlags,
                         const PRUnichar *aWindowTarget,
                         const char* aTypeHint,
                         nsIInputStream * aPostData,
                         nsIInputStream * aHeadersData,
                         PRUint32 aLoadType,
                         nsISHEntry * aSHEntry,
                         bool aFirstParty,
                         nsIDocShell** aDocShell,
                         nsIRequest** aRequest)
{
    nsresult rv = NS_OK;

#ifdef PR_LOGGING
    if (gDocShellLeakLog && PR_LOG_TEST(gDocShellLeakLog, PR_LOG_DEBUG)) {
        nsCAutoString spec;
        if (aURI)
            aURI->GetSpec(spec);
        PR_LogPrint("DOCSHELL %p InternalLoad %s\n", this, spec.get());
    }
#endif
    
    // Initialize aDocShell/aRequest
    if (aDocShell) {
        *aDocShell = nsnull;
    }
    if (aRequest) {
        *aRequest = nsnull;
    }

    if (!aURI) {
        return NS_ERROR_NULL_POINTER;
    }

    NS_ENSURE_TRUE(IsValidLoadType(aLoadType), NS_ERROR_INVALID_ARG);

    NS_ENSURE_TRUE(!mIsBeingDestroyed, NS_ERROR_NOT_AVAILABLE);

    // wyciwyg urls can only be loaded through history. Any normal load of
    // wyciwyg through docshell is  illegal. Disallow such loads.
    if (aLoadType & LOAD_CMD_NORMAL) {
        bool isWyciwyg = false;
        rv = aURI->SchemeIs("wyciwyg", &isWyciwyg);   
        if ((isWyciwyg && NS_SUCCEEDED(rv)) || NS_FAILED(rv)) 
            return NS_ERROR_FAILURE;
    }

    bool bIsJavascript = false;
    if (NS_FAILED(aURI->SchemeIs("javascript", &bIsJavascript))) {
        bIsJavascript = false;
    }

    //
    // First, notify any nsIContentPolicy listeners about the document load.
    // Only abort the load if a content policy listener explicitly vetos it!
    //
    nsCOMPtr<nsIDOMElement> requestingElement;
    // Use nsPIDOMWindow since we _want_ to cross the chrome boundary if needed
    nsCOMPtr<nsPIDOMWindow> privateWin(do_QueryInterface(mScriptGlobal));
    if (privateWin)
        requestingElement = privateWin->GetFrameElementInternal();

    PRInt16 shouldLoad = nsIContentPolicy::ACCEPT;
    PRUint32 contentType;
    if (IsFrame()) {
        NS_ASSERTION(requestingElement, "A frame but no DOM element!?");
        contentType = nsIContentPolicy::TYPE_SUBDOCUMENT;
    } else {
        contentType = nsIContentPolicy::TYPE_DOCUMENT;
    }

    nsISupports* context = requestingElement;
    if (!context) {
        context =  mScriptGlobal;
    }

    // XXXbz would be nice to know the loading principal here... but we don't
    nsCOMPtr<nsIPrincipal> loadingPrincipal;
    if (aReferrer) {
        nsCOMPtr<nsIScriptSecurityManager> secMan =
            do_GetService(NS_SCRIPTSECURITYMANAGER_CONTRACTID, &rv);
        NS_ENSURE_SUCCESS(rv, rv);

        rv = secMan->GetCodebasePrincipal(aReferrer,
                                          getter_AddRefs(loadingPrincipal));
    }
    
    rv = NS_CheckContentLoadPolicy(contentType,
                                   aURI,
                                   loadingPrincipal,
                                   context,
                                   EmptyCString(), //mime guess
                                   nsnull,         //extra
                                   &shouldLoad);

    if (NS_FAILED(rv) || NS_CP_REJECTED(shouldLoad)) {
        if (NS_SUCCEEDED(rv) && shouldLoad == nsIContentPolicy::REJECT_TYPE) {
            return NS_ERROR_CONTENT_BLOCKED_SHOW_ALT;
        }

        return NS_ERROR_CONTENT_BLOCKED;
    }

    nsCOMPtr<nsISupports> owner(aOwner);
    //
    // Get an owner from the current document if necessary.  Note that we only
    // do this for URIs that inherit a security context and local file URIs;
    // in particular we do NOT do this for about:blank.  This way, random
    // about:blank loads that have no owner (which basically means they were
    // done by someone from chrome manually messing with our nsIWebNavigation
    // or by C++ setting document.location) don't get a funky principal.  If
    // callers want something interesting to happen with the about:blank
    // principal in this case, they should pass an owner in.
    //
    {
        bool inherits;
        // One more twist: Don't inherit the owner for external loads.
        if (aLoadType != LOAD_NORMAL_EXTERNAL && !owner &&
            (aFlags & INTERNAL_LOAD_FLAGS_INHERIT_OWNER) &&
            NS_SUCCEEDED(nsContentUtils::URIInheritsSecurityContext(aURI,
                                                                    &inherits)) &&
            inherits) {

            owner = GetInheritedPrincipal(true);
        }
    }

    // Don't allow loads that would inherit our security context
    // if this document came from an unsafe channel.
    {
        bool willInherit;
        // This condition needs to match the one in
        // nsContentUtils::SetUpChannelOwner.
        // Except we reverse the rv check to be safe in case
        // nsContentUtils::URIInheritsSecurityContext fails here and
        // succeeds there.
        rv = nsContentUtils::URIInheritsSecurityContext(aURI, &willInherit);
        if (NS_FAILED(rv) || willInherit || NS_IsAboutBlank(aURI)) {
            nsCOMPtr<nsIDocShellTreeItem> treeItem = this;
            do {
                nsCOMPtr<nsIDocShell> itemDocShell =
                    do_QueryInterface(treeItem);
                bool isUnsafe;
                if (itemDocShell &&
                    NS_SUCCEEDED(itemDocShell->GetChannelIsUnsafe(&isUnsafe)) &&
                    isUnsafe) {
                    return NS_ERROR_DOM_SECURITY_ERR;
                }

                nsCOMPtr<nsIDocShellTreeItem> parent;
                treeItem->GetSameTypeParent(getter_AddRefs(parent));
                parent.swap(treeItem);
            } while (treeItem);
        }
    }
    
    //
    // Resolve the window target before going any further...
    // If the load has been targeted to another DocShell, then transfer the
    // load to it...
    //
    if (aWindowTarget && *aWindowTarget) {
        // We've already done our owner-inheriting.  Mask out that bit, so we
        // don't try inheriting an owner from the target window if we came up
        // with a null owner above.
        aFlags = aFlags & ~INTERNAL_LOAD_FLAGS_INHERIT_OWNER;
        
        // Locate the target DocShell.
        // This may involve creating a new toplevel window - if necessary.
        //
        nsCOMPtr<nsIDocShellTreeItem> targetItem;
        FindItemWithName(aWindowTarget, nsnull, this,
                         getter_AddRefs(targetItem));

        nsCOMPtr<nsIDocShell> targetDocShell = do_QueryInterface(targetItem);
        
        bool isNewWindow = false;
        if (!targetDocShell) {
            nsCOMPtr<nsIDOMWindow> win =
                do_GetInterface(GetAsSupports(this));
            NS_ENSURE_TRUE(win, NS_ERROR_NOT_AVAILABLE);

            nsDependentString name(aWindowTarget);
            nsCOMPtr<nsIDOMWindow> newWin;
            rv = win->Open(EmptyString(), // URL to load
                           name,          // window name
                           EmptyString(), // Features
                           getter_AddRefs(newWin));

            // In some cases the Open call doesn't actually result in a new
            // window being opened.  We can detect these cases by examining the
            // document in |newWin|, if any.
            nsCOMPtr<nsPIDOMWindow> piNewWin = do_QueryInterface(newWin);
            if (piNewWin) {
                nsCOMPtr<nsIDocument> newDoc =
                    do_QueryInterface(piNewWin->GetExtantDocument());
                if (!newDoc || newDoc->IsInitialDocument()) {
                    isNewWindow = true;
                    aFlags |= INTERNAL_LOAD_FLAGS_FIRST_LOAD;
                }
            }

            nsCOMPtr<nsIWebNavigation> webNav = do_GetInterface(newWin);
            targetDocShell = do_QueryInterface(webNav);
        }

        //
        // Transfer the load to the target DocShell...  Pass nsnull as the
        // window target name from to prevent recursive retargeting!
        //
        if (NS_SUCCEEDED(rv) && targetDocShell) {
            rv = targetDocShell->InternalLoad(aURI,
                                              aReferrer,
                                              owner,
                                              aFlags,
                                              nsnull,         // No window target
                                              aTypeHint,
                                              aPostData,
                                              aHeadersData,
                                              aLoadType,
                                              aSHEntry,
                                              aFirstParty,
                                              aDocShell,
                                              aRequest);
            if (rv == NS_ERROR_NO_CONTENT) {
                // XXXbz except we never reach this code!
                if (isNewWindow) {
                    //
                    // At this point, a new window has been created, but the
                    // URI did not have any data associated with it...
                    //
                    // So, the best we can do, is to tear down the new window
                    // that was just created!
                    //
                    nsCOMPtr<nsIDOMWindow> domWin =
                        do_GetInterface(targetDocShell);
                    if (domWin) {
                        domWin->Close();
                    }
                }
                //
                // NS_ERROR_NO_CONTENT should not be returned to the
                // caller... This is an internal error code indicating that
                // the URI had no data associated with it - probably a 
                // helper-app style protocol (ie. mailto://)
                //
                rv = NS_OK;
            }
            else if (isNewWindow) {
                // XXX: Once new windows are created hidden, the new
                //      window will need to be made visible...  For now,
                //      do nothing.
            }
        }

        // Else we ran out of memory, or were a popup and got blocked,
        // or something.
        
        return rv;
    }

    //
    // Load is being targetted at this docshell so return an error if the
    // docshell is in the process of being destroyed.
    //
    if (mIsBeingDestroyed) {
        return NS_ERROR_FAILURE;
    }

    rv = CheckLoadingPermissions();
    if (NS_FAILED(rv)) {
        return rv;
    }

    // If this docshell is owned by a frameloader, make sure to cancel
    // possible frameloader initialization before loading a new page.
    nsCOMPtr<nsIDocShellTreeItem> parent;
    GetParent(getter_AddRefs(parent));
    if (parent) {
      nsCOMPtr<nsIDocument> doc = do_GetInterface(parent);
      if (doc) {
        doc->TryCancelFrameLoaderInitialization(this);
      }
    }

    if (mFiredUnloadEvent) {
        if (IsOKToLoadURI(aURI)) {
            NS_PRECONDITION(!aWindowTarget || !*aWindowTarget,
                            "Shouldn't have a window target here!");

            // If this is a replace load, make whatever load triggered
            // the unload event also a replace load, so we don't
            // create extra history entries.
            if (LOAD_TYPE_HAS_FLAGS(aLoadType, LOAD_FLAGS_REPLACE_HISTORY)) {
                mLoadType = LOAD_NORMAL_REPLACE;
            }
            
            // Do this asynchronously
            nsCOMPtr<nsIRunnable> ev =
                new InternalLoadEvent(this, aURI, aReferrer, aOwner, aFlags,
                                      aTypeHint, aPostData, aHeadersData,
                                      aLoadType, aSHEntry, aFirstParty);
            return NS_DispatchToCurrentThread(ev);
        }

        // Just ignore this load attempt
        return NS_OK;
    }

    // Before going any further vet loads initiated by external programs.
    if (aLoadType == LOAD_NORMAL_EXTERNAL) {
        // Disallow external chrome: loads targetted at content windows
        bool isChrome = false;
        if (NS_SUCCEEDED(aURI->SchemeIs("chrome", &isChrome)) && isChrome) {
            NS_WARNING("blocked external chrome: url -- use '-chrome' option");
            return NS_ERROR_FAILURE;
        }

        // clear the decks to prevent context bleed-through (bug 298255)
        rv = CreateAboutBlankContentViewer(nsnull, nsnull);
        if (NS_FAILED(rv))
            return NS_ERROR_FAILURE;

        // reset loadType so we don't have to add lots of tests for
        // LOAD_NORMAL_EXTERNAL after this point
        aLoadType = LOAD_NORMAL;
    }

    mAllowKeywordFixup =
      (aFlags & INTERNAL_LOAD_FLAGS_ALLOW_THIRD_PARTY_FIXUP) != 0;
    mURIResultedInDocument = false;  // reset the clock...

    if (aLoadType == LOAD_NORMAL ||
        aLoadType == LOAD_STOP_CONTENT ||
        LOAD_TYPE_HAS_FLAGS(aLoadType, LOAD_FLAGS_REPLACE_HISTORY) ||
        aLoadType == LOAD_HISTORY ||
        aLoadType == LOAD_LINK) {

        // Split mCurrentURI and aURI on the '#' character.  Make sure we read
        // the return values of SplitURIAtHash; if it fails, we don't want to
        // allow a short-circuited navigation.
        nsCAutoString curBeforeHash, curHash, newBeforeHash, newHash;
        nsresult splitRv1, splitRv2;
        splitRv1 = mCurrentURI ?
            nsContentUtils::SplitURIAtHash(mCurrentURI,
                                           curBeforeHash, curHash) :
            NS_ERROR_FAILURE;
        splitRv2 = nsContentUtils::SplitURIAtHash(aURI, newBeforeHash, newHash);

        bool sameExceptHashes = NS_SUCCEEDED(splitRv1) &&
                                  NS_SUCCEEDED(splitRv2) &&
                                  curBeforeHash.Equals(newBeforeHash);

        bool historyNavBetweenSameDoc = false;
        if (mOSHE && aSHEntry) {
            // We're doing a history load.

            mOSHE->SharesDocumentWith(aSHEntry, &historyNavBetweenSameDoc);

#ifdef DEBUG
            if (historyNavBetweenSameDoc) {
                nsCOMPtr<nsIInputStream> currentPostData;
                mOSHE->GetPostData(getter_AddRefs(currentPostData));
                NS_ASSERTION(currentPostData == aPostData,
                             "Different POST data for entries for the same page?");
            }
#endif
        }

        // A short-circuited load happens when we navigate between two SHEntries
        // for the same document.  We do a short-circuited load under two
        // circumstances.  Either
        //
        //  a) we're navigating between two different SHEntries which share a
        //     document, or
        //
        //  b) we're navigating to a new shentry whose URI differs from the
        //     current URI only in its hash, the new hash is non-empty, and
        //     we're not doing a POST.
        //
        // The restriction tha the SHEntries in (a) must be different ensures
        // that history.go(0) and the like trigger full refreshes, rather than
        // short-circuited loads.
        bool doShortCircuitedLoad =
          (historyNavBetweenSameDoc && mOSHE != aSHEntry) ||
          (!aSHEntry && aPostData == nsnull &&
           sameExceptHashes && !newHash.IsEmpty());

        if (doShortCircuitedLoad) {
            // Save the current URI; we need it if we fire a hashchange later.
            nsCOMPtr<nsIURI> oldURI = mCurrentURI;

            // Save the position of the scrollers.
            nscoord cx = 0, cy = 0;
            GetCurScrollPos(ScrollOrientation_X, &cx);
            GetCurScrollPos(ScrollOrientation_Y, &cy);

            // ScrollToAnchor doesn't necessarily cause us to scroll the window;
            // the function decides whether a scroll is appropriate based on the
            // arguments it receives.  But even if we don't end up scrolling,
            // ScrollToAnchor performs other important tasks, such as informing
            // the presShell that we have a new hash.  See bug 680257.
            rv = ScrollToAnchor(curHash, newHash, aLoadType);
            NS_ENSURE_SUCCESS(rv, rv);

            // Reset mLoadType to its original value once we exit this block,
            // because this short-circuited load might have started after a
            // normal, network load, and we don't want to clobber its load type.
            // See bug 737307.
            AutoRestore<PRUint32> loadTypeResetter(mLoadType);

            mLoadType = aLoadType;
            mURIResultedInDocument = true;

            /* we need to assign mLSHE to aSHEntry right here, so that on History loads,
             * SetCurrentURI() called from OnNewURI() will send proper
             * onLocationChange() notifications to the browser to update
             * back/forward buttons.
             */
            SetHistoryEntry(&mLSHE, aSHEntry);

            /* This is a anchor traversal with in the same page.
             * call OnNewURI() so that, this traversal will be 
             * recorded in session and global history.
             */
            nsCOMPtr<nsISupports> owner;
            if (mOSHE) {
                mOSHE->GetOwner(getter_AddRefs(owner));
            }
            // Pass true for aCloneSHChildren, since we're not
            // changing documents here, so all of our subframes are
            // still relevant to the new session history entry.
            //
            // It also makes OnNewURI(...) set LOCATION_CHANGE_SAME_DOCUMENT
            // flag on firing onLocationChange(...).
            // Anyway, aCloneSHChildren param is simply reflecting
            // doShortCircuitedLoad in this scope.
            OnNewURI(aURI, nsnull, owner, mLoadType, true, true, true);

            nsCOMPtr<nsIInputStream> postData;
            nsCOMPtr<nsISupports> cacheKey;

            if (mOSHE) {
                /* save current position of scroller(s) (bug 59774) */
                mOSHE->SetScrollPosition(cx, cy);
                // Get the postdata and page ident from the current page, if
                // the new load is being done via normal means.  Note that
                // "normal means" can be checked for just by checking for
                // LOAD_CMD_NORMAL, given the loadType and allowScroll check
                // above -- it filters out some LOAD_CMD_NORMAL cases that we
                // wouldn't want here.
                if (aLoadType & LOAD_CMD_NORMAL) {
                    mOSHE->GetPostData(getter_AddRefs(postData));
                    mOSHE->GetCacheKey(getter_AddRefs(cacheKey));

                    // Link our new SHEntry to the old SHEntry's back/forward
                    // cache data, since the two SHEntries correspond to the
                    // same document.
                    if (mLSHE)
                        mLSHE->AdoptBFCacheEntry(mOSHE);
                }
            }

            /* Assign mOSHE to mLSHE. This will either be a new entry created
             * by OnNewURI() for normal loads or aSHEntry for history loads.
             */
            if (mLSHE) {
                SetHistoryEntry(&mOSHE, mLSHE);
                // Save the postData obtained from the previous page
                // in to the session history entry created for the 
                // anchor page, so that any history load of the anchor
                // page will restore the appropriate postData.
                if (postData)
                    mOSHE->SetPostData(postData);

                // Make sure we won't just repost without hitting the
                // cache first
                if (cacheKey)
                    mOSHE->SetCacheKey(cacheKey);
            }

            /* restore previous position of scroller(s), if we're moving
             * back in history (bug 59774)
             */
            if (mOSHE && (aLoadType == LOAD_HISTORY || aLoadType == LOAD_RELOAD_NORMAL))
            {
                nscoord bx, by;
                mOSHE->GetScrollPosition(&bx, &by);
                SetCurScrollPosEx(bx, by);
            }

            /* Clear out mLSHE so that further anchor visits get
             * recorded in SH and SH won't misbehave. 
             */
            SetHistoryEntry(&mLSHE, nsnull);
            /* Set the title for the SH entry for this target url. so that
             * SH menus in go/back/forward buttons won't be empty for this.
             */
            if (mSessionHistory) {
                PRInt32 index = -1;
                mSessionHistory->GetIndex(&index);
                nsCOMPtr<nsIHistoryEntry> hEntry;
                mSessionHistory->GetEntryAtIndex(index, false,
                                                 getter_AddRefs(hEntry));
                NS_ENSURE_TRUE(hEntry, NS_ERROR_FAILURE);
                nsCOMPtr<nsISHEntry> shEntry(do_QueryInterface(hEntry));
                if (shEntry)
                    shEntry->SetTitle(mTitle);
            }

            /* Set the title for the Global History entry for this anchor url.
             */
            if (mUseGlobalHistory) {
                nsCOMPtr<IHistory> history = services::GetHistoryService();
                if (history) {
                    history->SetURITitle(aURI, mTitle);
                }
                else if (mGlobalHistory) {
                    mGlobalHistory->SetPageTitle(aURI, mTitle);
                }
            }

            // Set the doc's URI according to the new history entry's URI.
            nsCOMPtr<nsIDocument> doc =
              do_GetInterface(GetAsSupports(this));
            NS_ENSURE_TRUE(doc, NS_ERROR_FAILURE);
            doc->SetDocumentURI(aURI);

            SetDocCurrentStateObj(mOSHE);

            // Dispatch the popstate and hashchange events, as appropriate.
            nsCOMPtr<nsPIDOMWindow> window = do_QueryInterface(mScriptGlobal);
            if (window) {
                // Fire a hashchange event URIs differ, and only in their hashes.
                bool doHashchange = sameExceptHashes && !curHash.Equals(newHash);

                if (historyNavBetweenSameDoc || doHashchange) {
                  window->DispatchSyncPopState();
                }

                if (doHashchange) {
                  // Make sure to use oldURI here, not mCurrentURI, because by
                  // now, mCurrentURI has changed!
                  window->DispatchAsyncHashchange(oldURI, aURI);
                }
            }

            // Inform the favicon service that the favicon for oldURI also
            // applies to aURI.
            CopyFavicon(oldURI, aURI);

            return NS_OK;
        }
    }
    
    // mContentViewer->PermitUnload can destroy |this| docShell, which
    // causes the next call of CanSavePresentation to crash. 
    // Hold onto |this| until we return, to prevent a crash from happening. 
    // (bug#331040)
    nsCOMPtr<nsIDocShell> kungFuDeathGrip(this);

    rv = MaybeInitTiming();
    if (mTiming) {
      mTiming->NotifyBeforeUnload();
    }
    // Check if the page doesn't want to be unloaded. The javascript:
    // protocol handler deals with this for javascript: URLs.
    if (!bIsJavascript && mContentViewer) {
        bool okToUnload;
        rv = mContentViewer->PermitUnload(false, &okToUnload);

        if (NS_SUCCEEDED(rv) && !okToUnload) {
            // The user chose not to unload the page, interrupt the
            // load.
            return NS_OK;
        }
    }

    if (mTiming) {
      mTiming->NotifyUnloadAccepted(mCurrentURI);
    }

    // Check for saving the presentation here, before calling Stop().
    // This is necessary so that we can catch any pending requests.
    // Since the new request has not been created yet, we pass null for the
    // new request parameter.
    // Also pass nsnull for the document, since it doesn't affect the return
    // value for our purposes here.
    bool savePresentation = CanSavePresentation(aLoadType, nsnull, nsnull);

    // Don't stop current network activity for javascript: URL's since
    // they might not result in any data, and thus nothing should be
    // stopped in those cases. In the case where they do result in
    // data, the javascript: URL channel takes care of stopping
    // current network activity.
    if (!bIsJavascript) {
        // Stop any current network activity.
        // Also stop content if this is a zombie doc. otherwise 
        // the onload will be delayed by other loads initiated in the 
        // background by the first document that
        // didn't fully load before the next load was initiated.
        // If not a zombie, don't stop content until data 
        // starts arriving from the new URI...

        nsCOMPtr<nsIContentViewer> zombieViewer;
        if (mContentViewer) {
            mContentViewer->GetPreviousViewer(getter_AddRefs(zombieViewer));
        }

        if (zombieViewer ||
            LOAD_TYPE_HAS_FLAGS(aLoadType, LOAD_FLAGS_STOP_CONTENT)) {
            rv = Stop(nsIWebNavigation::STOP_ALL);
        } else {
            rv = Stop(nsIWebNavigation::STOP_NETWORK);
        }

        if (NS_FAILED(rv)) 
            return rv;
    }

    mLoadType = aLoadType;

    // mLSHE should be assigned to aSHEntry, only after Stop() has
    // been called. But when loading an error page, do not clear the
    // mLSHE for the real page.
    if (mLoadType != LOAD_ERROR_PAGE)
        SetHistoryEntry(&mLSHE, aSHEntry);

    mSavingOldViewer = savePresentation;

    // If we have a saved content viewer in history, restore and show it now.
    if (aSHEntry && (mLoadType & LOAD_CMD_HISTORY)) {
        // Make sure our history ID points to the same ID as
        // SHEntry's docshell ID.
        aSHEntry->GetDocshellID(&mHistoryID);

        // It's possible that the previous viewer of mContentViewer is the
        // viewer that will end up in aSHEntry when it gets closed.  If that's
        // the case, we need to go ahead and force it into its shentry so we
        // can restore it.
        if (mContentViewer) {
            nsCOMPtr<nsIContentViewer> prevViewer;
            mContentViewer->GetPreviousViewer(getter_AddRefs(prevViewer));
            if (prevViewer) {
#ifdef DEBUG
                nsCOMPtr<nsIContentViewer> prevPrevViewer;
                prevViewer->GetPreviousViewer(getter_AddRefs(prevPrevViewer));
                NS_ASSERTION(!prevPrevViewer, "Should never have viewer chain here");
#endif
                nsCOMPtr<nsISHEntry> viewerEntry;
                prevViewer->GetHistoryEntry(getter_AddRefs(viewerEntry));
                if (viewerEntry == aSHEntry) {
                    // Make sure this viewer ends up in the right place
                    mContentViewer->SetPreviousViewer(nsnull);
                    prevViewer->Destroy();
                }
            }
        }
        nsCOMPtr<nsISHEntry> oldEntry = mOSHE;
        bool restoring;
        rv = RestorePresentation(aSHEntry, &restoring);
        if (restoring)
            return rv;

        // We failed to restore the presentation, so clean up.
        // Both the old and new history entries could potentially be in
        // an inconsistent state.
        if (NS_FAILED(rv)) {
            if (oldEntry)
                oldEntry->SyncPresentationState();

            aSHEntry->SyncPresentationState();
        }
    }

    nsCOMPtr<nsIRequest> req;
    rv = DoURILoad(aURI, aReferrer,
                   !(aFlags & INTERNAL_LOAD_FLAGS_DONT_SEND_REFERRER),
                   owner, aTypeHint, aPostData, aHeadersData, aFirstParty,
                   aDocShell, getter_AddRefs(req),
                   (aFlags & INTERNAL_LOAD_FLAGS_FIRST_LOAD) != 0,
                   (aFlags & INTERNAL_LOAD_FLAGS_BYPASS_CLASSIFIER) != 0,
                   (aFlags & INTERNAL_LOAD_FLAGS_FORCE_ALLOW_COOKIES) != 0);
    if (req && aRequest)
        NS_ADDREF(*aRequest = req);

    if (NS_FAILED(rv)) {
        nsCOMPtr<nsIChannel> chan(do_QueryInterface(req));
        DisplayLoadError(rv, aURI, nsnull, chan);
    }

    return rv;
}
