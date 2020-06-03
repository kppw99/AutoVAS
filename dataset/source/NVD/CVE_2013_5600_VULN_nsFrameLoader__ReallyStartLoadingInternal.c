nsresult
CVE_2013_5600_VULN_nsFrameLoader::ReallyStartLoadingInternal()
{
  NS_ENSURE_STATE(mURIToLoad && mOwnerContent && mOwnerContent->IsInDoc());

  nsresult rv = MaybeCreateDocShell();
  if (NS_FAILED(rv)) {
    return rv;
  }

  if (mRemoteFrame) {
    if (!mRemoteBrowser) {
      TryRemoteBrowser();

      if (!mRemoteBrowser) {
        NS_WARNING("Couldn't create child process for iframe.");
        return NS_ERROR_FAILURE;
      }
    }

    if (mRemoteBrowserShown || ShowRemoteFrame(nsIntSize(0, 0))) {
      // FIXME get error codes from child
      mRemoteBrowser->LoadURL(mURIToLoad);
    } else {
      NS_WARNING("[nsFrameLoader] ReallyStartLoadingInternal tried but couldn't show remote browser.\n");
    }

    return NS_OK;
  }

  NS_ASSERTION(mDocShell,
               "MaybeCreateDocShell succeeded with a null mDocShell");

  // Just to be safe, recheck uri.
  rv = CheckURILoad(mURIToLoad);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIDocShellLoadInfo> loadInfo;
  mDocShell->CreateLoadInfo(getter_AddRefs(loadInfo));
  NS_ENSURE_TRUE(loadInfo, NS_ERROR_FAILURE);

  // Is this an <iframe> with a sandbox attribute or a parent which is
  // sandboxed ?
  nsHTMLIFrameElement* iframe =
    nsHTMLIFrameElement::FromContent(mOwnerContent);

  uint32_t sandboxFlags = 0;

  if (iframe) {
    sandboxFlags = iframe->GetSandboxFlags();

    uint32_t parentSandboxFlags = iframe->OwnerDoc()->GetSandboxFlags();

    if (sandboxFlags || parentSandboxFlags) {
      // The child can only add restrictions, not remove them.
      sandboxFlags |= parentSandboxFlags;

      mDocShell->SetSandboxFlags(sandboxFlags);
    }
  }

  // If this is an <iframe> and it's sandboxed with respect to origin
  // we will set it up with a null principal later in nsDocShell::DoURILoad.
  // We do it there to correctly sandbox content that was loaded into
  // the iframe via other methods than the src attribute.
  // We'll use our principal, not that of the document loaded inside us.  This
  // is very important; needed to prevent XSS attacks on documents loaded in
  // subframes!
  loadInfo->SetOwner(mOwnerContent->NodePrincipal());

  nsCOMPtr<nsIURI> referrer;
  rv = mOwnerContent->NodePrincipal()->GetURI(getter_AddRefs(referrer));
  NS_ENSURE_SUCCESS(rv, rv);

  loadInfo->SetReferrer(referrer);

  // Kick off the load...
  bool tmpState = mNeedsAsyncDestroy;
  mNeedsAsyncDestroy = true;
  rv = mDocShell->LoadURI(mURIToLoad, loadInfo,
                          nsIWebNavigation::LOAD_FLAGS_NONE, false);
  mNeedsAsyncDestroy = tmpState;
  mURIToLoad = nullptr;
  NS_ENSURE_SUCCESS(rv, rv);

  return NS_OK;
}
