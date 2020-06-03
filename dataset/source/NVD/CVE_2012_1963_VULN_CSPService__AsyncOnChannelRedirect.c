NS_IMETHODIMP
CVE_2012_1963_VULN_CSPService::AsyncOnChannelRedirect(nsIChannel *oldChannel,
                                   nsIChannel *newChannel,
                                   PRUint32 flags,
                                   nsIAsyncVerifyRedirectCallback *callback)
{
  nsAsyncRedirectAutoCallback autoCallback(callback);

  // get the Content Security Policy and load type from the property bag
  nsCOMPtr<nsISupports> policyContainer;
  nsCOMPtr<nsIPropertyBag2> props(do_QueryInterface(oldChannel));
  if (!props)
    return NS_OK;

  props->GetPropertyAsInterface(NS_CHANNEL_PROP_CHANNEL_POLICY,
                                NS_GET_IID(nsISupports),
                                getter_AddRefs(policyContainer));

  // see if we have a valid nsIChannelPolicy containing CSP and load type
  nsCOMPtr<nsIChannelPolicy> channelPolicy(do_QueryInterface(policyContainer));
  if (!channelPolicy)
    return NS_OK;

  nsCOMPtr<nsIContentSecurityPolicy> csp;
  channelPolicy->GetContentSecurityPolicy(getter_AddRefs(csp));
  PRUint32 loadType;
  channelPolicy->GetLoadType(&loadType);

  // if no CSP in the channelPolicy, nothing for us to add to the channel
  if (!csp)
    return NS_OK;

  /* Since redirecting channels don't call into nsIContentPolicy, we call our
   * Content Policy implementation directly when redirects occur. When channels
   * are created using NS_NewChannel(), callers can optionally pass in a
   * nsIChannelPolicy containing a CSP object and load type, which is placed in
   * the new channel's property bag. This container is propagated forward when
   * channels redirect.
   */

  // Does the CSP permit this host for this type of load?
  // If not, cancel the load now.
  nsCOMPtr<nsIURI> newUri;
  newChannel->GetURI(getter_AddRefs(newUri));
  PRInt16 aDecision = nsIContentPolicy::ACCEPT;
  csp->ShouldLoad(loadType,        // load type per nsIContentPolicy (PRUint32)
                  newUri,          // nsIURI
                  nsnull,          // nsIURI
                  nsnull,          // nsISupports
                  EmptyCString(),  // ACString - MIME guess
                  nsnull,          // nsISupports - extra
                  &aDecision);

#ifdef PR_LOGGING
  if (newUri) {
    nsCAutoString newUriSpec("None");
    newUri->GetSpec(newUriSpec);
    PR_LOG(gCspPRLog, PR_LOG_DEBUG,
           ("CVE_2012_1963_VULN_CSPService::AsyncOnChannelRedirect called for %s",
            newUriSpec.get()));
  }
  if (aDecision == 1)
    PR_LOG(gCspPRLog, PR_LOG_DEBUG,
           ("CVE_2012_1963_VULN_CSPService::AsyncOnChannelRedirect ALLOWING request."));
  else
    PR_LOG(gCspPRLog, PR_LOG_DEBUG,
           ("CVE_2012_1963_VULN_CSPService::AsyncOnChannelRedirect CANCELLING request."));
#endif

  // if ShouldLoad doesn't accept the load, cancel the request
  if (aDecision != 1) {
    autoCallback.DontCallback();
    return NS_BINDING_FAILED;
  }

  // the redirect is permitted, so propagate the Content Security Policy
  // and load type to the redirecting channel
  nsresult rv;
  nsCOMPtr<nsIWritablePropertyBag2> props2 = do_QueryInterface(newChannel, &rv);
  if (props2)
    props2->SetPropertyAsInterface(NS_CHANNEL_PROP_CHANNEL_POLICY,
                                   channelPolicy);

  return NS_OK;
}
