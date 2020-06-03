NS_IMETHODIMP
CVE_2013_0790_VULN_nsPluginStreamListenerPeer::OnStartRequest(nsIRequest *request,
                                           nsISupports* aContext)
{
  nsresult rv = NS_OK;
  SAMPLE_LABEL("nsPluginStreamListenerPeer", "OnStartRequest");

  if (mRequests.IndexOfObject(GetBaseRequest(request)) == -1) {
    NS_ASSERTION(mRequests.Count() == 0,
                 "Only our initial stream should be unknown!");
    TrackRequest(request);
  }
  
  if (mHaveFiredOnStartRequest) {
    return NS_OK;
  }
  
  mHaveFiredOnStartRequest = true;
  
  nsCOMPtr<nsIChannel> channel = do_QueryInterface(request);
  NS_ENSURE_TRUE(channel, NS_ERROR_FAILURE);
  
  // deal with 404 (Not Found) HTTP response,
  // just return, this causes the request to be ignored.
  nsCOMPtr<nsIHttpChannel> httpChannel(do_QueryInterface(channel));
  if (httpChannel) {
    uint32_t responseCode = 0;
    rv = httpChannel->GetResponseStatus(&responseCode);
    if (NS_FAILED(rv)) {
      // NPP_Notify() will be called from OnStopRequest
      // in nsNPAPIPluginStreamListener::CleanUpStream
      // return error will cancel this request
      // ...and we also need to tell the plugin that
      mRequestFailed = true;
      return NS_ERROR_FAILURE;
    }
    
    if (responseCode > 206) { // not normal
      bool bWantsAllNetworkStreams = false;

      // We don't always have an instance here already, but if we do, check
      // to see if it wants all streams.
      if (mPluginInstance) {
        rv = mPluginInstance->GetValueFromPlugin(NPPVpluginWantsAllNetworkStreams,
                                                 &bWantsAllNetworkStreams);
        // If the call returned an error code make sure we still use our default value.
        if (NS_FAILED(rv)) {
          bWantsAllNetworkStreams = false;
        }
      }

      if (!bWantsAllNetworkStreams) {
        mRequestFailed = true;
        return NS_ERROR_FAILURE;
      }
    }
  }
  
  // Get the notification callbacks from the channel and save it as
  // week ref we'll use it in nsPluginStreamInfo::RequestRead() when
  // we'll create channel for byte range request.
  nsCOMPtr<nsIInterfaceRequestor> callbacks;
  channel->GetNotificationCallbacks(getter_AddRefs(callbacks));
  if (callbacks)
    mWeakPtrChannelCallbacks = do_GetWeakReference(callbacks);
  
  nsCOMPtr<nsILoadGroup> loadGroup;
  channel->GetLoadGroup(getter_AddRefs(loadGroup));
  if (loadGroup)
    mWeakPtrChannelLoadGroup = do_GetWeakReference(loadGroup);
  
  int64_t length;
  rv = channel->GetContentLength(&length);
  
  // it's possible for the server to not send a Content-Length.
  // we should still work in this case.
  if (NS_FAILED(rv) || length == -1) {
    // check out if this is file channel
    nsCOMPtr<nsIFileChannel> fileChannel = do_QueryInterface(channel);
    if (fileChannel) {
      // file does not exist
      mRequestFailed = true;
      return NS_ERROR_FAILURE;
    }
    mLength = 0;
  }
  else {
    mLength = length;
  }
  
  nsAutoCString aContentType; // XXX but we already got the type above!
  rv = channel->GetContentType(aContentType);
  if (NS_FAILED(rv))
    return rv;
  
  nsCOMPtr<nsIURI> aURL;
  rv = channel->GetURI(getter_AddRefs(aURL));
  if (NS_FAILED(rv))
    return rv;
  
  aURL->GetSpec(mURLSpec);
  
  if (!aContentType.IsEmpty())
    mContentType = aContentType;
  
#ifdef PLUGIN_LOGGING
  PR_LOG(nsPluginLogging::gPluginLog, PLUGIN_LOG_NOISY,
         ("CVE_2013_0790_VULN_nsPluginStreamListenerPeer::OnStartRequest this=%p request=%p mime=%s, url=%s\n",
          this, request, aContentType.get(), mURLSpec.get()));
  
  PR_LogFlush();
#endif

  // If we don't have an instance yet it means we weren't able to load
  // a plugin previously because we didn't have the mimetype. Try again
  // if we have a mime type now.
  if (!mPluginInstance && mContent && !aContentType.IsEmpty()) {
    nsObjectLoadingContent *olc = static_cast<nsObjectLoadingContent*>(mContent.get());
    rv = olc->InstantiatePluginInstance();
    if (NS_SUCCEEDED(rv)) {
      rv = olc->GetPluginInstance(getter_AddRefs(mPluginInstance));
      if (NS_FAILED(rv)) {
        return rv;
      }
    }
  }

  // Set up the stream listener...
  rv = SetUpStreamListener(request, aURL);
  if (NS_FAILED(rv)) return rv;
  
  return rv;
}
