bool CVE_2013_1696_PATCHED_nsDSURIContentListener::CheckFrameOptions(nsIRequest *request)
{
    nsresult rv;
    nsCOMPtr<nsIChannel> chan = do_QueryInterface(request);
    if (!chan) {
      return true;
    }

    nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(chan);
    if (!httpChannel) {
      // check if it is hiding in a multipart channel
      rv = mDocShell->GetHttpChannel(chan, getter_AddRefs(httpChannel));
      if (NS_FAILED(rv))
        return false;
    }

    if (!httpChannel) {
        return true;
    }

    nsAutoCString xfoHeaderCValue;
    httpChannel->GetResponseHeader(NS_LITERAL_CSTRING("X-Frame-Options"),
                                   xfoHeaderCValue);
    NS_ConvertUTF8toUTF16 xfoHeaderValue(xfoHeaderCValue);

    // if no header value, there's nothing to do.
    if (xfoHeaderValue.IsEmpty())
        return true;

    // iterate through all the header values (usually there's only one, but can
    // be many.  If any want to deny the load, deny the load.
    nsCharSeparatedTokenizer tokenizer(xfoHeaderValue, ',');
    while (tokenizer.hasMoreTokens()) {
        const nsSubstring& tok = tokenizer.nextToken();
        if (!CheckOneFrameOptionsPolicy(httpChannel, tok)) {
            // cancel the load and display about:blank
            httpChannel->Cancel(NS_BINDING_ABORTED);
            if (mDocShell) {
                nsCOMPtr<nsIWebNavigation> webNav(do_QueryObject(mDocShell));
                if (webNav) {
                    webNav->LoadURI(NS_LITERAL_STRING("about:blank").get(),
                                    0, nullptr, nullptr, nullptr);
                }
            }
            return false;
        }
    }

    return true;
}
