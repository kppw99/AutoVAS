NS_IMETHODIMP
CVE_2011_2984_PATCHED_nsDOMDataTransfer::MozGetDataAt(const nsAString& aFormat,
                                PRUint32 aIndex,
                                nsIVariant** aData)
{
  *aData = nsnull;

  if (aFormat.IsEmpty())
    return NS_OK;

  if (aIndex >= mItems.Length())
    return NS_ERROR_DOM_INDEX_SIZE_ERR;

  nsAutoString format;
  GetRealFormat(aFormat, format);

  nsTArray<TransferItem>& item = mItems[aIndex];

  // allow access to any data in the drop and dragdrop events, or if the
  // UniversalBrowserRead privilege is set, otherwise only allow access to
  // data from the same principal.

  PRUint32 count = item.Length();
  for (PRUint32 i = 0; i < count; i++) {
    TransferItem& formatitem = item[i];
    if (formatitem.mFormat.Equals(format)) {
      if (formatitem.mPrincipal &&
          !nsContentUtils::IsCallerTrustedForCapability("UniversalBrowserRead")) {
        if (mEventType != NS_DRAGDROP_DROP && mEventType != NS_DRAGDROP_DRAGDROP) {
          PRBool subsumes;
          nsIPrincipal* principal = GetCurrentPrincipal();
          if (principal &&
              (NS_FAILED(principal->Subsumes(formatitem.mPrincipal, &subsumes)) ||
               !subsumes))
            return NS_ERROR_DOM_SECURITY_ERR;
        } else {
          nsIScriptSecurityManager *ssm = nsContentUtils::GetSecurityManager();
          PRBool isSystem;
          if (NS_FAILED(ssm->IsSystemPrincipal(formatitem.mPrincipal, &isSystem)) ||
              isSystem)
            return NS_ERROR_DOM_SECURITY_ERR;
        }
      }

      if (!formatitem.mData)
        FillInExternalDragData(formatitem, aIndex);
      *aData = formatitem.mData;
      NS_IF_ADDREF(*aData);
      return NS_OK;
    }
  }

  return NS_OK;
}
