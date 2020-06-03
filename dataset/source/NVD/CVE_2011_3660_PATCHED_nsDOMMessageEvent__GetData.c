NS_IMETHODIMP
CVE_2011_3660_PATCHED_nsDOMMessageEvent::GetData(JSContext* aCx, jsval* aData)
{
  *aData = mData;
  if (!JS_WrapValue(aCx, aData))
    return NS_ERROR_FAILURE;
  return NS_OK;
}
