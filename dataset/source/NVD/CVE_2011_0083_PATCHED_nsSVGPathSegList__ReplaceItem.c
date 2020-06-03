NS_IMETHODIMP CVE_2011_0083_PATCHED_nsSVGPathSegList::ReplaceItem(nsIDOMSVGPathSeg *newItem,
                                            PRUint32 index,
                                            nsIDOMSVGPathSeg **_retval)
{
  NS_ENSURE_NATIVE_PATH_SEG(newItem, _retval);

  if (index >= static_cast<PRUint32>(mSegments.Count())) {
    return NS_ERROR_DOM_INDEX_SIZE_ERR;
  }

  // immediately remove the new item from its current list
  nsSVGPathSeg* newItemSeg = static_cast<nsSVGPathSeg*>(newItem);
  RemoveFromCurrentList(newItemSeg);

  // check length *again*, since mutation listener may have changed it!
  if (index >= static_cast<PRUint32>(mSegments.Count())) {
    return NS_ERROR_DOM_INDEX_SIZE_ERR;
  }

  WillModify();
  mSegments.ReplaceObjectAt(newItemSeg, index);
  newItemSeg->SetCurrentList(this);
  DidModify();

  NS_ADDREF(*_retval = newItem);
  return NS_OK;
}
