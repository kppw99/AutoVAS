NS_IMETHODIMP CVE_2011_0083_VULN_nsSVGPathSegList::ReplaceItem(nsIDOMSVGPathSeg *newItem,
                                            PRUint32 index,
                                            nsIDOMSVGPathSeg **_retval)
{
  NS_ENSURE_NATIVE_PATH_SEG(newItem, _retval);

  // immediately remove the new item from its current list
  nsSVGPathSeg* newItemSeg = static_cast<nsSVGPathSeg*>(newItem);
  RemoveFromCurrentList(newItemSeg);

  if (index >= static_cast<PRUint32>(mSegments.Count())) {
    return NS_ERROR_DOM_INDEX_SIZE_ERR;
  }

  // NOTE: the new item can never be the item we will be replacing now that we removed it from its current list beforehand
  InsertElementAt(newItemSeg, index);
  RemoveFromCurrentList(static_cast<nsSVGPathSeg*>(mSegments.ObjectAt(index+1)));
  NS_ADDREF(*_retval = newItem);

  return NS_OK;
}
