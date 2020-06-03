NS_IMETHODIMP
CVE_2012_1952_PATCHED_nsTableFrame::InsertFrames(ChildListID     aListID,
                           nsIFrame*       aPrevFrame,
                           nsFrameList&    aFrameList)
{
  // Asssume there's only one frame being inserted. The problem is that
  // row group frames and col group frames go in separate child lists and
  // so if there's more than one type of frames this gets messy...
  // XXX The frame construction code should be separating out child frames
  // based on the type, bug 343048.

  NS_ASSERTION(!aPrevFrame || aPrevFrame->GetParent() == this,
               "inserting after sibling frame with different parent");

  if ((aPrevFrame && !aPrevFrame->GetNextSibling()) ||
      (!aPrevFrame && GetChildList(aListID).IsEmpty())) {
    // Treat this like an append; still a workaround for bug 343048.
    return AppendFrames(aListID, aFrameList);
  }

  // Collect ColGroupFrames into a separate list and insert those separately
  // from the other frames (bug 759249).
  ChildListInsertions insertions[2]; // ColGroup, other
  const nsStyleDisplay* display = aFrameList.FirstChild()->GetStyleDisplay();
  nsFrameList::FrameLinkEnumerator e(aFrameList);
  for (; !aFrameList.IsEmpty(); e.Next()) {
    nsIFrame* next = e.NextFrame();
    if (!next || next->GetStyleDisplay()->mDisplay != display->mDisplay) {
      nsFrameList head = aFrameList.ExtractHead(e);
      if (display->mDisplay == NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP) {
        insertions[0].mID = kColGroupList;
        insertions[0].mList.AppendFrames(nsnull, head);
      } else {
        insertions[1].mID = kPrincipalList;
        insertions[1].mList.AppendFrames(nsnull, head);
      }
      if (!next) {
        break;
      }
      display = next->GetStyleDisplay();
    }
  }
  for (PRUint32 i = 0; i < ArrayLength(insertions); ++i) {
    // We pass aPrevFrame for both ColGroup and other frames since
    // HomogenousInsertFrames will only use it if it's a suitable
    // prev-sibling for the frames in the frame list.
    if (!insertions[i].mList.IsEmpty()) {
      HomogenousInsertFrames(insertions[i].mID, aPrevFrame,
                             insertions[i].mList);
    }
  }
  return NS_OK;
}
