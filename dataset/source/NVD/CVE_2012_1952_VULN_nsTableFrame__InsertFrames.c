NS_IMETHODIMP
CVE_2012_1952_VULN_nsTableFrame::InsertFrames(ChildListID     aListID,
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

  // See what kind of frame we have
  const nsStyleDisplay* display = aFrameList.FirstChild()->GetStyleDisplay();
#ifdef DEBUG
  // verify that all sibling have the same type, if they do not, expect cellmap issues
  for (nsFrameList::Enumerator e(aFrameList); !e.AtEnd(); e.Next()) {
    const nsStyleDisplay* nextDisplay = e.get()->GetStyleDisplay();
    NS_ASSERTION((display->mDisplay == NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP) ==
        (nextDisplay->mDisplay == NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP),
      "heterogenous childlist");
  }
#endif
  if (aPrevFrame) {
    const nsStyleDisplay* prevDisplay = aPrevFrame->GetStyleDisplay();
    // Make sure they belong on the same frame list
    if ((display->mDisplay == NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP) !=
        (prevDisplay->mDisplay == NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP)) {
      // the previous frame is not valid, see comment at ::AppendFrames
      // XXXbz Using content indices here means XBL will get screwed
      // over...  Oh, well.
      nsIFrame* pseudoFrame = aFrameList.FirstChild();
      nsIContent* parentContent = GetContent();
      nsIContent* content;
      aPrevFrame = nsnull;
      while (pseudoFrame  && (parentContent ==
                              (content = pseudoFrame->GetContent()))) {
        pseudoFrame = pseudoFrame->GetFirstPrincipalChild();
      }
      nsCOMPtr<nsIContent> container = content->GetParent();
      if (NS_LIKELY(container)) { // XXX need this null-check, see bug 411823.
        PRInt32 newIndex = container->IndexOf(content);
        nsIFrame* kidFrame;
        bool isColGroup = (NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP ==
                             display->mDisplay);
        nsTableColGroupFrame* lastColGroup;
        if (isColGroup) {
          kidFrame = mColGroups.FirstChild();
          lastColGroup = nsTableColGroupFrame::GetLastRealColGroup(this);
        }
        else {
          kidFrame = mFrames.FirstChild();
        }
        // Important: need to start at a value smaller than all valid indices
        PRInt32 lastIndex = -1;
        while (kidFrame) {
          if (isColGroup) {
            if (kidFrame == lastColGroup) {
              aPrevFrame = kidFrame; // there is no real colgroup after this one
              break;
            }
          }
          pseudoFrame = kidFrame;
          while (pseudoFrame  && (parentContent ==
                                  (content = pseudoFrame->GetContent()))) {
            pseudoFrame = pseudoFrame->GetFirstPrincipalChild();
          }
          PRInt32 index = container->IndexOf(content);
          if (index > lastIndex && index < newIndex) {
            lastIndex = index;
            aPrevFrame = kidFrame;
          }
          kidFrame = kidFrame->GetNextSibling();
        }
      }
    }
  }
  if (NS_STYLE_DISPLAY_TABLE_COLUMN_GROUP == display->mDisplay) {
    NS_ASSERTION(aListID == kPrincipalList || aListID == kColGroupList,
                 "unexpected child list");
    // Insert the column group frames
    const nsFrameList::Slice& newColgroups =
      mColGroups.InsertFrames(nsnull, aPrevFrame, aFrameList);
    // find the starting col index for the first new col group
    PRInt32 startColIndex = 0;
    if (aPrevFrame) {
      nsTableColGroupFrame* prevColGroup =
        (nsTableColGroupFrame*)GetFrameAtOrBefore(this, aPrevFrame,
                                                  nsGkAtoms::tableColGroupFrame);
      if (prevColGroup) {
        startColIndex = prevColGroup->GetStartColumnIndex() + prevColGroup->GetColCount();
      }
    }
    InsertColGroups(startColIndex, newColgroups);
  } else if (IsRowGroup(display->mDisplay)) {
    NS_ASSERTION(aListID == kPrincipalList, "unexpected child list");
    // Insert the frames in the sibling chain
    const nsFrameList::Slice& newRowGroups =
      mFrames.InsertFrames(nsnull, aPrevFrame, aFrameList);

    InsertRowGroups(newRowGroups);
  } else {
    NS_ASSERTION(aListID == kPrincipalList, "unexpected child list");
    NS_NOTREACHED("How did we even get here?");
    // Just insert the frame and don't worry about reflowing it
    mFrames.InsertFrames(nsnull, aPrevFrame, aFrameList);
    return NS_OK;
  }

  PresContext()->PresShell()->FrameNeedsReflow(this, nsIPresShell::eTreeChange,
                                               NS_FRAME_HAS_DIRTY_CHILDREN);
  SetGeometryDirty();
#ifdef DEBUG_TABLE_CELLMAP
  printf("=== TableFrame::InsertFrames\n");
  Dump(true, true, true);
#endif
  return NS_OK;
}
