  void CVE_2011_0073_PATCHED_Invalidate() {
    nsTArray<PRInt32> ranges;
    CollectRanges(this, ranges);
    InvalidateRanges(mSelection->mTree, ranges);
    
  }
