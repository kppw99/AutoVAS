  void CVE_2011_0073_VULN_Invalidate() {
    if (mSelection->mTree)
      mSelection->mTree->InvalidateRange(mMin, mMax);
    if (mNext)
      mNext->CVE_2011_0073_VULN_Invalidate();
  }
