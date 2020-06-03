  void CVE_2012_3964_PATCHED_ClearTextRuns() {
    ClearTextRun(nsnull, nsTextFrame::eInflated);
    if (HasFontSizeInflation()) {
      ClearTextRun(nsnull, nsTextFrame::eNotInflated);
    }
  }
