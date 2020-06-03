void
CVE_2012_3964_VULN_nsTextFrame::SetLength(PRInt32 aLength, nsLineLayout* aLineLayout,
                       PRUint32 aSetLengthFlags)
{
  mContentLengthHint = aLength;
  PRInt32 end = GetContentOffset() + aLength;
  nsTextFrame* f = static_cast<nsTextFrame*>(GetNextInFlow());
  if (!f)
    return;

  // If our end offset is moving, then even if frames are not being pushed or
  // pulled, content is moving to or from the next line and the next line
  // must be reflowed.
  // If the next-continuation is dirty, then we should dirty the next line now
  // because we may have skipped doing it if we dirtied it in
  // CharacterDataChanged. This is ugly but teaching FrameNeedsReflow
  // and ChildIsDirty to handle a range of frames would be worse.
  if (aLineLayout &&
      (end != f->mContentOffset || (f->GetStateBits() & NS_FRAME_IS_DIRTY))) {
    aLineLayout->SetDirtyNextLine();
  }

  if (end < f->mContentOffset) {
    // Our frame is shrinking. Give the text to our next in flow.
    if (aLineLayout &&
        GetStyleText()->WhiteSpaceIsSignificant() &&
        HasTerminalNewline() &&
        GetParent()->GetType() != nsGkAtoms::letterFrame &&
        (aSetLengthFlags & ALLOW_FRAME_CREATION_AND_DESTRUCTION)) {
      // Whatever text we hand to our next-in-flow will end up in a frame all of
      // its own, since it ends in a forced linebreak.  Might as well just put
      // it in a separate frame now.  This is important to prevent text run
      // churn; if we did not do that, then we'd likely end up rebuilding
      // textruns for all our following continuations.
      // We skip this optimization when the parent is a first-letter frame
      // because it doesn't deal well with more than one child frame.
      // We also skip this optimization if we were called during bidi
      // resolution, so as not to create a new frame which doesn't appear in
      // the bidi resolver's list of frames
      nsPresContext* presContext = PresContext();
      nsIFrame* newFrame;
      nsresult rv = presContext->PresShell()->FrameConstructor()->
        CreateContinuingFrame(presContext, this, GetParent(), &newFrame);
      if (NS_SUCCEEDED(rv)) {
        nsTextFrame* next = static_cast<nsTextFrame*>(newFrame);
        nsFrameList temp(next, next);
        GetParent()->InsertFrames(kNoReflowPrincipalList, this, temp);
        f = next;
      }
    }

    f->mContentOffset = end;
    if (f->GetTextRun(nsTextFrame::eInflated) != mTextRun) {
      ClearTextRuns();
      f->ClearTextRuns();
    }
    return;
  }
  // Our frame is growing. Take text from our in-flow(s).
  // We can take text from frames in lines beyond just the next line.
  // We don't dirty those lines. That's OK, because when we reflow
  // our empty next-in-flow, it will take text from its next-in-flow and
  // dirty that line.

  // Note that in the process we may end up removing some frames from
  // the flow if they end up empty.
  nsIFrame *framesToRemove = nsnull;
  while (f && f->mContentOffset < end) {
    f->mContentOffset = end;
    if (f->GetTextRun(nsTextFrame::eInflated) != mTextRun) {
      ClearTextRuns();
      f->ClearTextRuns();
    }
    nsTextFrame* next = static_cast<nsTextFrame*>(f->GetNextInFlow());
    // Note: the "f->GetNextSibling() == next" check below is to restrict
    // this optimization to the case where they are on the same child list.
    // Otherwise we might remove the only child of a nsFirstLetterFrame
    // for example and it can't handle that.  See bug 597627 for details.
    if (next && next->mContentOffset <= end && f->GetNextSibling() == next &&
        (aSetLengthFlags & ALLOW_FRAME_CREATION_AND_DESTRUCTION)) {
      // |f| is now empty.  We may as well remove it, instead of copying all
      // the text from |next| into it instead; the latter leads to use
      // rebuilding textruns for all following continuations.
      // We skip this optimization if we were called during bidi resolution,
      // since the bidi resolver may try to handle the destroyed frame later
      // and crash
      if (!framesToRemove) {
        // Remember that we have to remove this frame.
        framesToRemove = f;
      }

      // Important: if |f| has the same style context as its prev continuation,
      // mark it accordingly so we can skip clearing textruns as needed.  Note
      // that at this point f always has a prev continuation.
      if (f->GetStyleContext() == f->GetPrevContinuation()->GetStyleContext()) {
        f->AddStateBits(TEXT_STYLE_MATCHES_PREV_CONTINUATION);
      }
    } else if (framesToRemove) {
      RemoveInFlows(framesToRemove, f);
      framesToRemove = nsnull;
    }
    f = next;
  }
  NS_POSTCONDITION(!framesToRemove || (f && f->mContentOffset == end),
                   "How did we exit the loop if we null out framesToRemove if "
                   "!next || next->mContentOffset > end ?");
  if (framesToRemove) {
    // We are guaranteed that we exited the loop with f not null, per the
    // postcondition above
    RemoveInFlows(framesToRemove, f);
  }

#ifdef DEBUG
  f = this;
  PRInt32 iterations = 0;
  while (f && iterations < 10) {
    f->GetContentLength(); // Assert if negative length
    f = static_cast<nsTextFrame*>(f->GetNextContinuation());
    ++iterations;
  }
  f = this;
  iterations = 0;
  while (f && iterations < 10) {
    f->GetContentLength(); // Assert if negative length
    f = static_cast<nsTextFrame*>(f->GetPrevContinuation());
    ++iterations;
  }
#endif
}
