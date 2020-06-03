bool
CVE_2012_3962_PATCHED_nsTextFrame::IsFloatingFirstLetterChild() const
{
  nsIFrame* frame = GetParent();
  return frame && frame->GetStyleDisplay()->IsFloating() &&
         frame->GetType() == nsGkAtoms::letterFrame;
}
