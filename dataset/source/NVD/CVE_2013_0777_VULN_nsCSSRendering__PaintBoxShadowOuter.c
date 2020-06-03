void
CVE_2013_0777_VULN_nsCSSRendering::PaintBoxShadowOuter(nsPresContext* aPresContext,
                                    nsRenderingContext& aRenderingContext,
                                    nsIFrame* aForFrame,
                                    const nsRect& aFrameArea,
                                    const nsRect& aDirtyRect)
{
  const nsStyleBorder* styleBorder = aForFrame->GetStyleBorder();
  nsCSSShadowArray* shadows = styleBorder->mBoxShadow;
  if (!shadows)
    return;
  nscoord twipsPerPixel = aPresContext->DevPixelsToAppUnits(1);

  bool hasBorderRadius;
  bool nativeTheme; // mutually exclusive with hasBorderRadius
  gfxCornerSizes borderRadii;

  // Get any border radius, since box-shadow must also have rounded corners if the frame does
  const nsStyleDisplay* styleDisplay = aForFrame->GetStyleDisplay();
  nsITheme::Transparency transparency;
  if (aForFrame->IsThemed(styleDisplay, &transparency)) {
    // We don't respect border-radius for native-themed widgets
    hasBorderRadius = false;
    // For opaque (rectangular) theme widgets we can take the generic
    // border-box path with border-radius disabled.
    nativeTheme = transparency != nsITheme::eOpaque;
  } else {
    nativeTheme = false;
    nscoord twipsRadii[8];
    NS_ASSERTION(aFrameArea.Size() == aForFrame->GetSize(), "unexpected size");
    hasBorderRadius = aForFrame->GetBorderRadii(twipsRadii);
    if (hasBorderRadius) {
      ComputePixelRadii(twipsRadii, twipsPerPixel, &borderRadii);
    }
  }

  nsRect frameRect =
    nativeTheme ? aForFrame->GetVisualOverflowRectRelativeToSelf() + aFrameArea.TopLeft() : aFrameArea;
  gfxRect frameGfxRect(nsLayoutUtils::RectToGfxRect(frameRect, twipsPerPixel));
  frameGfxRect.Round();

  // We don't show anything that intersects with the frame we're blurring on. So tell the
  // blurrer not to do unnecessary work there.
  gfxRect skipGfxRect = frameGfxRect;
  bool useSkipGfxRect = true;
  if (nativeTheme) {
    // Optimize non-leaf native-themed frames by skipping computing pixels
    // in the padding-box. We assume the padding-box is going to be painted
    // opaquely for non-leaf frames.
    // XXX this may not be a safe assumption; we should make this go away
    // by optimizing box-shadow drawing more for the cases where we don't have a skip-rect.
    useSkipGfxRect = !aForFrame->IsLeaf();
    nsRect paddingRect =
      aForFrame->GetPaddingRect() - aForFrame->GetPosition() + aFrameArea.TopLeft();
    skipGfxRect = nsLayoutUtils::RectToGfxRect(paddingRect, twipsPerPixel);
  } else if (hasBorderRadius) {
    skipGfxRect.Deflate(gfxMargin(
        0, NS_MAX(borderRadii[C_TL].height, borderRadii[C_TR].height),
        0, NS_MAX(borderRadii[C_BL].height, borderRadii[C_BR].height)));
  }

  for (uint32_t i = shadows->Length(); i > 0; --i) {
    nsCSSShadowItem* shadowItem = shadows->ShadowAt(i - 1);
    if (shadowItem->mInset)
      continue;

    nsRect shadowRect = frameRect;
    shadowRect.MoveBy(shadowItem->mXOffset, shadowItem->mYOffset);
    nscoord pixelSpreadRadius;
    if (nativeTheme) {
      pixelSpreadRadius = shadowItem->mSpread;
    } else {
      shadowRect.Inflate(shadowItem->mSpread, shadowItem->mSpread);
      pixelSpreadRadius = 0;
    }

    // shadowRect won't include the blur, so make an extra rect here that includes the blur
    // for use in the even-odd rule below.
    nsRect shadowRectPlusBlur = shadowRect;
    nscoord blurRadius = shadowItem->mRadius;
    shadowRectPlusBlur.Inflate(
      nsContextBoxBlur::GetBlurRadiusMargin(blurRadius, twipsPerPixel));

    gfxRect shadowGfxRect =
      nsLayoutUtils::RectToGfxRect(shadowRect, twipsPerPixel);
    gfxRect shadowGfxRectPlusBlur =
      nsLayoutUtils::RectToGfxRect(shadowRectPlusBlur, twipsPerPixel);
    shadowGfxRect.Round();
    shadowGfxRectPlusBlur.RoundOut();

    gfxContext* renderContext = aRenderingContext.ThebesContext();
    nsRefPtr<gfxContext> shadowContext;
    nsContextBoxBlur blurringArea;

    // When getting the widget shape from the native theme, we're going
    // to draw the widget into the shadow surface to create a mask.
    // We need to ensure that there actually *is* a shadow surface
    // and that we're not going to draw directly into renderContext.
    shadowContext = 
      blurringArea.Init(shadowRect, pixelSpreadRadius,
                        blurRadius, twipsPerPixel, renderContext, aDirtyRect,
                        useSkipGfxRect ? &skipGfxRect : nullptr,
                        nativeTheme ? nsContextBoxBlur::FORCE_MASK : 0);
    if (!shadowContext)
      continue;

    // Set the shadow color; if not specified, use the foreground color
    nscolor shadowColor;
    if (shadowItem->mHasColor)
      shadowColor = shadowItem->mColor;
    else
      shadowColor = aForFrame->GetStyleColor()->mColor;

    renderContext->Save();
    renderContext->SetColor(gfxRGBA(shadowColor));

    // Draw the shape of the frame so it can be blurred. Recall how nsContextBoxBlur
    // doesn't make any temporary surfaces if blur is 0 and it just returns the original
    // surface? If we have no blur, we're painting this fill on the actual content surface
    // (renderContext == shadowContext) which is why we set up the color and clip
    // before doing this.
    if (nativeTheme) {
      // We don't clip the border-box from the shadow, nor any other box.
      // We assume that the native theme is going to paint over the shadow.

      // Draw the widget shape
      gfxContextMatrixAutoSaveRestore save(shadowContext);
      nsRefPtr<nsRenderingContext> wrapperCtx = new nsRenderingContext();
      wrapperCtx->Init(aPresContext->DeviceContext(), shadowContext);
      wrapperCtx->Translate(nsPoint(shadowItem->mXOffset,
                                    shadowItem->mYOffset));

      nsRect nativeRect;
      nativeRect.IntersectRect(frameRect, aDirtyRect);
      aPresContext->GetTheme()->DrawWidgetBackground(wrapperCtx, aForFrame,
          styleDisplay->mAppearance, aFrameArea, nativeRect);
    } else {
      // Clip out the area of the actual frame so the shadow is not shown within
      // the frame
      renderContext->NewPath();
      renderContext->Rectangle(shadowGfxRectPlusBlur);
      if (hasBorderRadius) {
        renderContext->RoundedRectangle(frameGfxRect, borderRadii);
      } else {
        renderContext->Rectangle(frameGfxRect);
      }

      renderContext->SetFillRule(gfxContext::FILL_RULE_EVEN_ODD);
      renderContext->Clip();

      shadowContext->NewPath();
      if (hasBorderRadius) {
        gfxCornerSizes clipRectRadii;
        gfxFloat spreadDistance = shadowItem->mSpread / twipsPerPixel;

        gfxFloat borderSizes[4];

        borderSizes[NS_SIDE_LEFT] = spreadDistance;
        borderSizes[NS_SIDE_TOP] = spreadDistance;
        borderSizes[NS_SIDE_RIGHT] = spreadDistance;
        borderSizes[NS_SIDE_BOTTOM] = spreadDistance;

        nsCSSBorderRenderer::ComputeOuterRadii(borderRadii, borderSizes,
            &clipRectRadii);
        shadowContext->RoundedRectangle(shadowGfxRect, clipRectRadii);
      } else {
        shadowContext->Rectangle(shadowGfxRect);
      }
      shadowContext->Fill();
    }

    blurringArea.DoPaint();
    renderContext->Restore();
  }
}
