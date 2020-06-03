static cairo_status_t
CVE_2013_1678_VULN__cairo_xlib_surface_add_glyph (cairo_xlib_display_t *display,
			       cairo_scaled_font_t   *scaled_font,
			       cairo_scaled_glyph_t **pscaled_glyph)
{
    XGlyphInfo glyph_info;
    unsigned long glyph_index;
    unsigned char *data;
    cairo_status_t status = CAIRO_STATUS_SUCCESS;
    cairo_scaled_glyph_t *scaled_glyph = *pscaled_glyph;
    cairo_image_surface_t *glyph_surface = scaled_glyph->surface;
    cairo_bool_t already_had_glyph_surface;
    cairo_xlib_font_glyphset_info_t *glyphset_info;

    glyph_index = _cairo_scaled_glyph_index (scaled_glyph);

    /* check to see if we have a pending XRenderFreeGlyph for this glyph */
    glyphset_info = _cairo_xlib_scaled_font_get_glyphset_info_for_pending_free_glyph (scaled_font, glyph_index, glyph_surface);
    if (glyphset_info != NULL) {
	_cairo_xlib_scaled_glyph_set_glyphset_info (scaled_glyph, glyphset_info);
	return CAIRO_STATUS_SUCCESS;
    }

    if (!glyph_surface) {
	status = _cairo_scaled_glyph_lookup (scaled_font,
					     glyph_index,
					     CAIRO_SCALED_GLYPH_INFO_METRICS |
					     CAIRO_SCALED_GLYPH_INFO_SURFACE,
					     pscaled_glyph);
	if (unlikely (status))
	    return status;

	scaled_glyph = *pscaled_glyph;
	glyph_surface = scaled_glyph->surface;
	already_had_glyph_surface = FALSE;
    } else {
	already_had_glyph_surface = TRUE;
    }

    if (scaled_font->surface_private == NULL) {
	status = _cairo_xlib_surface_font_init (display, scaled_font);
	if (unlikely (status))
	    return status;
    }

    glyphset_info = _cairo_xlib_scaled_font_get_glyphset_info_for_format (scaled_font,
									  glyph_surface->format);

    /* XRenderAddGlyph does not handle a glyph surface larger than the extended maximum XRequest size.  */
    {
	int len = cairo_format_stride_for_width (glyphset_info->format, glyph_surface->width) * glyph_surface->height;
	int max_request_size = (XExtendedMaxRequestSize (display->display) ? XExtendedMaxRequestSize (display->display)
                                                                           : XMaxRequestSize (display->display)) * 4 -
	                       sz_xRenderAddGlyphsReq -
	                       sz_xGlyphInfo          -
			       8;
	if (len >= max_request_size)
	    return UNSUPPORTED ("glyph too large for XRequest");
    }

    /* If the glyph surface has zero height or width, we create
     * a clear 1x1 surface, to avoid various X server bugs.
     */
    if (glyph_surface->width == 0 || glyph_surface->height == 0) {
	cairo_surface_t *tmp_surface;

	tmp_surface = cairo_image_surface_create (glyphset_info->format, 1, 1);
	status = tmp_surface->status;
	if (unlikely (status))
	    goto BAIL;

	tmp_surface->device_transform = glyph_surface->base.device_transform;
	tmp_surface->device_transform_inverse = glyph_surface->base.device_transform_inverse;

	glyph_surface = (cairo_image_surface_t *) tmp_surface;
    }

    /* If the glyph format does not match the font format, then we
     * create a temporary surface for the glyph image with the font's
     * format.
     */
    if (glyph_surface->format != glyphset_info->format) {
	cairo_surface_pattern_t pattern;
	cairo_surface_t *tmp_surface;

	tmp_surface = cairo_image_surface_create (glyphset_info->format,
						  glyph_surface->width,
						  glyph_surface->height);
	status = tmp_surface->status;
	if (unlikely (status))
	    goto BAIL;

	tmp_surface->device_transform = glyph_surface->base.device_transform;
	tmp_surface->device_transform_inverse = glyph_surface->base.device_transform_inverse;

	_cairo_pattern_init_for_surface (&pattern, &glyph_surface->base);
	status = _cairo_surface_paint (tmp_surface,
				       CAIRO_OPERATOR_SOURCE, &pattern.base,
				       NULL);
	_cairo_pattern_fini (&pattern.base);

	glyph_surface = (cairo_image_surface_t *) tmp_surface;

	if (unlikely (status))
	    goto BAIL;
    }

    /* XXX: FRAGILE: We're ignore device_transform scaling here. A bug? */
    glyph_info.x = _cairo_lround (glyph_surface->base.device_transform.x0);
    glyph_info.y = _cairo_lround (glyph_surface->base.device_transform.y0);
    glyph_info.width = glyph_surface->width;
    glyph_info.height = glyph_surface->height;
    glyph_info.xOff = scaled_glyph->x_advance;
    glyph_info.yOff = scaled_glyph->y_advance;

    data = glyph_surface->data;

    /* flip formats around */
    switch (_cairo_xlib_get_glyphset_index_for_format (scaled_glyph->surface->format)) {
    case GLYPHSET_INDEX_A1:
	/* local bitmaps are always stored with bit == byte */
	if (_native_byte_order_lsb() != (BitmapBitOrder (display->display) == LSBFirst)) {
	    int		    c = glyph_surface->stride * glyph_surface->height;
	    unsigned char   *d;
	    unsigned char   *new, *n;

	    new = malloc (c);
	    if (!new) {
		status = _cairo_error (CAIRO_STATUS_NO_MEMORY);
		goto BAIL;
	    }
	    n = new;
	    d = data;
	    do {
		char	b = *d++;
		b = ((b << 1) & 0xaa) | ((b >> 1) & 0x55);
		b = ((b << 2) & 0xcc) | ((b >> 2) & 0x33);
		b = ((b << 4) & 0xf0) | ((b >> 4) & 0x0f);
		*n++ = b;
	    } while (--c);
	    data = new;
	}
	break;
    case GLYPHSET_INDEX_A8:
	break;
    case GLYPHSET_INDEX_ARGB32:
	if (_native_byte_order_lsb() != (ImageByteOrder (display->display) == LSBFirst)) {
	    unsigned int c = glyph_surface->stride * glyph_surface->height / 4;
	    const uint32_t *d;
	    uint32_t *new, *n;

	    new = malloc (4 * c);
	    if (unlikely (new == NULL)) {
		status = _cairo_error (CAIRO_STATUS_NO_MEMORY);
		goto BAIL;
	    }
	    n = new;
	    d = (uint32_t *) data;
	    do {
		*n++ = bswap_32 (*d);
		d++;
	    } while (--c);
	    data = (uint8_t *) new;
	}
	break;
    default:
	ASSERT_NOT_REACHED;
	break;
    }
    /* XXX assume X server wants pixman padding. Xft assumes this as well */

    XRenderAddGlyphs (display->display, glyphset_info->glyphset,
		      &glyph_index, &glyph_info, 1,
		      (char *) data,
		      glyph_surface->stride * glyph_surface->height);

    if (data != glyph_surface->data)
	free (data);

    _cairo_xlib_scaled_glyph_set_glyphset_info (scaled_glyph, glyphset_info);

 BAIL:
    if (glyph_surface != scaled_glyph->surface)
	cairo_surface_destroy (&glyph_surface->base);

    /* if the scaled glyph didn't already have a surface attached
     * to it, release the created surface now that we have it
     * uploaded to the X server.  If the surface has already been
     * there (eg. because image backend requested it), leave it in
     * the cache
     */
    if (!already_had_glyph_surface)
	_cairo_scaled_glyph_set_surface (scaled_glyph, scaled_font, NULL);

    return status;
}
