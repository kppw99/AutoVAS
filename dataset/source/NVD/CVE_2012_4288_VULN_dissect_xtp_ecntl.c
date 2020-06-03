static void
CVE_2012_4288_VULN_dissect_xtp_ecntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *top_ti;
	proto_tree *xtp_subtree;
	struct xtp_ecntl ecntl[1];
	guint64	*spans, *p;
	guint32 spans_len;
	guint i;

	top_ti = proto_tree_add_text(tree, tvb, offset, len,
				"Error Control Segment");
	xtp_subtree = proto_item_add_subtree(top_ti, ett_xtp_ecntl);

	if (len < MIN_XTP_ECNTL_PKT_LEN) {
		proto_item_append_text(top_ti,
				", bogus length (%u, must be at least %u)",
				len, MIN_XTP_ECNTL_PKT_LEN);
		return;
	}

	/** parse **/
	/* rseq(8) */
	ecntl->rseq = tvb_get_ntohl(tvb, offset);
	ecntl->rseq <<= 32;
	ecntl->rseq += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* alloc(8) */
	ecntl->alloc = tvb_get_ntohl(tvb, offset);
	ecntl->alloc <<= 32;
	ecntl->alloc += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* echo(4) */
	ecntl->echo = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* nspan(4) */
	ecntl->nspan = tvb_get_ntohl(tvb, offset);
	offset += 4;
	len = len + XTP_HEADER_LEN - offset;
	spans_len = 16 * ecntl->nspan;
	if (len != spans_len) {
		proto_item_append_text(top_ti,
				", bogus spans field length (%u, must be %u)",
				len, spans_len);
		return;
	}
	/* spans(16n) */
	spans = ep_alloc0(spans_len);
	p = spans;
	for (i = 0; i < ecntl->nspan*2; i++) {
		guint64 span = tvb_get_ntohl(tvb, offset);
		span <<= 32;
		span += tvb_get_ntohl(tvb, offset+4);
		*p++ = span;
		offset += 8;
	}

	/** add summary **/
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Recv-Seq=%" G_GINT64_MODIFIER "u", ecntl->rseq);
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Alloc=%" G_GINT64_MODIFIER "u", ecntl->alloc);
	}
	proto_item_append_text(top_ti,
				", Recv-Seq: %" G_GINT64_MODIFIER "u", ecntl->rseq);

	/** display **/
	offset = start;
	/* rseq(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_rseq,
				tvb, offset, 8, ecntl->rseq);
	offset += 8;
	/* alloc(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_alloc,
				tvb, offset, 8, ecntl->alloc);
	offset += 8;
	/* echo(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_ecntl_echo,
				tvb, offset, 4, ecntl->echo);
	offset += 4;
	/* nspan(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_ecntl_nspan,
				tvb, offset, 4, ecntl->nspan);
	offset += 4;
	/* spans(16n) */
	p = spans;
	for (i = 0; i < ecntl->nspan; i++) {
		proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_span_left,
				tvb, offset, 8, *p);
		p++;
		offset += 8;
		proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_span_right,
				tvb, offset, 8, *p);
		p++;
		offset += 8;
	}

	return;
}
