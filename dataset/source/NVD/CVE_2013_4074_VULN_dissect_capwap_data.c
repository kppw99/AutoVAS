static void
CVE_2013_4074_VULN_dissect_capwap_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *capwap_data_tree;
	guint offset = 0;
	tvbuff_t *next_tvb;
	guint8 type_header;
	guint8 payload_type;
	guint8 payload_wbid;
	gboolean fragment_is;
	gboolean fragment_more;
	guint32 fragment_id;
	guint32 fragment_offset;
	fragment_data *frag_msg = NULL;
	gboolean save_fragmented;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAPWAP");
	col_set_str(pinfo->cinfo, COL_INFO, "CAPWAP-Data");

	ti = proto_tree_add_item(tree, proto_capwap, tvb, 0, -1, ENC_NA);
	capwap_data_tree = proto_item_add_subtree(ti, ett_capwap);

	/* CAPWAP Preamble */
	offset += dissect_capwap_preamble(tvb, capwap_data_tree, offset, &type_header);

	if (type_header == 1) {
		next_tvb = tvb_new_subset_remaining (tvb, offset);
		call_dissector(dtls_handle, next_tvb, pinfo, tree);
		return;
	}

	/* CAPWAP Header */
	offset += dissect_capwap_header(tvb, capwap_data_tree, offset, pinfo, &payload_type, &payload_wbid, &fragment_is, &fragment_more, &fragment_id, &fragment_offset);

	/* CAPWAP Reassemble */
	save_fragmented = pinfo->fragmented;

	if (global_capwap_reassemble && fragment_is)
	{
		pinfo->fragmented = TRUE;

		frag_msg = fragment_add_check(tvb, offset, pinfo,fragment_id,
		                              capwap_fragment_table,
		                              capwap_reassembled_table,
		                              fragment_offset,
		                              tvb_length_remaining(tvb, offset),
		                              fragment_more);

		next_tvb = process_reassembled_data(tvb, offset, pinfo,
		                                    "Reassembled CAPWAP", frag_msg,
		                                    &capwap_frag_items, NULL, tree);

		if (next_tvb == NULL)
		{ /* make a new subset */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(data_handle,next_tvb, pinfo, tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment ID: %u, Fragment Offset: %u)", fragment_id, fragment_offset);
		}
		else
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Reassembled, Fragment ID: %u)", fragment_id);
		}
	}
	else
	{
		next_tvb = tvb_new_subset_remaining (tvb, offset);
	}

	/* CAPWAP Data Payload */
	if (payload_type == 0) {
		/* IEEE 802.3 Frame */
		call_dissector(ieee8023_handle, next_tvb, pinfo, tree);
	} else {
		switch (payload_wbid) {
		case 0: /* Reserved - Cisco seems to use this instead of 1 */
			/* It seems that just calling ieee80211_handle is not
			 * quite enough to get this right, so call data_handle
			 * for now:
			 */
			call_dissector(data_handle, next_tvb, pinfo, tree);
			break;
		case 1: /* IEEE 802.11 */
			call_dissector(global_capwap_swap_frame_control ? ieee80211_bsfc_handle : ieee80211_handle, next_tvb, pinfo, tree);
			break;
		default: /* Unknown Data */
			call_dissector(data_handle, next_tvb, pinfo, tree);
			break;
		}
	}
	pinfo->fragmented = save_fragmented;
}
