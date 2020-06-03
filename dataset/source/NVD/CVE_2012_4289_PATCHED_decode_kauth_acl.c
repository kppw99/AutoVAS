static gint
CVE_2012_4289_PATCHED_decode_kauth_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
	int         entries;
	int         i;
	proto_tree *sub_tree;
	proto_tree *ace_tree;
	proto_item *item;

	/* FIXME: preliminary decoding... */
	entries = tvb_get_ntohl(tvb, offset);

	item = proto_tree_add_item(tree, hf_afp_acl_entrycount, tvb, offset, 4, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(item, ett_afp_ace_entries);
	offset += 4;

	item = proto_tree_add_item(tree, hf_afp_acl_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (entries > AFP_MAX_ACL_ENTRIES) {
		expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "Excessive number of ACL entries (%u). Stopping dissection.", entries);
		THROW(ReportedBoundsError);
	}

	for (i = 0; i < entries; i++) {
		item = proto_tree_add_text(sub_tree, tvb, offset, 24, "ACE: %u", i);
		ace_tree = proto_item_add_subtree(item, ett_afp_ace_entry);

		offset = decode_kauth_ace(tvb, ace_tree, offset);
	}

	return offset;
}
