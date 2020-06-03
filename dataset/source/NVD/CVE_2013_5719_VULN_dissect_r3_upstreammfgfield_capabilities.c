static void
CVE_2013_5719_VULN_dissect_r3_upstreammfgfield_capabilities (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *cf_item;
  proto_tree *cf_tree;
  gint        len;
  guint       items;
  guint       octets;
  gint        i;

  DISSECTOR_ASSERT(start_offset == 0);

  len = MAX(0, tvb_length_remaining (tvb, 0));

  items = 0;
  i     = 0;

  while (i < len)
  {
    items++;
    octets = tvb_get_guint8 (tvb, i);
    if (!octets)
    {
      cf_item = proto_tree_add_text (tree, tvb, 0, len, "Capabilities (unknown items)");
      expert_add_info_format(pinfo, cf_item, PI_MALFORMED, PI_WARN,
                             "Capabilities could not be decoded because length of 0 encountered");
      return;
    }
    i += octets;
  }

  if (!tree)
    return;

  cf_item = proto_tree_add_text (tree, tvb, 0, len, "Capabilities (%u items)", items);
  cf_tree = proto_item_add_subtree (cf_item, ett_r3capabilities);

  for (i = 0; i < len; i += tvb_get_guint8 (tvb, i))
  {
    proto_item  *tmp_item = proto_tree_add_item (cf_tree, hf_r3_capabilities, tvb, i, tvb_get_guint8 (tvb, i), ENC_NA);
    proto_tree  *tmp_tree = proto_item_add_subtree (tmp_item, ett_r3capabilities);
    const gchar *fn;

    fn = val_to_str_ext_const (tvb_get_guint8 (tvb, i + 1), &r3_capabilitiesnames_ext, "[Unknown Field Name]");

    proto_item_append_text (tmp_item, " (%s, %u)", fn, tvb_get_letohs (tvb, i + 2));
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_length, tvb, i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_type,   tvb, i + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (tmp_tree, hf_r3_capabilities_value,  tvb, i + 2, 2, ENC_LITTLE_ENDIAN);
  }
}
