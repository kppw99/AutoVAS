static void
CVE_2013_4083_VULN_dissect_pft(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint16 plen;
  gint offset = 0;
  guint16 seq, payload_len;
  guint32 findex, fcount;
  proto_tree *pft_tree = NULL;
  proto_item *ti = NULL, *li = NULL;
  tvbuff_t *next_tvb = NULL;
  gboolean fec = FALSE;
  guint16 rsk=0, rsz=0;

  pinfo->current_proto = "DCP-PFT";
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCP-PFT");

  if (tree) {                   /* we are being asked for details */
    ti = proto_tree_add_item (tree, proto_pft, tvb, 0, -1, ENC_NA);
    pft_tree = proto_item_add_subtree (ti, ett_pft);
    proto_tree_add_item (pft_tree, hf_edcp_sync, tvb, offset, 2, ENC_ASCII|ENC_NA);
  }
  offset += 2;
  seq = tvb_get_ntohs (tvb, offset);
  if (tree) {
    proto_tree_add_item (pft_tree, hf_edcp_pseq, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;
  findex = tvb_get_ntoh24 (tvb, offset);
  if (tree) {
    proto_tree_add_item (pft_tree, hf_edcp_findex, tvb, offset, 3, ENC_BIG_ENDIAN);
  }
  offset += 3;
  fcount = tvb_get_ntoh24 (tvb, offset);
  if (tree) {
    proto_tree_add_item (pft_tree, hf_edcp_fcount, tvb, offset, 3, ENC_BIG_ENDIAN);
  }
  offset += 3;
  plen = tvb_get_ntohs (tvb, offset);
  payload_len = plen & 0x3fff;
  if (tree) {
    proto_tree_add_item (pft_tree, hf_edcp_fecflag, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (pft_tree, hf_edcp_addrflag, tvb, offset, 2, ENC_BIG_ENDIAN);
    li = proto_tree_add_item (pft_tree, hf_edcp_plen, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;
  if (plen & 0x8000) {
    fec = TRUE;
    rsk = tvb_get_guint8 (tvb, offset);
    if (tree)
          proto_tree_add_item (pft_tree, hf_edcp_rsk, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    rsz = tvb_get_guint8 (tvb, offset);
    if (tree)
          proto_tree_add_item (pft_tree, hf_edcp_rsz, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }
  if (plen & 0x4000) {
    if (tree)
      proto_tree_add_item (pft_tree, hf_edcp_source, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (tree)
          proto_tree_add_item (pft_tree, hf_edcp_dest, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }
  if (tree) {
    proto_item *ci = NULL;
    guint header_len = offset+2;
    const char *crc_buf = (const char *) tvb_get_ptr(tvb, 0, header_len);
    unsigned long c = crc_drm(crc_buf, header_len, 16, 0x11021, 1);
    ci = proto_tree_add_item (pft_tree, hf_edcp_hcrc, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(ci, " (%s)", (c==0xe2f0)?"Ok":"bad");
    proto_tree_add_boolean(pft_tree, hf_edcp_hcrc_ok, tvb, offset, 2, c==0xe2f0);
  }
  offset += 2;
  if (fcount > 1) {             /* fragmented*/
    gboolean save_fragmented = pinfo->fragmented;
    guint16 real_len = tvb_length(tvb)-offset;
    proto_tree_add_item (pft_tree, hf_edcp_pft_payload, tvb, offset, real_len, ENC_NA);
    if(real_len != payload_len || real_len == 0) {
      if(li)
        proto_item_append_text(li, " (length error (%d))", real_len);
    }
    if (real_len)
      next_tvb = dissect_pft_fragmented(tvb, pinfo, pft_tree, findex, fcount,
                                        seq, offset, real_len, fec, rsk, rsz);
    pinfo->fragmented = save_fragmented;
  } else {
    next_tvb = tvb_new_subset_remaining (tvb, offset);
  }
  if(next_tvb) {
    dissect_af(next_tvb, pinfo, tree);
  }
}
