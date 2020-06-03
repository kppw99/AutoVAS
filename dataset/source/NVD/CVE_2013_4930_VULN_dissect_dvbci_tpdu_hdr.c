static gint
CVE_2013_4930_VULN_dissect_dvbci_tpdu_hdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 direction, guint8 lpdu_tcid, guint32 tpdu_len,
        guint8 *hdr_tag, guint32 *body_len)
{
    guint8       c_tpdu_tag, r_tpdu_tag, *tag = NULL;
    const gchar *c_tpdu_str, *r_tpdu_str;
    proto_item  *pi;
    gint         offset;
    guint32      len_field;
    guint8       t_c_id;

    if (direction==DATA_HOST_TO_CAM) {
        c_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &c_tpdu_tag;
        c_tpdu_str = try_val_to_str(c_tpdu_tag, dvbci_c_tpdu);
        if (c_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", c_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_c_tpdu_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        else {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Invalid Command-TPDU tag");
            pi = proto_tree_add_text(
                    tree, tvb, 0, 1, "Invalid Command-TPDU tag");
            expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                    "see DVB-CI specification, table A.16 for valid values");
            return -1;
        }
    }
    else {
        r_tpdu_tag = tvb_get_guint8(tvb, 0);
        tag = &r_tpdu_tag;
        r_tpdu_str = try_val_to_str(r_tpdu_tag, dvbci_r_tpdu);
        if (r_tpdu_str) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", r_tpdu_str);
            proto_tree_add_item(tree, hf_dvbci_r_tpdu_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
        else {
            if (r_tpdu_tag == T_SB) {
                /* we have an r_tpdu without header and body,
                   it contains only the status part */
                if (hdr_tag)
                    *hdr_tag = NO_TAG;
                if (body_len)
                    *body_len = 0;
                return 0;
            }
            else {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                        "Invalid Response-TPDU tag");
                pi = proto_tree_add_text(
                        tree, tvb, 0, 1, "Invalid Response-TPDU tag");
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                   "see DVB-CI specification, table A.16 for valid values");
                return -1;
            }
        }
    }

    offset = dissect_ber_length(pinfo, tree, tvb, 1, &len_field, NULL);
    if (((direction==DATA_HOST_TO_CAM) && ((offset+len_field)!=tpdu_len)) ||
        ((direction==DATA_CAM_TO_HOST) && ((offset+len_field)>tpdu_len))) {
        /* offset points to 1st byte after the length field */
        pi = proto_tree_add_text(
                tree, tvb, 1, offset-1, "Length field mismatch");
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR,
                "Length field mismatch");
        return -1;
    }

    t_c_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dvbci_t_c_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* tcid in transport header and link layer must only match for
     * data transmission commands */
    if (t_c_id!=lpdu_tcid) {
        if (tag && (*tag==T_RCV || *tag==T_DATA_MORE || *tag==T_DATA_LAST)) {
            pi = proto_tree_add_text(tree, tvb, offset, 1,
                    "Transport Connection ID mismatch");
            expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN,
               "tcid is %d in the transport layer and %d in the link layer",
                    t_c_id, lpdu_tcid);
        }
    }
    else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "tcid %d", t_c_id);
    }
    offset++;

    if (hdr_tag && tag)
        *hdr_tag = *tag;
    if (body_len)
        *body_len = len_field-1;  /* -1 for t_c_id */
    return offset;
}
