static int
CVE_2013_1583_VULN_dissect_version_4_primary_header(packet_info *pinfo, proto_tree *primary_tree, tvbuff_t *tvb)
{
    guint8        cosflags;
    const guint8 *dict_ptr;
    int           bundle_header_length;
    int           bundle_header_dict_length;
    int           offset;     /*Total offset into frame (frame_offset + convergence layer size)*/
    int           sdnv_length;
    int           dest_scheme_offset, dest_ssp_offset, source_scheme_offset, source_ssp_offset;
    int           report_scheme_offset, report_ssp_offset, cust_scheme_offset, cust_ssp_offset;
    int           fragment_offset, total_adu_length;
    int           dst_scheme_pos, src_scheme_pos, rpt_scheme_pos, cust_scheme_pos;
    int           dst_scheme_len, src_scheme_len, rpt_scheme_len, cust_scheme_len;
    int           dst_ssp_len, src_ssp_len, rpt_ssp_len, cust_ssp_len;
    const gchar  *src_node;
    const gchar  *dst_node;

    guint8        srrflags;
    proto_item   *srr_flag_item;
    proto_tree   *srr_flag_tree;

    proto_item   *proc_flag_item;
    proto_tree   *proc_flag_tree;
    proto_item   *cos_flag_item;
    proto_tree   *cos_flag_tree;
    proto_item   *dict_item;
    proto_tree   *dict_tree;

    offset = 1;         /* Version Number already displayed*/

    /* Primary Header Processing Flags */
    pri_hdr_procflags = tvb_get_guint8(tvb, offset);
    proc_flag_item = proto_tree_add_item(primary_tree, hf_bundle_procflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    proc_flag_tree = proto_item_add_subtree(proc_flag_item, ett_proc_flags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_fragment,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_admin,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_dont_fragment,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_cust_xfer_req,
                                                tvb, offset, 1, pri_hdr_procflags);
    proto_tree_add_boolean(proc_flag_tree, hf_bundle_procflags_dest_singleton,
                                                tvb, offset, 1, pri_hdr_procflags);

    /* Primary Header COS Flags */
    ++offset;
    cosflags = tvb_get_guint8(tvb, offset);
    cos_flag_item = proto_tree_add_item(primary_tree, hf_bundle_cosflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    cos_flag_tree = proto_item_add_subtree(cos_flag_item, ett_cos_flags);
    proto_tree_add_uint(cos_flag_tree, hf_bundle_cosflags_priority,
                                                tvb, offset, 1, cosflags);
    /* Status Report Request Flags */
    ++offset;
    srrflags = tvb_get_guint8(tvb, offset);
    srr_flag_item = proto_tree_add_item(primary_tree, hf_bundle_srrflags, tvb,
                                                offset, 1, ENC_BIG_ENDIAN);
    srr_flag_tree = proto_item_add_subtree(srr_flag_item, ett_srr_flags);

    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_receipt,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_cust_accept,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_forward,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_delivery,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_deletion,
                                                tvb, offset, 1, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_ack,
                                                tvb, offset, 1, srrflags);
    ++offset;

    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length, "Bundle Header Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Bundle Header Length: %d", bundle_header_length);

    tvb_ensure_bytes_exist(tvb, offset + sdnv_length, bundle_header_length);
    offset += sdnv_length;

    /*
     * Pick up offsets into dictionary (8 of them)
     */

    dest_scheme_offset = tvb_get_ntohs(tvb, offset);
    dst_scheme_pos = offset;
    dst_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dest_ssp_offset = tvb_get_ntohs(tvb, offset);
    dst_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_dest_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    source_scheme_offset = tvb_get_ntohs(tvb, offset);
    src_scheme_pos = offset;
    src_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    source_ssp_offset = tvb_get_ntohs(tvb, offset);
    src_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_source_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    report_scheme_offset = tvb_get_ntohs(tvb, offset);
    rpt_scheme_pos = offset;
    rpt_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    report_ssp_offset = tvb_get_ntohs(tvb, offset);
    rpt_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_report_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    cust_scheme_offset = tvb_get_ntohs(tvb, offset);
    cust_scheme_pos = offset;
    cust_scheme_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_scheme_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    cust_ssp_offset = tvb_get_ntohs(tvb, offset);
    cust_ssp_len = 2;
    proto_tree_add_item(primary_tree, hf_bundle_cust_ssp_offset,
                                                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(primary_tree, hf_bundle_creation_timestamp,
                                                        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(primary_tree, hf_bundle_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_dict_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length, "Dictionary Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Dictionary Length: %d", bundle_header_dict_length);
    offset += sdnv_length;

    /*
     * Pull out stuff from the dictionary
     */

    tvb_ensure_bytes_exist(tvb, offset, bundle_header_dict_length);

    dict_item = proto_tree_add_text(primary_tree, tvb, offset, bundle_header_dict_length, "Dictionary");
    dict_tree = proto_item_add_subtree(dict_item, ett_dictionary);

    /*
     * If the dictionary length is 0, then the CBHE block compression method is applied. (RFC6260)
     * So the scheme offset is the node number and the ssp offset is the service number.
     * If destination scheme offset is 2 and destination ssp offset is 1, then the EID is
     * ipn:2.1
     */
    if(bundle_header_dict_length == 0)
    {
        /*
         * Destination info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                0, "Destination Scheme: %s",IPN_SCHEME_STR);
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, dst_scheme_pos,
                                dst_scheme_len + dst_ssp_len, "Destination: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, dst_scheme_pos,
                                dst_scheme_len + dst_ssp_len,
                                "Destination: %d.%d",dest_scheme_offset,dest_ssp_offset);
        }

        /*
         * Source info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Source Scheme: %s",IPN_SCHEME_STR);
        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, src_scheme_pos,
                                src_scheme_len + src_ssp_len, "Source: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, src_scheme_pos,
                                src_scheme_len + src_ssp_len,
                                "Source: %d.%d",source_scheme_offset,source_ssp_offset);
        }

        /*
         * Report to info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Report Scheme: %s",IPN_SCHEME_STR);
        if(report_scheme_offset == 0 && report_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, rpt_scheme_pos,
                                rpt_scheme_len + rpt_ssp_len, "Report: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, rpt_scheme_pos,
                                rpt_scheme_len + rpt_ssp_len,
                                "Report: %d.%d",report_scheme_offset,report_ssp_offset);
        }

        /*
         * Custodian info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Custodian Scheme: %s",IPN_SCHEME_STR);
        if(cust_scheme_offset == 0 && cust_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len, "Custodian: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len,
                                "Custodian: %d.%d",cust_scheme_offset,cust_ssp_offset);
        }

        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                src_node = "Null";
        }
        else
        {
                src_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, source_scheme_offset, source_ssp_offset);
        }
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                dst_node = "Null";
        }
        else
        {
                dst_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, dest_scheme_offset, dest_ssp_offset);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s", src_node,dst_node);
        /* remember custodian, for use in checking cteb validity */
        bundle_custodian = ep_strdup_printf("%s:%d.%d", IPN_SCHEME_STR, cust_scheme_offset, cust_ssp_offset);
    }

    /*
     * This pointer can be made to address outside the packet boundaries so we
     * need to check for improperly formatted strings (no null termination).
     */

    else
    {
        /*
         * Destination info
         */

        proto_tree_add_item(dict_tree, hf_bundle_dest_scheme, tvb, offset + dest_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_dest_ssp, tvb, offset + dest_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Source info
         */

        proto_tree_add_item(dict_tree, hf_bundle_source_scheme, tvb, offset + source_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_source_ssp, tvb, offset + source_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Report to info
         */

        proto_tree_add_item(dict_tree, hf_bundle_report_scheme, tvb, offset + report_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_report_ssp, tvb, offset + report_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Custodian info
         */

        proto_tree_add_item(dict_tree, hf_bundle_custodian_scheme, tvb, offset + cust_scheme_offset, -1, ENC_ASCII|ENC_NA);
        proto_tree_add_item(dict_tree, hf_bundle_custodian_ssp, tvb, offset + cust_ssp_offset, -1, ENC_ASCII|ENC_NA);

        /*
         * Add Source/Destination to INFO Field
         */

        /* Note: If we get this far, the offsets (and the strings) are at least within the TVB */
        dict_ptr = tvb_get_ptr(tvb, offset, bundle_header_dict_length);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s:%s > %s:%s",
                     dict_ptr + source_scheme_offset, dict_ptr + source_ssp_offset,
                     dict_ptr + dest_scheme_offset, dict_ptr + dest_ssp_offset);
        /* remember custodian, for use in checking cteb validity */
        bundle_custodian = ep_strdup_printf("%s:%s", dict_ptr + cust_scheme_offset, dict_ptr + cust_ssp_offset);
    }
    offset += bundle_header_dict_length;        /*Skip over dictionary*/

    /*
     * Do this only if Fragment Flag is set
     */

    if(pri_hdr_procflags & BUNDLE_PROCFLAGS_FRAG_MASK) {
        fragment_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(fragment_offset < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                        "Fragment Offset: %d", fragment_offset);
        offset += sdnv_length;

        total_adu_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(total_adu_length < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Total Application Data Unit Length: %d", fragment_offset);
        offset += sdnv_length;
    }
    return (offset);
}
