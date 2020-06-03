static int
CVE_2013_1587_VULN_dissect_rohc_ir_packet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                       int offset, guint16 cid, gboolean is_add_cid, rohc_info *p_rohc_info)
{
    proto_item         *ir_item, *item;
    proto_tree         *ir_tree;
    int                 ir_item_start;
    int                 x_bit_offset;
    gboolean            d = FALSE;
    guint8              oct, profile, val_len;
    gint16              feedback_data_len = 0;
    tvbuff_t           *next_tvb;
    rohc_cid_context_t *rohc_cid_context = NULL;

    /* This function is potentially called from both dissect_rohc and dissect_pdcp_lte
     * The cid value must have been dissected and valid
     * offset must point to the IR octet  see below ( | 1   1   1   1   1   1   0 | D |  )
     * TODO: CRC validation
     */

     /*
      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
    |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
    | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
    /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
    |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
    |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
    |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
    |         Dynamic chain         |  present if D = 1, variable length
    |                               |
     - - - - - - - - - - - - - - - -
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

    */
    oct = tvb_get_guint8(tvb,offset);

    if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
        item = proto_tree_add_uint(tree, hf_rohc_small_cid, tvb, 0, 0, cid);
        PROTO_ITEM_SET_GENERATED(item);
    }
    ir_item = proto_tree_add_item(tree, hf_rohc_ir_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
    ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir);
    ir_item_start = offset;
    d = oct & 0x01;
    x_bit_offset = offset;
    offset++;
    if(p_rohc_info->large_cid_present == TRUE){
        /* Handle Large CID:s here */
        get_self_describing_var_len_val(tvb, ir_tree, offset, hf_rohc_large_cid, &val_len);
        offset = offset + val_len;
    }

    /* Read profile */
    profile = tvb_get_guint8(tvb,offset);

    if(profile==ROHC_PROFILE_RTP){
        proto_tree_add_item(ir_tree, hf_rohc_d_bit, tvb, x_bit_offset, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ir_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* See if we have an entry for this CID
     * Update it if we do otherwise create it
     * and fill in the info.
     */
    if (!pinfo->fd->flags.visited){
        gint key = cid;
        rohc_cid_context = (rohc_cid_context_t*)g_hash_table_lookup(rohc_cid_hash, GUINT_TO_POINTER(key));
        if (rohc_cid_context != NULL){
            /* This is not the first IR packet seen*/
            gint tmp_prev_ir_frame_number = rohc_cid_context->ir_frame_number;
            gint tmp_prev_rohc_ip_version = rohc_cid_context->rohc_ip_version;
            gint tmp_prev_mode = rohc_cid_context->mode;

            /*g_warning("IR pkt found CID %u",cid);*/

            rohc_cid_context = se_new(rohc_cid_context_t);
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = tmp_prev_ir_frame_number;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;
            rohc_cid_context->rohc_ip_version = tmp_prev_rohc_ip_version;
            rohc_cid_context->mode = tmp_prev_mode;

            g_hash_table_replace(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }else{
            rohc_cid_context = se_new(rohc_cid_context_t);
            /*rohc_cid_context->rohc_ip_version;*/
            /*rohc_cid_context->large_cid_present;*/
            /*rohc_cid_context->mode     mode;*/
            /*rohc_cid_context->d_mode;*/
            /*rohc_cid_context->rnd;*/
            /*rohc_cid_context->udp_checkum_present;*/
            rohc_cid_context->profile = profile;
            rohc_cid_context->prev_ir_frame_number = -1;
            rohc_cid_context->ir_frame_number = pinfo->fd->num;
            rohc_cid_context->rohc_ip_version = p_rohc_info->rohc_ip_version;
            rohc_cid_context->mode = p_rohc_info->mode;

            /*g_warning("IR pkt New CID %u",cid);*/

            g_hash_table_insert(rohc_cid_hash, GUINT_TO_POINTER(key), rohc_cid_context);
            p_add_proto_data(pinfo->fd, proto_rohc, rohc_cid_context);
        }
    }else{
        /* get the stored data */
        rohc_cid_context = (rohc_cid_context_t*)p_get_proto_data(pinfo->fd, proto_rohc);
    }

    switch(profile){
        case ROHC_PROFILE_UNCOMPRESSED:
            /*
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, cid, profile, rohc_cid_context);
            */
               next_tvb = tvb_new_subset_remaining(tvb, offset);
            if ( (oct&0xf0) == 0x60 ) {
                call_dissector(ipv6_handle, next_tvb, pinfo, tree);
            }
            else {
                call_dissector(ip_handle, next_tvb, pinfo, tree);
            }
            col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "ROHC <");
              col_append_str(pinfo->cinfo, COL_PROTOCOL, ">");
            break;
        case ROHC_PROFILE_RTP:
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, profile, rohc_cid_context);
            break;
        case ROHC_PROFILE_UDP:
            offset = dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, profile, rohc_cid_context);
            break;
        default:
            proto_tree_add_text(ir_tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
            offset = -1;
            break;
    }

    /* Set length of IR header */
    proto_item_set_len(ir_item, offset-ir_item_start);

    return offset;
}
