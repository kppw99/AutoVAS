static int
CVE_2013_4928_VULN_dissect_headers(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo,
        gint profile, gboolean is_obex_over_l2cap)
{
    proto_tree *hdrs_tree   = NULL;
    proto_tree *hdr_tree    = NULL;
    proto_item *hdr         = NULL;
    proto_item *handle_item;
    gint        item_length = -1;
    gint        parameters_length;
    guint8      hdr_id, i;

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_item *hdrs;
        hdrs      = proto_tree_add_text(tree, tvb, offset, item_length, "Headers");
        hdrs_tree = proto_item_add_subtree(hdrs, ett_btobex_hdrs);
    }
    else {
        return offset;
    }

    while (tvb_length_remaining(tvb, offset) > 0) {
        hdr_id = tvb_get_guint8(tvb, offset);

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                item_length = tvb_get_ntohs(tvb, offset+1);
                break;
            case 0x40:  /* byte sequence */
                item_length = tvb_get_ntohs(tvb, offset+1);
                break;
            case 0x80:  /* 1 byte */
                item_length = 2;
                break;
            case 0xc0:  /* 4 bytes */
                item_length = 5;
                break;
        }

        hdr = proto_tree_add_text(hdrs_tree, tvb, offset, item_length, "%s",
                                  val_to_str_ext_const(hdr_id, &header_id_vals_ext, "Unknown"));
        hdr_tree = proto_item_add_subtree(hdr, ett_btobex_hdr);

        proto_tree_add_item(hdr_tree, hf_hdr_id, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset++;

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                {
                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    if (item_length > 3) {
                        char *str;

                        display_unicode_string(tvb, hdr_tree, offset, &str);
                        proto_item_append_text(hdr_tree, " (\"%s\")", str);

                        col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", str);
                    }
                    else {
                        col_append_str(pinfo->cinfo, COL_INFO, " \"\"");
                    }

                    offset += item_length - 3;
                }
                break;
            case 0x40:  /* byte sequence */
                if (hdr_id == 0x4C) { /* Application Parameters */

                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    parameters_length = tvb_get_ntohs(tvb, offset) - 3;
                    offset += 2;

                    switch (profile) {
                        case PROFILE_BPP:
                            offset = dissect_bpp_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_BIP:
                            offset = dissect_bip_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_PBAP:
                            offset = dissect_pbap_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_MAP:
                            offset = dissect_map_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        default:
                            offset = dissect_raw_application_parameters(tvb, hdr_tree, offset, parameters_length);
                            break;
                    }
                    break;
                }

                proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                handle_item = proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, item_length - 3, ENC_NA);

                if (((hdr_id == 0x46) || (hdr_id == 0x4a)) && (item_length == 19)) { /* target or who */
                    for(i=0; target_vals[i].strptr != NULL; i++) {
                        if (tvb_memeql(tvb, offset, target_vals[i].value, target_vals[i].length) == 0) {
                            proto_item_append_text(handle_item, ": %s", target_vals[i].strptr);
                            proto_item_append_text(hdr_tree, " (%s)", target_vals[i].strptr);

                            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", target_vals[i].strptr);
                            if (!pinfo->fd->flags.visited) {
                                obex_profile_data_t  *obex_profile_data;
                                guint32               interface_id;
                                guint32               adapter_id;
                                guint32               chandle;
                                guint32               channel;
                                emem_tree_key_t       key[6];
                                guint32               k_interface_id;
                                guint32               k_adapter_id;
                                guint32               k_frame_number;
                                guint32               k_chandle;
                                guint32               k_channel;

                                if (is_obex_over_l2cap) {
                                    btl2cap_data_t      *l2cap_data;

                                    l2cap_data   = (btl2cap_data_t *)pinfo->private_data;
                                    interface_id = l2cap_data->interface_id;
                                    adapter_id   = l2cap_data->adapter_id;
                                    chandle      = l2cap_data->chandle;
                                    channel      = l2cap_data->cid;
                                } else {
                                    btrfcomm_data_t      *rfcomm_data;

                                    rfcomm_data  = (btrfcomm_data_t *)pinfo->private_data;
                                    interface_id = rfcomm_data->interface_id;
                                    adapter_id   = rfcomm_data->adapter_id;
                                    chandle      = rfcomm_data->chandle;
                                    channel      = rfcomm_data->dlci >> 1;
                                }

                                k_interface_id = interface_id;
                                k_adapter_id   = adapter_id;
                                k_chandle      = chandle;
                                k_channel      = channel;
                                k_frame_number = pinfo->fd->num;

                                key[0].length = 1;
                                key[0].key = &k_interface_id;
                                key[1].length = 1;
                                key[1].key = &k_adapter_id;
                                key[2].length = 1;
                                key[2].key = &k_chandle;
                                key[3].length = 1;
                                key[3].key = &k_channel;
                                key[4].length = 1;
                                key[4].key = &k_frame_number;
                                key[5].length = 0;
                                key[5].key = NULL;

                                obex_profile_data = wmem_new(wmem_file_scope(), obex_profile_data_t);
                                obex_profile_data->interface_id = interface_id;
                                obex_profile_data->adapter_id = adapter_id;
                                obex_profile_data->chandle = chandle;
                                obex_profile_data->channel = channel;
                                obex_profile_data->profile = target_to_profile[i];

                                se_tree_insert32_array(obex_profile, key, obex_profile_data);
                            }
                        }
                    }
                }

                if (!tvb_strneql(tvb, offset, "<?xml", 5))
                {
                    tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);

                    call_dissector(xml_handle, next_tvb, pinfo, tree);
                }
                else if (is_ascii_str(tvb_get_ptr(tvb, offset,item_length - 3), item_length - 3))
                {
                    proto_item_append_text(hdr_tree, " (\"%s\")", tvb_get_ephemeral_string(tvb, offset,item_length - 3));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", tvb_get_ephemeral_string(tvb, offset,item_length - 3));
                }

                offset += item_length - 3;
                break;
            case 0x80:  /* 1 byte */
                proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
                proto_tree_add_item(hdr_tree, hf_hdr_val_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                break;
            case 0xc0:  /* 4 bytes */
                proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
                proto_tree_add_item(hdr_tree, hf_hdr_val_long, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            default:
                break;
        }
    }

    return offset;
}
