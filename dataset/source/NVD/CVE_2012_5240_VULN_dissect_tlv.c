static int
CVE_2012_5240_VULN_dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    guint16 type, typebak;
    int length;

    length=tvb_reported_length_remaining(tvb, offset);
    rem=MIN(rem, length);

    if( rem < 4 ) {/*chk for minimum header*/
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, rem,
                                "Error processing TLV: length is %d, should be >= 4",
                                rem);
        }
        return rem;
    }
    type = tvb_get_ntohs(tvb, offset) & 0x3FFF;

    length = tvb_get_ntohs(tvb, offset + 2);
    rem -= 4; /*do not count header*/
    length = MIN(length, rem);  /* Don't go haywire if a problem ... */

    if (tree) {
        proto_tree *ti = NULL, *tlv_tree;
        /*chk for vendor-private*/
        if(type>=TLV_VENDOR_PRIVATE_START && type<=TLV_VENDOR_PRIVATE_END){
            typebak=type;               /*keep type*/
            type=TLV_VENDOR_PRIVATE_START;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Vendor Private TLV");
            /*chk for experimental*/
        } else if(type>=TLV_EXPERIMENTAL_START && type<=TLV_EXPERIMENTAL_END){
            typebak=type;               /*keep type*/
            type=TLV_EXPERIMENTAL_START;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Experimental TLV");
        } else {
            typebak=0;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                                     val_to_str(type, tlv_type_names, "Unknown TLV type (0x%04X)"));
        }

        tlv_tree = proto_item_add_subtree(ti, ett_ldp_tlv);

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (type) {
        case TLV_VENDOR_PRIVATE_START:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "TLV Type: Vendor Private (0x%X)", typebak);
            break;
        case TLV_EXPERIMENTAL_START:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "TLV Type: Experimental (0x%X)", typebak);
            break;
        default:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       type, "TLV Type: %s (0x%X)", val_to_str(type, tlv_type_names, "Unknown TLV type"), type );
        }

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (type) {

        case TLV_FEC:
            dissect_tlv_fec(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ADDRESS_LIST:
            dissect_tlv_address_list(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_HOP_COUNT:
            if( length != 1 ) /*error, only one byte*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4,length,
                                    "Error processing Hop Count TLV: length is %d, should be 1",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_hc_value, tvb,offset + 4, length, ENC_BIG_ENDIAN);
            break;

        case TLV_PATH_VECTOR:
            dissect_tlv_path_vector(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_GENERIC_LABEL:
            if( length != 4 ) /*error, need only label*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Generic Label TLV: length is %d, should be 4",
                                    length);
            else {
                guint32 label=tvb_get_ntohl(tvb, offset+4) & 0x000FFFFF;

                proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_generic_label,
                                           tvb, offset+4, length, label, "Generic Label: %u", label);
            }
            break;

        case TLV_ATM_LABEL:
            dissect_tlv_atm_label(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_LABEL:
            dissect_tlv_frame_label(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_PROTECTION:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT Protection TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_protect_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_STATUS:
            dissect_tlv_status(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_EXTENDED_STATUS:
            if( length != 4 ) /*error, need only status_code(guint32)*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Extended Status TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_extstatus_data, tvb, offset + 4, length, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_RETURNED_PDU:
            dissect_tlv_returned_pdu(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_RETURNED_MESSAGE:
            dissect_tlv_returned_message(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_HELLO_PARMS:
#if 0
            dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree, length);
#else
            dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree);
#endif
            break;

        case TLV_IPV4_TRANSPORT_ADDRESS:
            if( length != 4 ) /*error, need only ipv4*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing IPv4 Transport Address TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv4_taddr, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_CONFIGURATION_SEQNO:
            if( length != 4 ) /*error, need only seq_num(guint32)*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Configuration Sequence Number TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_config_seqno, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_IPV6_TRANSPORT_ADDRESS:
            if( length != 16 ) /*error, need only ipv6*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing IPv6 Transport Address TLV: length is %d, should be 16",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv6_taddr, tvb, offset + 4, 16, ENC_NA);
            }
            break;

        case TLV_MAC: /* draft-lasserre-vkompella-ppvpn-vpls-02.txt */
            dissect_tlv_mac(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_SESSION_PARMS:
            dissect_tlv_common_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ATM_SESSION_PARMS:
            dissect_tlv_atm_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_RELAY_SESSION_PARMS:
            dissect_tlv_frame_relay_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_SESSION:
            /* Used in RFC3478 LDP Graceful Restart */
            dissect_tlv_ft_session(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_ACK:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT ACK TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_ack_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_FT_CORK:
            if( length != 0 ) /* Length must be 0 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT Cork TLV: length is %d, should be 0",
                                    length);
            break;

        case TLV_LABEL_REQUEST_MESSAGE_ID:
            if( length != 4 ) /*error, need only one msgid*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Label Request Message ID TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_lbl_req_msg_id, tvb,offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_LSPID:
            dissect_tlv_lspid(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER:
            dissect_tlv_er(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_IPV4:
            dissect_tlv_er_hop_ipv4(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_IPV6:
            dissect_tlv_er_hop_ipv6(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_ER_HOP_AS:
            dissect_tlv_er_hop_as(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_LSPID:
            dissect_tlv_er_hop_lspid(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_TRAFFIC_PARAM:
            dissect_tlv_traffic(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_PREEMPTION:
            dissect_tlv_preemption(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_RESOURCE_CLASS:
            dissect_tlv_resource_class(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_ROUTE_PINNING:
            dissect_tlv_route_pinning(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_DIFFSERV:
            dissect_tlv_diffserv(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_VENDOR_PRIVATE_START:
            if( length < 4 ) /*error, at least Vendor ID*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Vendor Private Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_vendor_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
            }
            break;

        case TLV_EXPERIMENTAL_START:
            if( length < 4 ) /*error, at least Experiment ID*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Experimental Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_experiment_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
            }
            break;

        case TLV_PW_STATUS:
        {
            /* Ref: RFC 4447  and 4446*/
            dissect_tlv_pw_status(tvb, offset +4, tlv_tree, length);
            break;
        }
        case TLV_PW_INTERFACE_PARAMETERS:
        {
            /* Ref: RFC 4447 */
            static int *interface_params_header_fields[] = {
                &hf_ldp_tlv_intparam_length ,
                &hf_ldp_tlv_intparam_mtu ,
                &hf_ldp_tlv_intparam_tdmbps ,
                &hf_ldp_tlv_intparam_id ,
                &hf_ldp_tlv_intparam_maxcatmcells ,
                &hf_ldp_tlv_intparam_desc ,
                &hf_ldp_tlv_intparam_cepbytes ,
                &hf_ldp_tlv_intparam_cepopt_ais ,
                &hf_ldp_tlv_intparam_cepopt_une ,
                &hf_ldp_tlv_intparam_cepopt_rtp ,
                &hf_ldp_tlv_intparam_cepopt_ebm ,
                &hf_ldp_tlv_intparam_cepopt_mah ,
                &hf_ldp_tlv_intparam_cepopt_res ,
                &hf_ldp_tlv_intparam_cepopt_ceptype ,
                &hf_ldp_tlv_intparam_cepopt_t3 ,
                &hf_ldp_tlv_intparam_cepopt_e3 ,
                &hf_ldp_tlv_intparam_vlanid ,
                &hf_ldp_tlv_intparam_dlcilen ,
                &hf_ldp_tlv_intparam_fcslen ,
                &hf_ldp_tlv_intparam_tdmopt_r ,
                &hf_ldp_tlv_intparam_tdmopt_d ,
                &hf_ldp_tlv_intparam_tdmopt_f ,
                &hf_ldp_tlv_intparam_tdmopt_res1 ,
                &hf_ldp_tlv_intparam_tdmopt_pt ,
                &hf_ldp_tlv_intparam_tdmopt_res2 ,
                &hf_ldp_tlv_intparam_tdmopt_freq ,
                &hf_ldp_tlv_intparam_tdmopt_ssrc ,
                &hf_ldp_tlv_intparam_vccv_cctype_cw ,
                &hf_ldp_tlv_intparam_vccv_cctype_mplsra ,
                &hf_ldp_tlv_intparam_vccv_cctype_ttl1 ,
                &hf_ldp_tlv_intparam_vccv_cvtype_icmpping ,
                &hf_ldp_tlv_intparam_vccv_cvtype_lspping ,
                &hf_ldp_tlv_intparam_vccv_cvtype_bfd
            };
            int vc_len = length;
            offset += 4;
            while ( (vc_len > 1) && (rem > 1) ) {       /* enough to include id and length */
                int intparam_len = tvb_get_guint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_text(tlv_tree, tvb, offset +1, 1, "Malformed interface parameter");
                    break;
                }

                if ( (vc_len -intparam_len) <0 && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_text(tlv_tree, tvb, offset +2, MIN(vc_len,rem), "Malformed data");
                    break;
                }
                dissect_subtlv_interface_parameters(tvb, offset, tlv_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                vc_len -= intparam_len;
                offset += intparam_len;
            }
            break;
        }
        case TLV_PW_GROUPING:
        {
            /* Ref: RFC 4447 */
            dissect_tlv_pw_grouping(tvb, offset +4, tlv_tree, length);
            break;
        }
        default:
            proto_tree_add_item(tlv_tree, hf_ldp_tlv_value, tvb, offset + 4, length, ENC_NA);
            break;
        }
    }

    return length + 4;  /* Length of the value field + header */
}
