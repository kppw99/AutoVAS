static int
CVE_2012_6058_VULN_dissect_icmpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree         *icmp6_tree = NULL, *flag_tree = NULL;
    proto_item         *ti         = NULL, *hidden_item, *checksum_item = NULL, *code_item = NULL, *ti_flag = NULL;
    const char         *code_name  = NULL;
    guint               length     = 0, reported_length;
    vec_t               cksum_vec[4];
    guint32             phdr[2];
    guint16             cksum, computed_cksum;
    int                 offset;
    tvbuff_t           *next_tvb;
    guint8              icmp6_type, icmp6_code;
    icmp_transaction_t *trans      = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 0;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_icmpv6, tvb, offset, -1, ENC_NA);
        icmp6_tree = proto_item_add_subtree(ti, ett_icmpv6);

        /* Type */
        proto_tree_add_item(icmp6_tree, hf_icmpv6_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    icmp6_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(icmp6_type, icmpv6_type_val, "Unknown (%d)"));

    if (tree)
        code_item = proto_tree_add_item(icmp6_tree, hf_icmpv6_code, tvb, offset, 1, ENC_BIG_ENDIAN);

    icmp6_code = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (icmp6_type) {
        case ICMP6_DST_UNREACH:
            code_name = val_to_str_const(icmp6_code, icmpv6_unreach_code_val, "Unknown");
            break;
        case ICMP6_TIME_EXCEEDED:
            code_name = val_to_str(icmp6_code, icmpv6_timeex_code_val, "Unknown (%d)");
            break;
        case ICMP6_PARAM_PROB:
            code_name = val_to_str(icmp6_code, icmpv6_paramprob_code_val, "Unknown (%d)");
            break;
        case ICMP6_ROUTER_RENUMBERING:
            code_name = val_to_str(icmp6_code, icmpv6_rr_code_val, "Unknown (%d)");
            break;
        case ICMP6_NI_QUERY:
            code_name = val_to_str(icmp6_code, ni_query_code_val, "Unknown (%d)");
            break;
        case ICMP6_NI_REPLY:
            code_name = val_to_str(icmp6_code, ni_reply_code_val, "Unknown (%d)");
            break;
        case ICMP6_RPL_CONTROL:
            code_name = val_to_str(icmp6_code, rpl_code_val, "Unknown (%d)");
            break;
    }

    if (code_name)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", code_name);

    /* RFC 4380
     * 2.7.   Teredo UDP Port
     * 5.2.9. Direct IPv6 Connectivity Test  */
    if (pinfo->destport == 3544 && icmp6_type == ICMP6_ECHO_REQUEST) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Teredo");
        col_set_str(pinfo->cinfo, COL_INFO, "Direct IPv6 Connectivity Test");
    }

    if (tree) {
        if (code_name)
            proto_item_append_text(code_item, " (%s)", code_name);
        checksum_item = proto_tree_add_item(icmp6_tree, hf_icmpv6_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    cksum = tvb_get_ntohs(tvb, offset);

    if (1) { /* There's an expert info in here so always execute */
        length = tvb_length(tvb);
        reported_length = tvb_reported_length(tvb);
        if (!pinfo->fragmented && length >= reported_length) {
            /* The packet isn't part of a fragmented datagram and isn't
               truncated, so we can checksum it. */

            /* Set up the fields of the pseudo-header. */
            cksum_vec[0].ptr = pinfo->src.data;
            cksum_vec[0].len = pinfo->src.len;
            cksum_vec[1].ptr = pinfo->dst.data;
            cksum_vec[1].len = pinfo->dst.len;
            cksum_vec[2].ptr = (const guint8 *)&phdr;
            phdr[0] = g_htonl(reported_length);
            phdr[1] = g_htonl(IP_PROTO_ICMPV6);
            cksum_vec[2].len = 8;
            cksum_vec[3].len = reported_length;
            cksum_vec[3].ptr = tvb_get_ptr(tvb, 0, cksum_vec[3].len);
            computed_cksum = in_cksum(cksum_vec, 4);

            if (computed_cksum == 0) {
                proto_item_append_text(checksum_item, " [correct]");
            } else {
                hidden_item = proto_tree_add_boolean(icmp6_tree, hf_icmpv6_checksum_bad, tvb, offset, 2, TRUE);

                PROTO_ITEM_SET_GENERATED(hidden_item);
                proto_item_append_text(checksum_item, " [incorrect, should be 0x%04x]", in_cksum_shouldbe(cksum, computed_cksum));
                expert_add_info_format(pinfo, checksum_item, PI_CHECKSUM, PI_WARN,
                                       "ICMPv6 Checksum Incorrect, should be 0x%04x", in_cksum_shouldbe(cksum, computed_cksum));
            }
        }
    }
    offset += 2;

    if (icmp6_type == ICMP6_ECHO_REQUEST || icmp6_type == ICMP6_ECHO_REPLY) {
        guint16 identifier, sequence;

        /* Identifier */
        if (tree)
            proto_tree_add_item(icmp6_tree, hf_icmpv6_echo_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        identifier = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* Sequence Number */
        if (tree)
            proto_tree_add_item(icmp6_tree, hf_icmpv6_echo_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        sequence = tvb_get_ntohs(tvb, offset);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " id=0x%04x, seq=%u", identifier, sequence);

        if (pinfo->destport == 3544 && icmp6_type == ICMP6_ECHO_REQUEST) {
            /* RFC 4380
             * 2.7.   Teredo UDP Port
             * 5.2.9. Direct IPv6 Connectivity Test
             *
             * TODO: Clarify the nonce:  The RFC states, "(It is recommended to
             * use a random number [the nonce] at least 64 bits long.)"
             *
             * Shouldn't the nonce be at least 8 then?  Why not just use (-1),
             * as it could really be any length, couldn't it?
             */
            if (tree)
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
        } else {
            if (!pinfo->flags.in_error_pkt) {
                guint32 conv_key[2];

                conv_key[1] = (guint32)((identifier << 16) | sequence);

                if (icmp6_type == ICMP6_ECHO_REQUEST) {
                    conv_key[0] = (guint32)cksum;
                    if (pinfo->flags.in_gre_pkt)
                        conv_key[0] |= 0x00010000; /* set a bit for "in GRE" */
                    trans = transaction_start(pinfo, icmp6_tree, conv_key);
                } else { /* ICMP6_ECHO_REPLY */
                    guint16 tmp[2];

                    tmp[0] = ~cksum;
                    tmp[1] = ~0x0100; /* The difference between echo request & reply */
                    cksum_vec[0].len = sizeof(tmp);
                    cksum_vec[0].ptr = (guint8 *)tmp;
                    conv_key[0] = in_cksum(cksum_vec, 1);
                    if (conv_key[0] == 0)
                        conv_key[0] = 0xffff;
                    if (pinfo->flags.in_gre_pkt)
                        conv_key[0] |= 0x00010000; /* set a bit for "in GRE" */
                    trans = transaction_end(pinfo, icmp6_tree, conv_key);
                }
            }
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            offset += call_dissector(data_handle, next_tvb, pinfo, icmp6_tree);
        }
    }

    if (1) { /* There are expert infos buried in here so always execute */
        /* decode... */
        /* FIXME: The following messages MUST have a TTL^WHop-Limit of 255:
                133-137, 141-142, 148-149. Detect this and add expert items. */
        switch (icmp6_type) {
            case ICMP6_DST_UNREACH: /* Destination Unreachable (1) */
            case ICMP6_TIME_EXCEEDED: /* Time Exceeded (3) */
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_PACKET_TOO_BIG: /* Packet Too Big (2) */
                /* MTU */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mtu, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_PARAM_PROB: /* Parameter Problem (4) */
                /* MTU */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_pointer, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_ECHO_REQUEST:    /* Echo Request (128) */
            case ICMP6_ECHO_REPLY:      /* Echo Reply (129) */
                /* Already handled above */
                break;
            case ICMP6_MEMBERSHIP_QUERY: /* Multicast Listener Query (130) */
            case ICMP6_MEMBERSHIP_REPORT: /* Multicast Listener Report (131) */
            case ICMP6_MEMBERSHIP_REDUCTION: /* Multicast Listener Done (132) */
            {
                /* It is MLDv2 packet ? (the min length for a MLDv2 packet is 28) */
                if ((icmp6_type == ICMP6_MEMBERSHIP_QUERY) && (length >= MLDV2_PACKET_MINLEN)) {
                    guint32 mrc;
                    guint16 qqi, i, nb_sources;

                    /* Maximum Response Code */
                    mrc = tvb_get_ntohs(tvb, offset);
                    if (mrc >= 32768){
                        mrc = ((mrc & 0x0fff) | 0x1000) << (((mrc & 0x7000) >> 12) + 3);
                    }
                    proto_tree_add_uint(icmp6_tree, hf_icmpv6_mld_mrc, tvb, offset, 2, mrc);
                    offset += 2;

                    /* Reserved */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;

                    /* Multicast Address */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_multicast_address, tvb, offset, 16, ENC_NA);
                    offset += 16;

                    /* Flag */
                    ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_mld);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_qrv, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    /* QQI */
                    qqi = tvb_get_guint8(tvb, offset);
                    if (qqi >= 128){
                        qqi = ((qqi & 0x0f) | 0x10) << (((qqi & 0x70) >> 4) + 3);
                    }
                    proto_tree_add_uint(icmp6_tree, hf_icmpv6_mld_qqi, tvb, offset, 1, qqi);
                    offset += 1;

                    /* Number of Sources */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_nb_sources, tvb, offset, 2, ENC_BIG_ENDIAN);
                    nb_sources = tvb_get_ntohs(tvb, offset);
                    offset += 2;

                    /* Source Address */
                    for (i=1; i <= nb_sources; i++){
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_source_address, tvb, offset, 16, ENC_NA);
                        offset += 16;
                    }

                }else{ /* It is a MLDv1 Packet */

                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_mrd, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* Reserved */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;

                    /* Multicast Address */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_multicast_address, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                break;
            }
            case ICMP6_ND_ROUTER_SOLICIT: /* Router Solicitation (133) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_ROUTER_ADVERT: /* Router Advertisement (134) */
            {

                /* Current hop limit */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_cur_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Flags */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_ra);

                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_m, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_o, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_h, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_prf, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Router lifetime */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_router_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reachable time */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_reachable_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Retrans timer */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_retrans_timer, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_NEIGHBOR_SOLICIT: /* Neighbor Solicitation (135) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ns_target_address, tvb, offset, 16, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " for %s", tvb_ip6_to_str(tvb, offset));

                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_NEIGHBOR_ADVERT: /* Neighbor Advertisement (136) */
            {
                guint32 na_flags;
                emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("");

                /* Flags */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_na_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_na);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_r, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_s, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_o, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_rsv, tvb, offset, 4, ENC_BIG_ENDIAN);
                na_flags = tvb_get_ntohl(tvb, offset);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_na_target_address, tvb, offset, 16, ENC_NA);


                if (na_flags & ND_NA_FLAG_R) {
                    ep_strbuf_append(flags_strbuf, "rtr, ");
                }
                if (na_flags & ND_NA_FLAG_S) {
                    ep_strbuf_append(flags_strbuf, "sol, ");
                }
                if (na_flags & ND_NA_FLAG_O) {
                    ep_strbuf_append(flags_strbuf, "ovr, ");
                }
                if (flags_strbuf->len > 2) {
                    ep_strbuf_truncate(flags_strbuf, flags_strbuf->len - 2);
                } else {
                    ep_strbuf_printf(flags_strbuf, "none");
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, " %s (%s)", tvb_ip6_to_str(tvb, offset), flags_strbuf->str);
                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_REDIRECT: /* Redirect Message (137) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_rd_target_address, tvb, offset, 16, ENC_NA);
                offset += 16;

                /* Destination Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_rd_destination_address, tvb, offset, 16, ENC_NA);
                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ROUTER_RENUMBERING: /* Router Renumbering (138) */
            {
                offset = dissect_rrenum(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }
            case ICMP6_NI_QUERY: /* ICMP Node Information Query (139) */
            case ICMP6_NI_REPLY: /* ICMP Node Information Response (140) */
            {
                offset = dissect_nodeinfo(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }
            case ICMP6_IND_SOLICIT: /* Inverse Neighbor Discovery Solicitation Message (141) */
            case ICMP6_IND_ADVERT: /* Inverse Neighbor Discovery Advertisement Message (142) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_MLDV2_REPORT: /* Version 2 Multicast Listener Report (143) */
            {
                offset = dissect_mldrv2( tvb, offset, pinfo, icmp6_tree );
                break;
            }
            case ICMP6_MIP6_DHAAD_REQUEST: /* Home Agent Address Discovery Request Message (144) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                break;
            }
            case ICMP6_MIP6_DHAAD_REPLY: /* Home Agent Address Discovery Reply Message (145) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                /* Show all Home Agent Addresses */
                while((int)length > offset)
                {
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_home_agent_address, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                break;
            }
            case ICMP6_MIP6_MPS: /* Mobile Prefix Solicitation (146) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            }
            case ICMP6_MIP6_MPA: /* Mobile Prefix Advertisement (147) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Flag */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_flag, tvb,offset, 6, ENC_NA);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_mip6);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_m, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_o, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_CERT_PATH_SOL: /* Certification Path Solicitation Message (148) */
            {

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Component  */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_component, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_CERT_PATH_AD: /* Certification Path Advertisement Message (149) */
            {

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* All Components */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_all_components, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Component  */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_component, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_EXPERIMENTAL_MOBILITY: /* ICMP messages utilized by experimental mobility protocols (150) */
            case ICMP6_FMIPV6_MESSAGES:  /* FMIPv6 Messages (154)*/
            {
                guint8 subtype;

                /* Subtype */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                subtype = tvb_get_guint8(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(subtype, fmip6_subtype_val, "Unknown (%d)"));
                offset += 1;

                switch(subtype){
                    case FMIP6_SUBTYPE_RTSOLPR:
                    {
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                    case FMIP6_SUBTYPE_PRRTADV:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_prrtadv_code_val, "Unknown %d") );
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                    case FMIP6_SUBTYPE_HI:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_hi_code_val, "Unknown %d") );
                        /* Flags */
                        ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_hi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_fmip6);

                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_u, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    break;
                    case FMIP6_SUBTYPE_HACK:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_hack_code_val, "Unknown %d") );
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                }
                offset +=1;

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_MCAST_ROUTER_ADVERT: /* Multicast Router Advertisement (151) */
            {
                /* Query Interval */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mcast_ra_query_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Robustness Variable */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mcast_ra_robustness_variable, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            case ICMP6_MCAST_ROUTER_SOLICIT: /* Multicast Router Solicitation (152) */
            case ICMP6_MCAST_ROUTER_TERM: /* Multicast Router Termination (153) */
            {
                /* No Action... */
                break;
            }
            case ICMP6_RPL_CONTROL: /* RPL Control (155) */
            {
                /* RPL: RFC 6550 : Routing over Low-Power and Lossy Networks. */
                offset = dissect_rpl_control(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }

            case ICMP6_6LOWPANND_DAR:
            case ICMP6_6LOWPANND_DAC:
            {
                /* Status */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Lifetime */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* EUI-64 */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_eui64, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;

                /* Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_raddr, tvb, offset, 16, ENC_NA);
                offset += 16;
                break;
            }
            default:
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
                                       "Dissector for ICMPv6 Type (%d)"
                                       " code not implemented, Contact Wireshark"
                                       " developers if you want this supported", icmp6_type);
                proto_tree_add_item(icmp6_tree, hf_icmpv6_data, tvb, offset, -1, ENC_NA);
                break;
        } /* switch (icmp6_type) */
    } /* if (1) */

    if (trans)
        tap_queue_packet(icmpv6_tap, pinfo, trans);

    return offset;
}
