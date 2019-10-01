static int
CVE_2012_5237_VULN_dissect_hsrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t   *next_tvb;
        gchar dst[16];

	/* Return if this isn't really HSRP traffic
	 * (source and destination port must be UDP_PORT_HSRP on HSRPv1 or HSRPv2(IPv4))
         * (source and destination port must be UDP_PORT_HSRP2_V6 on HSRPv2(IPv6))
         */
	if(pinfo->destport != UDP_PORT_HSRP && pinfo->destport != UDP_PORT_HSRP2_V6)
		return 0;

        /*
         * To check whether this is an HSRPv1 packet or HSRPv2 on dest IPv4 addr.
         */
	address_to_str_buf(&(pinfo->dst), dst, sizeof dst);

        if (pinfo->dst.type == AT_IPv4 && strcmp(dst,HSRP_DST_IP_ADDR) == 0) {
                /* HSRPv1 */
                guint8 opcode, state = 0;

                col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSRP");

                opcode = tvb_get_guint8(tvb, 1);
                if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_add_str(pinfo->cinfo, COL_INFO,
                                     val_to_str(opcode, hsrp_opcode_vals, "Unknown"));
        	}
        	if (opcode < 3) {
                	state = tvb_get_guint8(tvb, 2);
        		if (check_col(pinfo->cinfo, COL_INFO)) {
                        	col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                               		     val_to_str(state, hsrp_state_vals, "Unknown"));
        		}
                } else if (opcode == 3) {
                	state = tvb_get_guint8(tvb, 6);
        		if (check_col(pinfo->cinfo, COL_INFO)) {
                        	col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                               		     val_to_str(state, hsrp_adv_state_vals, "Unknown"));
        		}
        	}

                if (tree) {
                        proto_item *ti;
                        proto_tree *hsrp_tree;
                        gint offset;
                        guint8 hellotime, holdtime;
                        gchar auth_buf[8 + 1];

                        offset = 0;
                        ti = proto_tree_add_item(tree, proto_hsrp, tvb, offset, -1, ENC_NA);
                        hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);

                        proto_tree_add_item(hsrp_tree, hf_hsrp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        proto_tree_add_uint(hsrp_tree, hf_hsrp_opcode, tvb, offset, 1, opcode);
                        offset++;
        		if (opcode < 3) {
        			proto_tree_add_uint(hsrp_tree, hf_hsrp_state, tvb, offset, 1, state);
        			offset++;
        			hellotime = tvb_get_guint8(tvb, offset);
        			proto_tree_add_uint_format(hsrp_tree, hf_hsrp_hellotime, tvb, offset, 1, hellotime,
                                                   "Hellotime: %sDefault (%u)",
                                                   (hellotime == HSRP_DEFAULT_HELLOTIME) ? "" : "Non-",
                                                   hellotime);
        			offset++;
        			holdtime = tvb_get_guint8(tvb, offset);
        			proto_tree_add_uint_format(hsrp_tree, hf_hsrp_holdtime, tvb, offset, 1, holdtime,
                                                   "Holdtime: %sDefault (%u)",
                                                   (holdtime == HSRP_DEFAULT_HOLDTIME) ? "" : "Non-",
                                                   holdtime);
        			offset++;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
        			offset++;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_group, tvb, offset, 1, ENC_BIG_ENDIAN);
        			offset++;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        			offset++;
        			tvb_memcpy(tvb, auth_buf, offset, 8);
        			auth_buf[sizeof auth_buf - 1] = '\0';
        			proto_tree_add_string_format(hsrp_tree, hf_hsrp_auth_data, tvb, offset, 8, auth_buf,
                                                     "Authentication Data: %sDefault (%s)",
                                                     (tvb_strneql(tvb, offset, "cisco", strlen("cisco"))) == 0 ? "" : "Non-",
                                                     auth_buf);
        			offset += 8;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_virt_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        		} else if (opcode == 3) {
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        			offset += 2;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        			offset += 2;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        			offset += 1;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
        			offset += 1;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_activegrp, tvb, offset, 2, ENC_BIG_ENDIAN);
        			offset += 2;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_passivegrp, tvb, offset, 2, ENC_BIG_ENDIAN);
        			offset += 2;
        			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
        		} else {
        			next_tvb = tvb_new_subset_remaining(tvb, offset);
        			call_dissector(data_handle, next_tvb, pinfo, hsrp_tree);
        		}
                }
        } else if ((pinfo->dst.type == AT_IPv4 && strcmp(dst,HSRP2_DST_IP_ADDR) == 0) ||
		   (pinfo->dst.type == AT_IPv6 && pinfo->destport == UDP_PORT_HSRP2_V6)) {
                /* HSRPv2 */
                guint offset = 0;
                proto_item *ti = NULL;
                proto_tree *hsrp_tree = NULL;
                guint8 type,len;

                col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSRPv2");

                if (tree) {
                        ti = proto_tree_add_item(tree, proto_hsrp, tvb, offset, -1, ENC_NA);
                        hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);
		}

                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                        type = tvb_get_guint8(tvb, offset);
                        len = tvb_get_guint8(tvb, offset+1);

                        if (type == 1 && len == 40) {
                                /* Group State TLV */
                                guint8 opcode, state = 0, ipver;
                                guint32 hellotime, holdtime;
                                proto_tree *group_state_tlv;

                                if (tree) {
                                        ti = proto_tree_add_uint_format(hsrp_tree, hf_hsrp2_group_state_tlv, tvb, offset, 2, type,
                                        "Group State TLV: Type=%d Len=%d", type, len);
                                }
				offset+=2;

                                opcode = tvb_get_guint8(tvb, offset+1);
                                if (check_col(pinfo->cinfo, COL_INFO)) {
                                        col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                                                     val_to_str(opcode, hsrp2_opcode_vals, "Unknown"));
                        	}

                                state = tvb_get_guint8(tvb, offset+2);
                        	if (check_col(pinfo->cinfo, COL_INFO)) {
                                       	col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                                      	             val_to_str(state, hsrp2_state_vals, "Unknown"));
                                }

                                if (tree) {
                                        /* Making Group State TLV subtree. */
                                        group_state_tlv = proto_item_add_subtree(ti, ett_hsrp2_group_state_tlv);
                                        proto_tree_add_item(group_state_tlv, hf_hsrp2_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset++;
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_opcode, tvb, offset, 1, opcode);
                                        offset++;
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_state, tvb, offset, 1, state);
                			offset++;
                			ipver = tvb_get_guint8(tvb, offset);
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_ipversion, tvb, offset, 1, ipver);
                			offset++;
                			proto_tree_add_item(group_state_tlv, hf_hsrp2_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                			offset+=2;
                			proto_tree_add_item(group_state_tlv, hf_hsrp2_identifier, tvb, offset, 6, ENC_NA);
                			offset+=6;
                			proto_tree_add_item(group_state_tlv, hf_hsrp2_priority, tvb, offset, 4, ENC_BIG_ENDIAN);
                			offset+=4;

                			hellotime = tvb_get_ntohl(tvb, offset);
                			proto_tree_add_uint_format(group_state_tlv, hf_hsrp2_hellotime, tvb, offset, 4, hellotime,
                                                           "Hellotime: %sDefault (%u)",
                                                           (hellotime == HSRP2_DEFAULT_HELLOTIME) ? "" : "Non-",
                                                           hellotime);
                			offset+=4;
                			holdtime = tvb_get_ntohl(tvb, offset);
                			proto_tree_add_uint_format(group_state_tlv, hf_hsrp2_holdtime, tvb, offset, 4, holdtime,
                                                           "Holdtime: %sDefault (%u)",
                                                           (holdtime == HSRP2_DEFAULT_HOLDTIME) ? "" : "Non-",
                                                           holdtime);
                			offset+=4;
                                        if (ipver == 4) {
                                                /* Fetch Virtual IP as IPv4 */
                                                proto_tree_add_item(group_state_tlv, hf_hsrp2_virt_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                                        } else if (ipver == 6) {
                                                /* Fetch Virtual IP as IPv6 */
                                                proto_tree_add_item(group_state_tlv, hf_hsrp2_virt_ip_addr_v6, tvb, offset, 16, ENC_NA);
                                        } else {
                                                /* Unknown protocol */
                        			next_tvb = tvb_new_subset_remaining(tvb, offset);
                        			call_dissector(data_handle, next_tvb, pinfo, hsrp_tree);
                                                break;
					}
				}
                        } else if (type == 2 && len == 4) {
                                /* Interface State TLV */
                                guint16 active,passive;
                                active = tvb_get_ntohs(tvb, offset+2);
                                passive = tvb_get_ntohs(tvb, offset+4);

                                if (check_col(pinfo->cinfo, COL_INFO)) {
                                        col_add_fstr(pinfo->cinfo, COL_INFO, "Interface State TLV (Act=%d Pass=%d)",active,passive);
                                }

                                if (tree) {
                                        proto_tree *interface_state_tlv;
                                        ti = proto_tree_add_uint_format(hsrp_tree, hf_hsrp2_interface_state_tlv, tvb, offset, 1, type,
                                        "Interface State TLV: Type=%d Len=%d", type, len);
                                        offset+=2;

                                        /* Making Interface State TLV subtree */
                                        interface_state_tlv = proto_item_add_subtree(ti, ett_hsrp2_interface_state_tlv);
                			proto_tree_add_item(interface_state_tlv, hf_hsrp2_active_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset+=2;
                			proto_tree_add_item(interface_state_tlv, hf_hsrp2_passive_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                                }
                        } else if (type == 3 && len == 8) {
                                /* Text Authentication TLV */
                                if (tree) {
                                        proto_tree *text_auth_tlv;
                                        gchar auth_buf[8 + 1];

                                        ti = proto_tree_add_uint_format(hsrp_tree, hf_hsrp2_text_auth_tlv, tvb, offset, 1, type,
                                        "Text Authentication TLV: Type=%d Len=%d", type, len);
                                        offset+=2;

                                        /* Making Text Authentication TLV subtree */
                                        text_auth_tlv = proto_item_add_subtree(ti, ett_hsrp2_text_auth_tlv);

                			tvb_memcpy(tvb, auth_buf, offset, 8);
                			auth_buf[sizeof auth_buf - 1] = '\0';
                			proto_tree_add_string_format(text_auth_tlv, hf_hsrp2_auth_data, tvb, offset, 8, auth_buf,
                                                             "Authentication Data: %sDefault (%s)",
                                                             (tvb_strneql(tvb, offset, "cisco", strlen("cisco"))) == 0 ? "" : "Non-",
                                                             auth_buf);
                                }
                        } else if (type == 4 && len == 28) {
                                /* Text Authentication TLV */
                                if (tree) {
                                        proto_tree *md5_auth_tlv;

                                        ti = proto_tree_add_uint_format(hsrp_tree, hf_hsrp2_text_auth_tlv, tvb, offset, 1, type,
                                        "MD5 Authentication TLV: Type=%d Len=%d", type, len);
                                        offset+=2;

                                        /* Making MD5 Authentication TLV subtree */
                                        md5_auth_tlv = proto_item_add_subtree(ti, ett_hsrp2_md5_auth_tlv);
                                        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset++;
                                        /* Skip padding field */
                                        offset++;
                                        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset+=2;
                                        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
                                        offset+=4;
                                        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_key_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                                        offset+=4;
                                        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_auth_data, tvb, offset, 16, ENC_BIG_ENDIAN);
                                }
                        } else {
                                /* Undefined TLV */
				if (tree) {
        				next_tvb = tvb_new_subset_remaining(tvb, offset);
        				call_dissector(data_handle, next_tvb, pinfo, hsrp_tree);
				}
                                break;
			}
		}
        }

        return tvb_length(tvb);
}
