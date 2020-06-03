static const gchar *
CVE_2012_6055_VULN_dissect_3gpp2_radius_aut_flow_profile_ids(proto_tree  *tree, tvbuff_t  *tvb, packet_info *pinfo _U_)
{
    proto_tree *sub_tree;
    int         offset = 0;
    proto_item *item;
    guint8      sub_type, sub_type_length;
    guint32     value;

    while (tvb_length_remaining(tvb,offset)>0){
        sub_type = tvb_get_guint8(tvb,offset);
        sub_type_length = tvb_get_guint8(tvb,offset+1);
        /* value is 2 octets */
        value = tvb_get_ntohs(tvb,offset+2);
        item = proto_tree_add_text(tree, tvb, offset, sub_type_length, "%s = %u",
                                   val_to_str(sub_type, a11_aut_flow_prof_subtype_vals, "Unknown"), value);
        sub_tree = proto_item_add_subtree(item, ett_a11_aut_flow_profile_ids);

        proto_tree_add_item(sub_tree, hf_a11_aut_flow_prof_sub_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_a11_aut_flow_prof_sub_type_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_a11_aut_flow_prof_sub_type_value, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset = offset+sub_type_length-2;
    }

    return "";
}
