static gint
CVE_2012_6054_PATCHED_dissect_sflow_245_address_type(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, gint offset,
                               struct sflow_address_type *hf_type,
                               struct sflow_address_details *addr_detail) {
    guint32 addr_type;
    int len;
    proto_item *pi;

    addr_type = tvb_get_ntohl(tvb, offset);
    offset += 4;

    switch (addr_type) {
    case ADDR_TYPE_IPV4:
        len = 4;
        proto_tree_add_item(tree, hf_type->hf_addr_v4, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case ADDR_TYPE_IPV6:
        len = 16;
        proto_tree_add_item(tree, hf_type->hf_addr_v6, tvb, offset, 16, ENC_NA);
        break;
    default:
        /* unknown/invalid address type, we don't know the length
           setting it to 0 is ok, offset is incremented by this function,
           we won't get stuck in an endless loop */
        len = 0;
        pi = proto_tree_add_text(tree, tvb, offset - 4, 4, "Unknown address type (%u)", addr_type);
        expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_ERROR, "Unknown/invalid address type");
    }

    if (addr_detail) {
        addr_detail->addr_type = addr_type;
        switch (len) {
        case 4:
            tvb_memcpy(tvb, addr_detail->agent_address.v4, offset, len);
            break;
        case 16:
            tvb_memcpy(tvb, addr_detail->agent_address.v6, offset, len);
            break;
        }
    }

    return offset + len;
}
