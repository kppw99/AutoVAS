static int
CVE_2012_6057_VULN_dissect_eigrp_wide_metric_attr (proto_tree *tree, tvbuff_t *tvb,
                                int offset, int limit)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t   *sub_tvb;
    int         sub_offset;

    gint8 attr_offset = 0;
    gint8 attr_opcode = 0;

    limit *= 2;   /* words to bytes */

    sub_ti     = proto_tree_add_text(tree, tvb, offset, limit, "Attributes");
    sub_tree   = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_attr);
    sub_tvb    = tvb_new_subset(tvb, offset, limit, -1);
    sub_offset = 0;

    while (limit > 0) {
        attr_opcode = tvb_get_guint8(sub_tvb, sub_offset);
        proto_tree_add_item(sub_tree, hf_eigrp_attr_opcode, sub_tvb,
                            sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset += 1;

        attr_offset = tvb_get_guint8(sub_tvb, sub_offset) * 2;
        proto_tree_add_item(sub_tree, hf_eigrp_attr_offset, sub_tvb,
                            sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset += 1;

        switch (attr_opcode) {
        case EIGRP_ATTR_NOOP:
            break;

        case EIGRP_ATTR_SCALED:
            proto_tree_add_item(sub_tree, hf_eigrp_attr_scaled, sub_tvb,
                                sub_offset, 4, ENC_BIG_ENDIAN);
            break;

        case EIGRP_ATTR_TAG:
            proto_tree_add_item(sub_tree, hf_eigrp_attr_tag, sub_tvb,
                                sub_offset, 4, ENC_BIG_ENDIAN);
            break;

        case EIGRP_ATTR_COMM:
            dissect_eigrp_metric_comm(sub_tree,
                                      tvb_new_subset(sub_tvb, sub_offset, 8, -1),
                                      sub_offset, limit);
            break;

        case EIGRP_ATTR_JITTER:
            proto_tree_add_item(sub_tree, hf_eigrp_attr_jitter, sub_tvb,
                                sub_offset, 4, ENC_BIG_ENDIAN);
            break;

        case EIGRP_ATTR_QENERGY:
            proto_tree_add_item(sub_tree, hf_eigrp_attr_qenergy, sub_tvb,
                                sub_offset, 4, ENC_BIG_ENDIAN);
            break;

        case EIGRP_ATTR_ENERGY:
            proto_tree_add_item(sub_tree, hf_eigrp_attr_energy, sub_tvb,
                                sub_offset, 4, ENC_BIG_ENDIAN);
            break;

        default:
            break;
        }
        sub_offset += attr_offset;
        limit -= (EIGRP_ATTR_HDRLEN + attr_offset);
    }

    offset += sub_offset;
    return(offset);
}
