static int
CVE_2013_4924_PATCHED_dissect_dcom_ActivationPropertiesBody(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, guint8 *drep)
{
    gint      old_offset;

    proto_item *sub_item;
    proto_tree *sub_tree;
    dcerpc_info *di;
    property_guids_t *pg;
    guint32 i;
    guint32 min_idx;

    di = (dcerpc_info *)pinfo->private_data;
    pg = (property_guids_t*)di->private_data;

    if (pg->id_idx == pg->size_idx) {
        min_idx = pg->id_idx;
    }
    else {
        /* TODO: expert info */
        min_idx = MIN(pg->id_idx, pg->size_idx);
    }

    sub_item = proto_tree_add_text(tree, tvb, offset, 0, "Properties");
    sub_tree = proto_item_add_subtree(sub_item, ett_properties);

    old_offset = offset;
    for (i = 0; i < min_idx; i++) {
        offset = dissect_dcom_ActivationProperty(tvb, offset, pinfo, sub_tree, drep,
                                                    &pg->guid[i], pg->size[i]);
    }
    proto_item_set_len(sub_item, offset - old_offset);

    return offset;
}
