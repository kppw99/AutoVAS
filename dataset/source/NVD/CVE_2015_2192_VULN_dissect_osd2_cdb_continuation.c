static void
CVE_2015_2192_VULN_dissect_osd2_cdb_continuation(packet_info *pinfo, tvbuff_t *tvb, guint32 offset,
                              proto_tree *tree, scsi_task_data_t *cdata)
{
    scsi_osd_extra_data_t *extra_data = NULL;
    proto_item            *item;
    guint8                 format;
    guint16                sa;
    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
    }
    if (!extra_data || extra_data->continuation_length<40) return;

    /* cdb continuation format */
    item = proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    format = tvb_get_guint8(tvb, offset);
    if (format != 0x01) {
        expert_add_info(pinfo, item, &ei_osd2_cdb_continuation_format_unknown);
        return;
    }
    offset += 1;

    /* 1 reserved byte */
    offset += 1;

    /* continued service action */
    item = proto_tree_add_item(tree, hf_scsi_osd2_continued_service_action, tvb, offset, 2, ENC_BIG_ENDIAN);
    sa = tvb_get_ntohs(tvb, offset);
    if (sa != extra_data->svcaction) {
        expert_add_info(pinfo, item, &ei_osd2_continued_service_action_mismatch);
    }
    offset += 2;

    /*4 reserved bytes and continuation integrity check value (32 bytes, not dissected)*/
    offset += 36;


    /* CDB continuation descriptors */
    while (offset<extra_data->continuation_length) {
        guint16 type;
        guint32 length, padlen;
        proto_item *item_type, *item_length;

        /* descriptor type */
        item_type= proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        type = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* 1 reserved byte*/
        offset += 1;

        /* descriptor pad length */
        proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_pad_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        padlen = tvb_get_guint8(tvb, offset)&7;
        offset += 1;

        /* descriptor length */
        item_length = proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        switch (type) {
            case 0x0000: break;
            case 0x0001: break;
            case 0x0002: dissect_osd2_query_list_descriptor(pinfo, tvb, offset, tree, length);
            case 0x0100: break;
            case 0x0101: break;
            case 0xFFEE: break;
            default: expert_add_info(pinfo, item_type, &ei_osd2_cdb_continuation_descriptor_type_unknown);
        }

        if ((length+padlen)%8) {
            expert_add_info(pinfo, item_length, &ei_osd2_cdb_continuation_descriptor_length_invalid);
            return;
        }
        offset += length+padlen;
    }

}
