static int
CVE_2012_6053_PATCHED_dissect_usb_interface_descriptor(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item       = NULL;
    proto_tree *tree       = NULL;
    int         old_offset = offset;
    guint8      len;
    guint8      interface_num;
    guint8      alt_setting;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, -1, "INTERFACE DESCRIPTOR");
        tree = proto_item_add_subtree(item, ett_descriptor_device);
    }

    len = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset);
    offset += 2;

    /* bInterfaceNumber */
    interface_num = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_bInterfaceNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bAlternateSetting */
    alt_setting = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bNumEndpoints */
    proto_tree_add_item(tree, hf_usb_bNumEndpoints, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bInterfaceClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* save the class so we can access it later in the endpoint descriptor */
    usb_conv_info->interfaceClass = tvb_get_guint8(tvb, offset);
    if (!pinfo->fd->flags.visited && (alt_setting == 0)) {
        conversation_t *conversation;
        guint32 if_port;

        usb_trans_info->interface_info = se_alloc0(sizeof(usb_conv_info_t));
        usb_trans_info->interface_info->interfaceClass = tvb_get_guint8(tvb, offset);
        /* save the subclass so we can access it later in class-specific descriptors */
        usb_trans_info->interface_info->interfaceSubclass = tvb_get_guint8(tvb, offset+1);
        usb_trans_info->interface_info->transactions = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "usb transactions");

        /* Register conversation for this interface in case CONTROL messages are sent to it */
        if_port = htolel(INTERFACE_PORT | interface_num);
        conversation = get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst, if_port, pinfo->destport);
        conversation_add_proto_data(conversation, proto_usb, usb_trans_info->interface_info);
    }
    offset += 1;

    /* bInterfaceSubClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* save the subclass so we can access it later in class-specific descriptors */
    usb_conv_info->interfaceSubclass = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* bInterfaceProtocol */
    proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* iInterface */
    proto_tree_add_item(tree, hf_usb_iInterface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if(item){
        proto_item_set_len(item, len);
    }
    if (offset != old_offset + len) {
        /* unknown records */
    }

    return offset;
}
