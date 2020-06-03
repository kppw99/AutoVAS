static int
CVE_2012_6053_VULN_dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item           = NULL;
    proto_tree *tree           = NULL;
    proto_item *ep_attrib_item = NULL;
    proto_tree *ep_attrib_tree = NULL;
    proto_item *ep_pktsize_item;
    proto_tree *ep_pktsize_tree;
    int         old_offset     = offset;
    guint8      endpoint;
    guint8      ep_type;
    guint8      len;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, -1, "ENDPOINT DESCRIPTOR");
        tree = proto_item_add_subtree(item, ett_descriptor_device);
    }

    len = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset);
    offset += 2;

    endpoint = tvb_get_guint8(tvb, offset)&0x0f;
    dissect_usb_endpoint_address(tree, tvb, offset);
    offset += 1;

    /* Together with class from the interface descriptor we know what kind
     * of class the device at endpoint is.
     * Make sure a conversation exists for this endpoint and attach a
     * usb_conv_into_t structure to it.
     *
     * All endpoints for the same interface descriptor share the same
     * usb_conv_info structure.
     */
    if((!pinfo->fd->flags.visited)&&usb_trans_info->interface_info){
        conversation_t *conversation;

        if(pinfo->destport==NO_ENDPOINT){
            static address tmp_addr;
            static usb_address_t usb_addr;

            /* Create a new address structure that points to the same device
             * but the new endpoint.
             */
            usb_addr.device = ((usb_address_t *)(pinfo->src.data))->device;
            usb_addr.endpoint = htolel(endpoint);
            SET_ADDRESS(&tmp_addr, AT_USB, USB_ADDR_LEN, (char *)&usb_addr);
            conversation = get_usb_conversation(pinfo, &tmp_addr, &pinfo->dst, usb_addr.endpoint, pinfo->destport);
        } else {
            static address tmp_addr;
            static usb_address_t usb_addr;

            /* Create a new address structure that points to the same device
             * but the new endpoint.
             */
            usb_addr.device = ((usb_address_t *)(pinfo->dst.data))->device;
            usb_addr.endpoint = htolel(endpoint);
            SET_ADDRESS(&tmp_addr, AT_USB, USB_ADDR_LEN, (char *)&usb_addr);
            conversation = get_usb_conversation(pinfo, &pinfo->src, &tmp_addr, pinfo->srcport, usb_addr.endpoint);
        }

        conversation_add_proto_data(conversation, proto_usb, usb_trans_info->interface_info);
    }

    /* bmAttributes */
    ep_type = ENDPOINT_TYPE(tvb_get_guint8(tvb, offset));
    if (tree) {
        ep_attrib_item = proto_tree_add_item(tree, hf_usb_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ep_attrib_tree = proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);
    }
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeTransfer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeSynchonisation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeBehaviour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* wMaxPacketSize */
    ep_pktsize_item = proto_tree_add_item(tree, hf_usb_wMaxPacketSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    ep_pktsize_tree = proto_item_add_subtree(ep_pktsize_item, ett_endpoint_wMaxPacketSize);
    if ((ep_type == ENDPOINT_TYPE_INTERRUPT) || (ep_type == ENDPOINT_TYPE_ISOCHRONOUS)) {
        proto_tree_add_item(ep_pktsize_tree, hf_usb_wMaxPacketSize_slots, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(ep_pktsize_tree, hf_usb_wMaxPacketSize_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* bInterval */
    proto_tree_add_item(tree, hf_usb_bInterval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if(item){
        proto_item_set_len(item, len);
    }
    if (offset != old_offset + len) {
        /* unknown records */
    }
    offset = old_offset + len;

    return offset;
}
