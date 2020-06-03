static gboolean
CVE_2013_4936_VULN_IsDFP_Frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16       u16SFCRC16;
    guint8        u8SFPosition;
    guint8        u8SFDataLength   = 255;
    int           offset           = 0;
    guint32       u32SubStart;
    guint16       crc;
    gint          tvb_len          = 0;
    unsigned char virtualFramebuffer[16];
    guint16       u16FrameID;

    /* the sub tvb will NOT contain the frame_id here! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

    /* try to bild a temporaray buffer for generating this CRC */
    memcpy(&virtualFramebuffer[0], pinfo->dst.data, 6);
    memcpy(&virtualFramebuffer[6], pinfo->src.data, 6);
    virtualFramebuffer[12] = 0x88;
    virtualFramebuffer[13] = 0x92;
    virtualFramebuffer[15] = (unsigned char) (u16FrameID &0xff);
    virtualFramebuffer[14] = (unsigned char) (u16FrameID>>8);
    crc = crc16_plain_init();
    crc = crc16_plain_update(crc, &virtualFramebuffer[0], 16);
    crc = crc16_plain_finalize(crc);
    /* can check this CRC only by having built a temporary data buffer out of the pinfo data */
    u16SFCRC16 = tvb_get_letohs(tvb, offset);
    if (u16SFCRC16 != 0) /* no crc! */
    {
        if (u16SFCRC16 != crc)
        {
            proto_item_append_text(tree, ", no packed frame: SFCRC16 is 0x%x should be 0x%x", u16SFCRC16, crc);
            return(FALSE);
        }
    }
    /* end of first CRC check */

    offset += 2;    /*Skip first crc */
    tvb_len = tvb_length(tvb);
    if (offset + 4 > tvb_len)
        return FALSE;
    if (tvb_get_letohs(tvb, offset) == 0)
        return FALSE;   /* no valid DFP frame */
    while (1) {
        u32SubStart = offset;

        u8SFPosition = tvb_get_guint8(tvb, offset);
        offset += 1;

        u8SFDataLength = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (u8SFDataLength == 0) {
            break;
        }

        offset += 2;

        offset += u8SFDataLength;
       if (offset > tvb_len)
           return /*TRUE; */FALSE;

        u16SFCRC16 = tvb_get_letohs(tvb, offset);
        if (u16SFCRC16 != 0) {
            if (u8SFPosition & 0x80) {
                crc = crc16_plain_tvb_offset_seed(tvb, u32SubStart, offset-u32SubStart, 0);
                if (crc != u16SFCRC16) {
                    return FALSE;
                } else {
                }
            } else {
            }
        }
        offset += 2;
    }
    return TRUE;
}
