static gboolean CVE_2013_4082_VULN_vwr_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    vwr_t       *vwr = (vwr_t *)wth->priv;
    guint8      rec[B_SIZE];                        /* local buffer (holds input record) */
    int         rec_size = 0, IS_TX;
    guint8      *data_ptr;
    guint16     pkt_len;                            /* length of radiotap headers */

    /* read the next frame record header in the capture file; if no more frames, return */
    if (!vwr_read_rec_header(vwr, wth->fh, &rec_size, &IS_TX, err, err_info))
        return(FALSE);                                  /* Read error or EOF */

    *data_offset = (file_tell(wth->fh) - 16);           /* set offset for random seek @PLCP */

    /* got a frame record; read over entire record (frame + trailer) into a local buffer */
    /* if we don't get it all, then declare an error, we can't process the frame */
    if (file_read(rec, rec_size, wth->fh) != rec_size) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return(FALSE);
    }

    

    /* before writing anything out, make sure the buffer has enough space for everything */
    if ((vwr->FPGA_VERSION == vVW510021_W_FPGA) || (vwr->FPGA_VERSION == vVW510006_W_FPGA) )
    /* frames are always 802.11 with an extended radiotap header */
        pkt_len = (guint16)(rec_size + STATS_COMMON_FIELDS_LEN + EXT_RTAP_FIELDS_LEN);
    else
        /* frames are always ethernet with an extended ethernettap header */
        pkt_len = (guint16)(rec_size + STATS_COMMON_FIELDS_LEN + STATS_ETHERNETTAP_FIELDS_LEN);
    buffer_assure_space(wth->frame_buffer, pkt_len);
    data_ptr = buffer_start_ptr(wth->frame_buffer);

    /* now format up the frame data */
    switch (vwr->FPGA_VERSION)
    {
        case vVW510006_W_FPGA:
            vwr_read_rec_data(wth, data_ptr, rec, rec_size);
            break;
        case vVW510021_W_FPGA:
            vwr_read_rec_data_vVW510021(wth, data_ptr, rec, rec_size, IS_TX);
            break;
        case vVW510012_E_FPGA:
            vwr_read_rec_data_ethernet(wth, data_ptr, rec, rec_size, IS_TX);
            break;
        case vVW510024_E_FPGA:
            vwr_read_rec_data_ethernet(wth, data_ptr, rec, rec_size, IS_TX);
            break;
    }

    /* If the per-file encapsulation isn't known, set it to this packet's encapsulation */
    /* If it *is* known, and it isn't this packet's encapsulation, set it to */
    /* WTAP_ENCAP_PER_PACKET, as this file doesn't have a single encapsulation for all */
    /* packets in the file */
    if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
        wth->file_encap = wth->phdr.pkt_encap;
    else {
        if (wth->file_encap != wth->phdr.pkt_encap)
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return(TRUE);
}
