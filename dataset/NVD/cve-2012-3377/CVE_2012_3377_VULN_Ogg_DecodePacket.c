 ****************************************************************************/
static void CVE_2012_3377_VULN_Ogg_DecodePacket( demux_t *p_demux,
                              logical_stream_t *p_stream,
                              ogg_packet *p_oggpacket )
{
    block_t *p_block;
    bool b_selected;
    int i_header_len = 0;
    mtime_t i_pts = -1, i_interpolated_pts;
    demux_sys_t *p_ogg = p_demux->p_sys;

    /* Sanity check */
    if( !p_oggpacket->bytes )
    {
        msg_Dbg( p_demux, "discarding 0 sized packet" );
        return;
    }

    if( p_oggpacket->bytes >= 7 &&
        ! memcmp ( p_oggpacket->packet, "Annodex", 7 ) )
    {
        /* it's an Annodex packet -- skip it (do nothing) */
        return;
    }
    else if( p_oggpacket->bytes >= 7 &&
        ! memcmp ( p_oggpacket->packet, "AnxData", 7 ) )
    {
        /* it's an AnxData packet -- skip it (do nothing) */
        return;
    }

    if( p_stream->fmt.i_codec == VLC_CODEC_SUBT &&
        p_oggpacket->packet[0] & PACKET_TYPE_BITS ) return;

    /* Check the ES is selected */
    es_out_Control( p_demux->out, ES_OUT_GET_ES_STATE,
                    p_stream->p_es, &b_selected );

    if( p_stream->b_force_backup )
    {
        bool b_xiph;
        p_stream->i_packets_backup++;
        switch( p_stream->fmt.i_codec )
        {
        case VLC_CODEC_VORBIS:
        case VLC_CODEC_SPEEX:
        case VLC_CODEC_THEORA:
            if( p_stream->i_packets_backup == 3 ) p_stream->b_force_backup = 0;
            b_xiph = true;
            break;

        case VLC_CODEC_FLAC:
            if( !p_stream->fmt.audio.i_rate && p_stream->i_packets_backup == 2 )
            {
                Ogg_ReadFlacHeader( p_demux, p_stream, p_oggpacket );
                p_stream->b_force_backup = 0;
            }
            else if( p_stream->fmt.audio.i_rate )
            {
                p_stream->b_force_backup = 0;
                if( p_oggpacket->bytes >= 9 )
                {
                    p_oggpacket->packet += 9;
                    p_oggpacket->bytes -= 9;
                }
            }
            b_xiph = false;
            break;

        case VLC_CODEC_KATE:
            if( p_stream->i_packets_backup == p_stream->i_kate_num_headers ) p_stream->b_force_backup = 0;
            b_xiph = true;
            break;

        default:
            p_stream->b_force_backup = 0;
            b_xiph = false;
            break;
        }

        /* Backup the ogg packet (likely an header packet) */
        if( !b_xiph )
        {
            void *p_org = p_stream->p_headers;
            p_stream->i_headers += p_oggpacket->bytes;
            p_stream->p_headers = realloc( p_stream->p_headers, p_stream->i_headers );
            if( p_stream->p_headers )
            {
                memcpy( (unsigned char *)p_stream->p_headers + p_stream->i_headers - p_oggpacket->bytes,
                        p_oggpacket->packet, p_stream->i_headers );
            }
            else
            {
#warning Memory leak
                p_stream->i_headers = 0;
                p_stream->p_headers = NULL;
                free( p_org );
            }
        }
        else if( xiph_AppendHeaders( &p_stream->i_headers, &p_stream->p_headers,
                                     p_oggpacket->bytes, p_oggpacket->packet ) )
        {
            p_stream->i_headers = 0;
            p_stream->p_headers = NULL;
        }
        if( p_stream->i_headers > 0 )
        {
            if( !p_stream->b_force_backup )
            {
                /* Last header received, commit changes */
                free( p_stream->fmt.p_extra );

                p_stream->fmt.i_extra = p_stream->i_headers;
                p_stream->fmt.p_extra = malloc( p_stream->i_headers );
                if( p_stream->fmt.p_extra )
                    memcpy( p_stream->fmt.p_extra, p_stream->p_headers,
                            p_stream->i_headers );
                else
                    p_stream->fmt.i_extra = 0;

                if( Ogg_LogicalStreamResetEsFormat( p_demux, p_stream ) )
                    es_out_Control( p_demux->out, ES_OUT_SET_ES_FMT,
                                    p_stream->p_es, &p_stream->fmt );

                if( p_stream->i_headers > 0 )
                    Ogg_ExtractMeta( p_demux, p_stream->fmt.i_codec,
                                     p_stream->p_headers, p_stream->i_headers );

                /* we're not at BOS anymore for this logical stream */
                p_ogg->i_bos--;
            }
        }

        b_selected = false; /* Discard the header packet */
    }

    /* Convert the pcr into a pts */
    if( p_stream->fmt.i_codec == VLC_CODEC_VORBIS ||
        p_stream->fmt.i_codec == VLC_CODEC_SPEEX ||
        p_stream->fmt.i_codec == VLC_CODEC_FLAC )
    {
        if( p_stream->i_pcr >= 0 )
        {
            /* This is for streams where the granulepos of the header packets
             * doesn't match these of the data packets (eg. ogg web radios). */
            if( p_stream->i_previous_pcr == 0 &&
                p_stream->i_pcr  > 3 * DEFAULT_PTS_DELAY )
            {
                es_out_Control( p_demux->out, ES_OUT_RESET_PCR );

                /* Call the pace control */
                es_out_Control( p_demux->out, ES_OUT_SET_PCR,
                                VLC_TS_0 + p_stream->i_pcr );
            }

            p_stream->i_previous_pcr = p_stream->i_pcr;

            /* The granulepos is the end date of the sample */
            i_pts =  p_stream->i_pcr;
        }
    }

    /* Convert the granulepos into the next pcr */
    i_interpolated_pts = p_stream->i_interpolated_pcr;
    Ogg_UpdatePCR( p_stream, p_oggpacket );

    /* SPU streams are typically discontinuous, do not mind large gaps */
    if( p_stream->fmt.i_cat != SPU_ES )
    {
        if( p_stream->i_pcr >= 0 )
        {
            /* This is for streams where the granulepos of the header packets
             * doesn't match these of the data packets (eg. ogg web radios). */
            if( p_stream->i_previous_pcr == 0 &&
                p_stream->i_pcr  > 3 * DEFAULT_PTS_DELAY )
            {
                es_out_Control( p_demux->out, ES_OUT_RESET_PCR );

                /* Call the pace control */
                es_out_Control( p_demux->out, ES_OUT_SET_PCR, VLC_TS_0 + p_stream->i_pcr );
            }
        }
    }

    if( p_stream->fmt.i_codec != VLC_CODEC_VORBIS &&
        p_stream->fmt.i_codec != VLC_CODEC_SPEEX &&
        p_stream->fmt.i_codec != VLC_CODEC_FLAC &&
        p_stream->i_pcr >= 0 )
    {
        p_stream->i_previous_pcr = p_stream->i_pcr;

        /* The granulepos is the start date of the sample */
        i_pts = p_stream->i_pcr;
    }

    if( !b_selected )
    {
        /* This stream isn't currently selected so we don't need to decode it,
         * but we did need to store its pcr as it might be selected later on */
        return;
    }

    if( p_oggpacket->bytes <= 0 )
        return;

    if( !( p_block = block_New( p_demux, p_oggpacket->bytes ) ) ) return;


    /* may need to preroll video frames after a seek */
    if ( p_stream->i_skip_frames > 0 )
    {
        p_block->i_flags |= BLOCK_FLAG_PREROLL;
        p_stream->i_skip_frames--;
    }


    /* Normalize PTS */
    if( i_pts == 0 ) i_pts = VLC_TS_0;
    else if( i_pts == -1 && i_interpolated_pts == 0 ) i_pts = VLC_TS_0;
    else if( i_pts == -1 ) i_pts = VLC_TS_INVALID;

    if( p_stream->fmt.i_cat == AUDIO_ES )
        p_block->i_dts = p_block->i_pts = i_pts;
    else if( p_stream->fmt.i_cat == SPU_ES )
    {
        p_block->i_dts = p_block->i_pts = i_pts;
        p_block->i_length = 0;
    }
    else if( p_stream->fmt.i_codec == VLC_CODEC_THEORA )
    {
        p_block->i_dts = p_block->i_pts = i_pts;
        if( (p_oggpacket->granulepos & ((1<<p_stream->i_granule_shift)-1)) == 0 )
        {
            p_block->i_flags |= BLOCK_FLAG_TYPE_I;
        }
    }
    else if( p_stream->fmt.i_codec == VLC_CODEC_DIRAC )
    {
        ogg_int64_t dts = p_oggpacket->granulepos >> 31;
        ogg_int64_t delay = (p_oggpacket->granulepos >> 9) & 0x1fff;

        uint64_t u_pnum = dts + delay;

        p_block->i_dts = p_stream->i_pcr;
        p_block->i_pts = VLC_TS_INVALID;
        /* NB, OggDirac granulepos values are in units of 2*picturerate */

        /* granulepos for dirac is possibly broken, this value should be ignored */
        if( -1 != p_oggpacket->granulepos )
            p_block->i_pts = u_pnum * INT64_C(1000000) / p_stream->f_rate / 2;
    }
    else
    {
        p_block->i_dts = i_pts;
        p_block->i_pts = VLC_TS_INVALID;
    }

    if( p_stream->fmt.i_codec != VLC_CODEC_VORBIS &&
        p_stream->fmt.i_codec != VLC_CODEC_SPEEX &&
        p_stream->fmt.i_codec != VLC_CODEC_FLAC &&
        p_stream->fmt.i_codec != VLC_CODEC_TARKIN &&
        p_stream->fmt.i_codec != VLC_CODEC_THEORA &&
        p_stream->fmt.i_codec != VLC_CODEC_CMML &&
        p_stream->fmt.i_codec != VLC_CODEC_DIRAC &&
        p_stream->fmt.i_codec != VLC_CODEC_KATE )
    {
        /* We remove the header from the packet */
        i_header_len = (*p_oggpacket->packet & PACKET_LEN_BITS01) >> 6;
        i_header_len |= (*p_oggpacket->packet & PACKET_LEN_BITS2) << 1;

        if( p_stream->fmt.i_codec == VLC_CODEC_SUBT)
        {
            /* But with subtitles we need to retrieve the duration first */
            int i, lenbytes = 0;

            if( i_header_len > 0 && p_oggpacket->bytes >= i_header_len + 1 )
            {
                for( i = 0, lenbytes = 0; i < i_header_len; i++ )
                {
                    lenbytes = lenbytes << 8;
                    lenbytes += *(p_oggpacket->packet + i_header_len - i);
                }
            }
            if( p_oggpacket->bytes - 1 - i_header_len > 2 ||
                ( p_oggpacket->packet[i_header_len + 1] != ' ' &&
                  p_oggpacket->packet[i_header_len + 1] != 0 &&
                  p_oggpacket->packet[i_header_len + 1] != '\n' &&
                  p_oggpacket->packet[i_header_len + 1] != '\r' ) )
            {
                p_block->i_length = (mtime_t)lenbytes * 1000;
            }
        }

        i_header_len++;
        if( p_block->i_buffer >= (unsigned int)i_header_len )
            p_block->i_buffer -= i_header_len;
        else
            p_block->i_buffer = 0;
    }

    if( p_stream->fmt.i_codec == VLC_CODEC_TARKIN )
    {
        /* FIXME: the biggest hack I've ever done */
        msg_Warn( p_demux, "tarkin pts: %"PRId64", granule: %"PRId64,
                  p_block->i_pts, p_block->i_dts );
        msleep(10000);
    }

    memcpy( p_block->p_buffer, p_oggpacket->packet + i_header_len,
            p_oggpacket->bytes - i_header_len );

    es_out_Send( p_demux->out, p_stream->p_es, p_block );
}
