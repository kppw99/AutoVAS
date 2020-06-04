static int CVE_2012_2797_VULN_decode_frame_mp3on4(AVCodecContext *avctx, void *data,
                               int *got_frame_ptr, AVPacket *avpkt)
{
    const uint8_t *buf     = avpkt->data;
    int buf_size           = avpkt->size;
    MP3On4DecodeContext *s = avctx->priv_data;
    MPADecodeContext *m;
    int fsize, len = buf_size, out_size = 0;
    uint32_t header;
    OUT_INT *out_samples;
    OUT_INT *outptr, *bp;
    int fr, j, n, ch, ret;

    /* get output buffer */
    s->frame->nb_samples = MPA_FRAME_SIZE;
    if ((ret = avctx->get_buffer(avctx, s->frame)) < 0) {
        av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
        return ret;
    }
    out_samples = (OUT_INT *)s->frame->data[0];

    // Discard too short frames
    if (buf_size < HEADER_SIZE)
        return AVERROR_INVALIDDATA;

    // If only one decoder interleave is not needed
    outptr = s->frames == 1 ? out_samples : s->decoded_buf;

    avctx->bit_rate = 0;

    ch = 0;
    for (fr = 0; fr < s->frames; fr++) {
        fsize = AV_RB16(buf) >> 4;
        fsize = FFMIN3(fsize, len, MPA_MAX_CODED_FRAME_SIZE);
        m     = s->mp3decctx[fr];
        assert(m != NULL);

        if (fsize < HEADER_SIZE) {
            av_log(avctx, AV_LOG_ERROR, "Frame size smaller than header size\n");
            return AVERROR_INVALIDDATA;
        }
        header = (AV_RB32(buf) & 0x000fffff) | s->syncword; // patch header

        if (ff_mpa_check_header(header) < 0) // Bad header, discard block
            break;

        avpriv_mpegaudio_decode_header((MPADecodeHeader *)m, header);

        if (ch + m->nb_channels > avctx->channels) {
            av_log(avctx, AV_LOG_ERROR, "frame channel count exceeds codec "
                                        "channel count\n");
            return AVERROR_INVALIDDATA;
        }
        ch += m->nb_channels;

        out_size += mp_decode_frame(m, outptr, buf, fsize);
        buf      += fsize;
        len      -= fsize;

        if (s->frames > 1) {
            n = m->avctx->frame_size*m->nb_channels;
            /* interleave output data */
            bp = out_samples + s->coff[fr];
            if (m->nb_channels == 1) {
                for (j = 0; j < n; j++) {
                    *bp = s->decoded_buf[j];
                    bp += avctx->channels;
                }
            } else {
                for (j = 0; j < n; j++) {
                    bp[0] = s->decoded_buf[j++];
                    bp[1] = s->decoded_buf[j];
                    bp   += avctx->channels;
                }
            }
        }
        avctx->bit_rate += m->bit_rate;
    }

    /* update codec info */
    avctx->sample_rate = s->mp3decctx[0]->sample_rate;

    s->frame->nb_samples = out_size / (avctx->channels * sizeof(OUT_INT));
    *got_frame_ptr   = 1;
    *(AVFrame *)data = *s->frame;

    return buf_size;
}