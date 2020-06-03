static int CVE_2014_7933_VULN_matroska_read_seek(AVFormatContext *s, int stream_index,
                              int64_t timestamp, int flags)
{
    MatroskaDemuxContext *matroska = s->priv_data;
    MatroskaTrack *tracks = matroska->tracks.elem;
    AVStream *st = s->streams[stream_index];
    int i, index, index_sub, index_min;

    /* Parse the CUES now since we need the index data to seek. */
    if (matroska->cues_parsing_deferred > 0) {
        matroska->cues_parsing_deferred = 0;
        matroska_parse_cues(matroska);
    }

    if (!st->nb_index_entries)
        goto err;
    timestamp = FFMAX(timestamp, st->index_entries[0].timestamp);

    if ((index = av_index_search_timestamp(st, timestamp, flags)) < 0) {
        avio_seek(s->pb, st->index_entries[st->nb_index_entries - 1].pos,
                  SEEK_SET);
        matroska->current_id = 0;
        while ((index = av_index_search_timestamp(st, timestamp, flags)) < 0) {
            matroska_clear_queue(matroska);
            if (matroska_parse_cluster(matroska) < 0)
                break;
        }
    }

    matroska_clear_queue(matroska);
    if (index < 0 || (matroska->cues_parsing_deferred < 0 && index == st->nb_index_entries - 1))
        goto err;

    index_min = index;
    for (i = 0; i < matroska->tracks.nb_elem; i++) {
        tracks[i].audio.pkt_cnt        = 0;
        tracks[i].audio.sub_packet_cnt = 0;
        tracks[i].audio.buf_timecode   = AV_NOPTS_VALUE;
        tracks[i].end_timecode         = 0;
        if (tracks[i].type == MATROSKA_TRACK_TYPE_SUBTITLE &&
            tracks[i].stream->discard != AVDISCARD_ALL) {
            index_sub = av_index_search_timestamp(
                tracks[i].stream, st->index_entries[index].timestamp,
                AVSEEK_FLAG_BACKWARD);
            while (index_sub >= 0 &&
                  index_min > 0 &&
                  tracks[i].stream->index_entries[index_sub].pos < st->index_entries[index_min].pos &&
                  st->index_entries[index].timestamp - tracks[i].stream->index_entries[index_sub].timestamp < 30000000000 / matroska->time_scale)
                index_min--;
        }
    }

    avio_seek(s->pb, st->index_entries[index_min].pos, SEEK_SET);
    matroska->current_id       = 0;
    if (flags & AVSEEK_FLAG_ANY) {
        st->skip_to_keyframe = 0;
        matroska->skip_to_timecode = timestamp;
    } else {
        st->skip_to_keyframe = 1;
        matroska->skip_to_timecode = st->index_entries[index].timestamp;
    }
    matroska->skip_to_keyframe = 1;
    matroska->done             = 0;
    matroska->num_levels       = 0;
    ff_update_cur_dts(s, st, st->index_entries[index].timestamp);
    return 0;
err:
    // slightly hackish but allows proper fallback to
    // the generic seeking code.
    matroska_clear_queue(matroska);
    matroska->current_id = 0;
    st->skip_to_keyframe =
    matroska->skip_to_keyframe = 0;
    matroska->done = 0;
    matroska->num_levels = 0;
    return -1;
}
