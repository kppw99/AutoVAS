static int CVE_2014_9676_VULN_seg_write_packet(AVFormatContext *s, AVPacket *pkt)
{
    SegmentContext *seg = s->priv_data;
    AVFormatContext *oc = seg->avf;
    AVStream *st = s->streams[pkt->stream_index];
    int64_t end_pts = INT64_MAX, offset;
    int start_frame = INT_MAX;
    int ret;

    if (seg->times) {
        end_pts = seg->segment_count < seg->nb_times ?
            seg->times[seg->segment_count] : INT64_MAX;
    } else if (seg->frames) {
        start_frame = seg->segment_count <= seg->nb_frames ?
            seg->frames[seg->segment_count] : INT_MAX;
    } else {
        end_pts = seg->time * (seg->segment_count+1);
    }

    av_dlog(s, "packet stream:%d pts:%s pts_time:%s is_key:%d frame:%d\n",
           pkt->stream_index, av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base),
           pkt->flags & AV_PKT_FLAG_KEY,
           pkt->stream_index == seg->reference_stream_index ? seg->frame_count : -1);

    if (pkt->stream_index == seg->reference_stream_index &&
        pkt->flags & AV_PKT_FLAG_KEY &&
        (seg->frame_count >= start_frame ||
         (pkt->pts != AV_NOPTS_VALUE &&
          av_compare_ts(pkt->pts, st->time_base,
                        end_pts-seg->time_delta, AV_TIME_BASE_Q) >= 0))) {
        if ((ret = segment_end(s, seg->individual_header_trailer, 0)) < 0)
            goto fail;

        if ((ret = segment_start(s, seg->individual_header_trailer)) < 0)
            goto fail;

        oc = seg->avf;

        seg->cur_entry.index = seg->segment_idx;
        seg->cur_entry.start_time = (double)pkt->pts * av_q2d(st->time_base);
        seg->cur_entry.start_pts = av_rescale_q(pkt->pts, st->time_base, AV_TIME_BASE_Q);
    } else if (pkt->pts != AV_NOPTS_VALUE) {
        seg->cur_entry.end_time =
            FFMAX(seg->cur_entry.end_time, (double)(pkt->pts + pkt->duration) * av_q2d(st->time_base));
    }

    if (seg->is_first_pkt) {
        av_log(s, AV_LOG_DEBUG, "segment:'%s' starts with packet stream:%d pts:%s pts_time:%s frame:%d\n",
               seg->avf->filename, pkt->stream_index,
               av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base), seg->frame_count);
        seg->is_first_pkt = 0;
    }

    av_log(s, AV_LOG_DEBUG, "stream:%d start_pts_time:%s pts:%s pts_time:%s dts:%s dts_time:%s",
           pkt->stream_index,
           av_ts2timestr(seg->cur_entry.start_pts, &AV_TIME_BASE_Q),
           av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base),
           av_ts2str(pkt->dts), av_ts2timestr(pkt->dts, &st->time_base));

    /* compute new timestamps */
    offset = av_rescale_q(seg->initial_offset - (seg->reset_timestamps ? seg->cur_entry.start_pts : 0),
                          AV_TIME_BASE_Q, st->time_base);
    if (pkt->pts != AV_NOPTS_VALUE)
        pkt->pts += offset;
    if (pkt->dts != AV_NOPTS_VALUE)
        pkt->dts += offset;

    av_log(s, AV_LOG_DEBUG, " -> pts:%s pts_time:%s dts:%s dts_time:%s\n",
           av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base),
           av_ts2str(pkt->dts), av_ts2timestr(pkt->dts, &st->time_base));

    ret = ff_write_chained(oc, pkt->stream_index, pkt, s);

fail:
    if (pkt->stream_index == seg->reference_stream_index)
        seg->frame_count++;

    if (ret < 0) {
        if (seg->list)
            avio_close(seg->list_pb);
        avformat_free_context(oc);
    }

    return ret;
}
