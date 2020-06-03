static void
CVE_2012_6056_VULN_dissect_sack_chunk(packet_info* pinfo, tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item, sctp_half_assoc_t* ha)
{
  guint16 number_of_gap_blocks, number_of_dup_tsns;
  guint16 gap_block_number, dup_tsn_number, start, end;
  gint gap_block_offset, dup_tsn_offset;
  guint32 cum_tsn_ack;
  proto_item *block_item;
  proto_tree *block_tree;
  proto_tree *flags_tree;
  proto_item *ctsa_item;
  proto_item *a_rwnd_item;
  proto_tree *acks_tree;
  guint32 tsns_gap_acked = 0;
  guint32 a_rwnd;
  guint16 last_end;

  flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_sack_chunk_flags);
  proto_tree_add_item(flags_tree, hf_sack_chunk_ns,                    chunk_tvb, CHUNK_FLAGS_OFFSET,                      CHUNK_FLAGS_LENGTH,                      ENC_BIG_ENDIAN);
  ctsa_item = proto_tree_add_item(chunk_tree, hf_sack_chunk_cumulative_tsn_ack,    chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET,    SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH,    ENC_BIG_ENDIAN);
  a_rwnd_item = proto_tree_add_item(chunk_tree, hf_sack_chunk_adv_rec_window_credit, chunk_tvb, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(chunk_tree, hf_sack_chunk_number_of_gap_blocks,  chunk_tvb, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET,  SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_LENGTH,  ENC_BIG_ENDIAN);
  proto_tree_add_item(chunk_tree, hf_sack_chunk_number_of_dup_tsns,    chunk_tvb, SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET,    SACK_CHUNK_NUMBER_OF_DUP_TSNS_LENGTH,    ENC_BIG_ENDIAN);

  a_rwnd = tvb_get_ntohl(chunk_tvb, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
  if (a_rwnd == 0)
      expert_add_info_format(pinfo, a_rwnd_item, PI_SEQUENCE, PI_NOTE, "Zero Advertised Receiver Window Credit");


  /* handle the gap acknowledgement blocks */
  number_of_gap_blocks = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET);
  gap_block_offset     = SACK_CHUNK_GAP_BLOCK_OFFSET;
  cum_tsn_ack          = tvb_get_ntohl(chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);

  acks_tree = proto_item_add_subtree(ctsa_item,ett_sctp_ack);
  sctp_ack_block(pinfo, ha, chunk_tvb, acks_tree, NULL, cum_tsn_ack);

  last_end = 0;
  for(gap_block_number = 1; gap_block_number <= number_of_gap_blocks; gap_block_number++) {
    proto_item *pi;
    proto_tree *pt;
    guint32 tsn_start;

    start = tvb_get_ntohs(chunk_tvb, gap_block_offset);
    end   = tvb_get_ntohs(chunk_tvb, gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH);
    tsn_start = cum_tsn_ack + start;

    block_item = proto_tree_add_text(chunk_tree, chunk_tvb, gap_block_offset, SACK_CHUNK_GAP_BLOCK_LENGTH, "Gap Acknowledgement for TSN %u to %u", cum_tsn_ack + start, cum_tsn_ack + end);
    block_tree = proto_item_add_subtree(block_item, ett_sctp_sack_chunk_gap_block);

    pi = proto_tree_add_item(block_tree, hf_sack_chunk_gap_block_start, chunk_tvb, gap_block_offset, SACK_CHUNK_GAP_BLOCK_START_LENGTH, ENC_BIG_ENDIAN);
    pt = proto_item_add_subtree(pi, ett_sctp_sack_chunk_gap_block_start);
    pi = proto_tree_add_uint(pt, hf_sack_chunk_gap_block_start_tsn,
                             chunk_tvb, gap_block_offset,SACK_CHUNK_GAP_BLOCK_START_LENGTH, cum_tsn_ack + start);
    PROTO_ITEM_SET_GENERATED(pi);

    pi = proto_tree_add_item(block_tree, hf_sack_chunk_gap_block_end, chunk_tvb, gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH, SACK_CHUNK_GAP_BLOCK_END_LENGTH,   ENC_BIG_ENDIAN);
    pt = proto_item_add_subtree(pi, ett_sctp_sack_chunk_gap_block_end);
    pi = proto_tree_add_uint(pt, hf_sack_chunk_gap_block_end_tsn, chunk_tvb,
                             gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH, SACK_CHUNK_GAP_BLOCK_END_LENGTH, cum_tsn_ack + end);
    PROTO_ITEM_SET_GENERATED(pi);

    sctp_ack_block(pinfo, ha, chunk_tvb, block_tree, &tsn_start, cum_tsn_ack + end);
    gap_block_offset += SACK_CHUNK_GAP_BLOCK_LENGTH;

    tsns_gap_acked += (end+1 - start);

    /* Check validity */
    if (start > end) {
       expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_ERROR, "Malformed gap block");
    }
    if (last_end > start) {
       expert_add_info_format(pinfo, pi, PI_PROTOCOL, PI_WARN, "Gap blocks not in strict order");
    }
    last_end = end;
  }

  if (tsns_gap_acked) {
    proto_item *pi;

    pi = proto_tree_add_uint(chunk_tree, hf_sack_chunk_number_tsns_gap_acked, chunk_tvb, 0, 0, tsns_gap_acked);
    PROTO_ITEM_SET_GENERATED(pi);

    /*  If there are a huge number of GAP ACKs, warn the user.  100 is a random
     *  number: it could be tuned.
     */
    if (tsns_gap_acked > 100)
      expert_add_info_format(pinfo, pi, PI_SEQUENCE, PI_WARN, "More than 100 TSNs were gap-acknowledged in this SACK");

  }


  /* handle the duplicate TSNs */
  number_of_dup_tsns = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET);
  dup_tsn_offset     = SACK_CHUNK_GAP_BLOCK_OFFSET + number_of_gap_blocks * SACK_CHUNK_GAP_BLOCK_LENGTH;
  for(dup_tsn_number = 1; dup_tsn_number <= number_of_dup_tsns; dup_tsn_number++) {
    proto_tree_add_item(chunk_tree, hf_sack_chunk_duplicate_tsn, chunk_tvb, dup_tsn_offset, SACK_CHUNK_DUP_TSN_LENGTH, ENC_BIG_ENDIAN);
    dup_tsn_offset += SACK_CHUNK_DUP_TSN_LENGTH;
  }

  proto_item_append_text(chunk_item, " (Cumulative TSN: %u, a_rwnd: %u, gaps: %u, duplicate TSNs: %u)",
                         tvb_get_ntohl(chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET),
                         a_rwnd,
                         number_of_gap_blocks, number_of_dup_tsns);
}
