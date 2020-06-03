static void
CVE_2014_2282_VULN_dissect_protocol_data_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 ulp_length;
  tvbuff_t *payload_tvb;
  proto_item *item, *gen_item;
  mtp3_tap_rec_t* mtp3_tap = ep_new0(mtp3_tap_rec_t);
  proto_tree *q708_tree;
  gint heuristic_standard;
  guint8 si;
  guint32 opc, dpc;

  si = tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET);
  ulp_length  = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - DATA_HDR_LENGTH;
  payload_tvb = tvb_new_subset(parameter_tvb, DATA_ULP_OFFSET, ulp_length, ulp_length);
  dpc = tvb_get_ntohl(parameter_tvb, DATA_DPC_OFFSET);
  opc = tvb_get_ntohl(parameter_tvb, DATA_OPC_OFFSET);

  m3ua_pref_mtp3_standard = mtp3_standard;

  if (mtp3_heuristic_standard) {
      heuristic_standard = m3ua_heur_mtp3_standard(payload_tvb, pinfo, opc, dpc, si);
      if (heuristic_standard == HEURISTIC_FAILED_STANDARD) {
	  gen_item = proto_tree_add_text(tree, parameter_tvb, 0, 0, "Could not determine Heuristic using %s", val_to_str_const(mtp3_standard, mtp3_standard_vals, "unknown"));
      } else {
	  gen_item = proto_tree_add_text(tree, parameter_tvb, 0, 0, "%s", val_to_str_const(heuristic_standard, mtp3_standard_vals, "unknown"));

	  mtp3_standard = heuristic_standard;

	  /* Register a frame-end routine to ensure mtp3_standard is set
	   * back even if an exception is thrown.
	   */
	  register_frame_end_routine(pinfo, m3ua_reset_mtp3_standard);
      }
      PROTO_ITEM_SET_GENERATED(gen_item);
  }

  mtp3_tap->addr_dpc.type = (Standard_Type)mtp3_standard;
  mtp3_tap->addr_dpc.pc = dpc;
  mtp3_tap->addr_dpc.ni = tvb_get_guint8(parameter_tvb, DATA_NI_OFFSET);
  SET_ADDRESS(&pinfo->dst, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) &mtp3_tap->addr_dpc);


  mtp3_tap->addr_opc.type = (Standard_Type)mtp3_standard;
  mtp3_tap->addr_opc.pc = opc;
  mtp3_tap->addr_opc.ni = tvb_get_guint8(parameter_tvb, DATA_NI_OFFSET);
  SET_ADDRESS(&pinfo->src, AT_SS7PC, sizeof(mtp3_addr_pc_t), (guint8 *) &mtp3_tap->addr_opc);

  mtp3_tap->si_code = tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET);
  mtp3_tap->size = 0;

  tap_queue_packet(m3ua_tap, pinfo, mtp3_tap);

  ulp_length  = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - DATA_HDR_LENGTH;

  if (parameter_tree) {
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_opc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(opc));
    if(mtp3_tap->addr_opc.ni == MTP3_NI_INT0) {
        q708_tree = proto_item_add_subtree(item,ett_q708_opc);
        /*  Q.708 (1984-10)  Numbering of International Signalling Point Codes  */
        analyze_q708_ispc(parameter_tvb, q708_tree, DATA_OPC_OFFSET, DATA_OPC_LENGTH, opc);
    }

    item = proto_tree_add_item(parameter_tree, hf_protocol_data_dpc, parameter_tvb, DATA_DPC_OFFSET, DATA_DPC_LENGTH, ENC_BIG_ENDIAN);
    if (mtp3_pc_structured())
      proto_item_append_text(item, " (%s)", mtp3_pc_to_str(dpc));
    if(mtp3_tap->addr_dpc.ni == MTP3_NI_INT0) {
        q708_tree = proto_item_add_subtree(item,ett_q708_dpc);
        analyze_q708_ispc(parameter_tvb, q708_tree, DATA_DPC_OFFSET, DATA_DPC_LENGTH, dpc);
    }

    proto_tree_add_item(parameter_tree, hf_protocol_data_si,  parameter_tvb, DATA_SI_OFFSET,  DATA_SI_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_ni,  parameter_tvb, DATA_NI_OFFSET,  DATA_NI_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_mp,  parameter_tvb, DATA_MP_OFFSET,  DATA_MP_LENGTH,  ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_protocol_data_sls, parameter_tvb, DATA_SLS_OFFSET, DATA_SLS_LENGTH, ENC_BIG_ENDIAN);

    proto_item_append_text(parameter_item, " (SS7 message of %u byte%s)", ulp_length, plurality(ulp_length, "", "s"));
    proto_item_set_len(parameter_item, PARAMETER_HEADER_LENGTH + DATA_HDR_LENGTH);

    item = proto_tree_add_text(parameter_tree,parameter_tvb,0,0,"MTP3 equivalents");
    PROTO_ITEM_SET_GENERATED(item);
    parameter_tree = proto_item_add_subtree(item,ett_mtp3_equiv);

    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_opc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_dpc, parameter_tvb, DATA_DPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_pc, parameter_tvb, DATA_OPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_pc, parameter_tvb, DATA_DPC_OFFSET, DATA_OPC_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_ni,  parameter_tvb, DATA_NI_OFFSET,  DATA_NI_LENGTH,  ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_item(parameter_tree, hf_protocol_data_mtp3_sls, parameter_tvb, DATA_SLS_OFFSET, DATA_SLS_LENGTH, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);

  }/* parameter_tree */

  payload_tvb = tvb_new_subset(parameter_tvb, DATA_ULP_OFFSET, ulp_length, ulp_length);
  if (!dissector_try_uint(si_dissector_table, tvb_get_guint8(parameter_tvb, DATA_SI_OFFSET), payload_tvb, pinfo, tree))
    call_dissector(data_handle, payload_tvb, pinfo, tree);

  mtp3_standard = m3ua_pref_mtp3_standard;
}
