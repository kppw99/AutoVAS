void CVE_2012_4293_VULN_proto_register_ecat_mailbox(void)
{
   static const true_false_string flags_set_truth =
   {
      "Set",
      "Not set"
   };

   static hf_register_info hf[] =
   {
      { &hf_ecat_mailboxlength,
      { "Length", "ecat_mailbox.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailboxaddress,
      { "Address", "ecat_mailbox.address",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe,
      { "EoE Fragment", "ecat_mailbox.eoe",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fraghead,
      { "Eoe Frag Header", "ecat_mailbox.eoe.fraghead",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_type,
      { "EoE"/*"Type*/, "ecat_mailbox.eoe.type",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fragno,
      { "EoE"/*"FragNo*/, "ecat_mailbox.eoe.fragno",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_offset,
      { "EoE"/*"Offset"*/, "ecat_mailbox.eoe.offset",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
      },
      { &hf_ecat_mailbox_eoe_frame,
      { "EoE"/*"FrameNo"*/, "ecat_mailbox.eoe.frame",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_last,
      { "Last Fragment"/*"Last Fragment"*/, "ecat_mailbox.eoe.last",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestampapp,
      { "Last Fragment"/*"Last Fragment"*/, "ecat_mailbox.eoe.timestampapp",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestampreq,
      { "Last Fragment"/*"Last Fragment"*/, "ecat_mailbox.eoe.timestampreq",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_fragment,
      { "EoE Frag Data", "ecat_mailbox.eoe.fragment",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init,
      { "Init", "ecat_mailbox.eoe.init",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_macaddr,
      { "MacAddr", "ecat_mailbox.eoe.init.contains_macaddr",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000001, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_ipaddr,
      { "IpAddr", "ecat_mailbox.eoe.init.contains_ipaddr",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000002, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_subnetmask,
      { "SubnetMask", "ecat_mailbox.eoe.init.contains_subnetmask",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000004, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_defaultgateway,
      { "DefaultGateway", "ecat_mailbox.eoe.init.contains_defaultgateway",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000008, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_dnsserver,
      { "DnsServer", "ecat_mailbox.eoe.init.contains_dnsserver",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000010, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_contains_dnsname,
      { "DnsName", "ecat_mailbox.eoe.init.contains_dnsname",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00000020, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_append_timestamp,
      { "AppendTimeStamp", "ecat_mailbox.eoe.init.append_timestamp",
      FT_BOOLEAN, 32, TFS(&flags_set_truth), 0x00010000, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_macaddr,
      { "Mac Addr", "ecat_mailbox.eoe.init.macaddr",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_ipaddr,
      { "Ip Addr", "ecat_mailbox.eoe.init.ipaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_subnetmask,
      { "Subnet Mask", "ecat_mailbox.eoe.init.subnetmask",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_defaultgateway,
      { "Default Gateway", "ecat_mailbox.eoe.init.defaultgateway",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_dnsserver,
      { "Dns Server", "ecat_mailbox.eoe.init.dnsserver",
      FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_init_dnsname,
      { "Dns Name", "ecat_mailbox.eoe.init.dnsname",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter,
      { "Mac Filter", "ecat_mailbox.eoe.macfilter",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_macfiltercount,
      { "Mac Filter Count", "ecat_mailbox.eoe.macfilter.macfiltercount",
      FT_UINT8, 16, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_maskcount,
      { "Mac Filter Mask Count", "ecat_mailbox.eoe.macfilter.maskcount",
      FT_UINT8, 16, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_nobroadcasts,
      { "No Broadcasts", "ecat_mailbox.eoe.macfilter.nobroadcasts",
      FT_BOOLEAN, BASE_NONE,  TFS(&flags_set_truth), 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filter,
      { "Filter", "ecat_mailbox.eoe.macfilter.filter",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[0],
      { "Filter 0", "ecat_mailbox.eoe.macfilter.filter0",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[1],
      { "Filter 1", "ecat_mailbox.eoe.macfilter.filter1",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[2],
      { "Filter 2", "ecat_mailbox.eoe.macfilter.filter2",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[3],
      { "Filter 3", "ecat_mailbox.eoe.macfilter.filter3",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[4],
      { "Filter 4", "ecat_mailbox.eoe.macfilter.filter4",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[5],
      { "Filter 5", "ecat_mailbox.eoe.macfilter.filter5",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[6],
      { "Filter 6", "ecat_mailbox.eoe.macfilter.filter6",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[7],
      { "Filter 7", "ecat_mailbox.eoe.macfilter.filter7",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[8],
      { "Filter 8", "ecat_mailbox.eoe.macfilter.filter8",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[9],
      { "Filter 9", "ecat_mailbox.eoe.macfilter.filter9",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[10],
      { "Filter 10", "ecat_mailbox.eoe.macfilter.filter10",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[11],
      { "Filter 11", "ecat_mailbox.eoe.macfilter.filter11",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[12],
      { "Filter 12", "ecat_mailbox.eoe.macfilter.filter12",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[13],
      { "Filter 13", "ecat_mailbox.eoe.macfilter.filter13",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[14],
      { "Filter 14", "ecat_mailbox.eoe.macfilter.filter14",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filters[15],
      { "Filter 15", "ecat_mailbox.eoe.macfilter.filter15",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermask,
      { "Filter Mask", "ecat_mailbox.eoe.macfilter.filtermask",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[0],
      { "Mask 0", "ecat_mailbox.eoe.macfilter.filtermask0",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[1],
      { "Mask 1", "ecat_mailbox.eoe.macfilter.filtermask1",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[2],
      { "Mask 2", "ecat_mailbox.eoe.macfilter.filtermask2",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_macfilter_filtermasks[3],
      { "Mask 3", "ecat_mailbox.eoe.macfilter.filtermask3",
      FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_eoe_timestamp,
      { "Time Stamp", "ecat_mailbox.eoe.timestamp",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe,
      { "CoE", "ecat_mailbox.coe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_number,
      { "Number", "ecat_mailbox.coe.number",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_type,
      { "Type", "ecat_mailbox.coe.type",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoreq,
      { "SDO Req", "ecat_mailbox.coe.sdoreq",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid,
      { "Initiate Download", "ecat_mailbox.coe.sdoccsid",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_sizeind,
      { "Size Ind.", "ecat_mailbox.coe.sdoccsid.sizeind",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000001,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_expedited,
      { "Expedited", "ecat_mailbox.coe.sdoccsid.expedited",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000002,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_size0,
      { "Bytes", "ecat_mailbox.coe.sdoccsid.size0",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000004,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_size1,
      { "Bytes", "ecat_mailbox.coe.sdoccsid.size1",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000008,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsid_complete,
      { "Access", "ecat_mailbox.coe.sdoccsid.complete",
      FT_BOOLEAN, 8, TFS(&tfs_complete), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds,
      { "Download Segment", "ecat_mailbox.coe.sdoccsds",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_lastseg,
      { "Last Segment", "ecat_mailbox.coe.sdoccsds.lastseg",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000001,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_size,
      { "Size", "ecat_mailbox.coe.sdoccsds.size",
      FT_UINT8, BASE_DEC, NULL, 0x0000000E,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsds_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsds.toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsiu,
      { "Init Upload", "ecat_mailbox.coe.sdoccsiu",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsiu_complete,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsiu_complete",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsus,
      { "Upload Segment", "ecat_mailbox.coe.sdoccsus",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoccsus_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoccsus_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },

      { &hf_ecat_mailbox_coe_sdoidx,
      { "Index", "ecat_mailbox.coe.sdoidx",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdosub,
      { "SubIndex", "ecat_mailbox.coe.sdosub",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata1,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdodata2,
      { "Data", "ecat_mailbox.coe.sdodata",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoldata,
      { "Data", "ecat_mailbox.coe.dsoldata",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdolength,
      { "Length", "ecat_mailbox.coe.sdolength",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoerror,
      { "SDO Error", "ecat_mailbox.coe.sdoerror",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdores,
      { "SDO Res", "ecat_mailbox.coe.sdores",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu,
      { "Initiate Upload Response", "ecat_mailbox.coe.sdoscsiu",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_sizeind,
      { "Size Ind.", "ecat_mailbox.coe.sdoscsiu_sizeind",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000001,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_expedited,
      { "Expedited", "ecat_mailbox.coe.sdoscsiu_expedited",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000002,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_size0,
      { "Bytes", "ecat_mailbox.coe.sdoscsiu_size0",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000004,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_size1,
      { "Bytes", "ecat_mailbox.coe.sdoscsiu_size1",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000008,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsiu_complete,
      { "Access", "ecat_mailbox.coe.sdoscsiu_complete",
      FT_BOOLEAN, 8, TFS(&tfs_complete), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsds,
      { "Download Segment Response", "ecat_mailbox.coe.sdoscsds",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsds_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoscsds_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus,
      { "Upload Segment", "ecat_mailbox.coe.sdoscsus",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_lastseg,
      { "Last Segment", "ecat_mailbox.coe.sdoscsus_lastseg",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000001,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_bytes,
      { "Bytes", "ecat_mailbox.coe.sdoscsus_bytes",
      FT_UINT8, BASE_DEC, NULL, 0x0000000E,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoscsus_toggle,
      { "Toggle Bit", "ecat_mailbox.coe.sdoscsus_toggle",
      FT_BOOLEAN, 8, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_coe_sdoinfoopcode,
      { "Info OpCode", "ecat_mailbox.coe.sdoinfoopcode",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfofrag,
      { "Info Frag Left", "ecat_mailbox.coe.sdoinfofrag",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfolisttype,
      { "Info List Type", "ecat_mailbox.coe.sdoinfolisttype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfolist,
      { "Info List", "ecat_mailbox.coe.sdoinfolist",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoindex,
      { "Info Obj Index", "ecat_mailbox.coe.sdoinfoindex",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfosubindex,
      { "Info Obj SubIdx", "ecat_mailbox.coe.sdoinfosubindex",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfovalueinfo,
      { "Info Obj SubIdx", "ecat_mailbox.coe.sdoinfovalueinfo",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoerrorcode,
      { "Info Error Code", "ecat_mailbox.coe.sdoinfoerrorcode",
      FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfodatatype,
      { "Info Data Type", "ecat_mailbox.coe.sdoinfodatatype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfomaxsub,
      { "Info Max SubIdx", "ecat_mailbox.coe.sdoinfomaxsub",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoobjcode,
      { "Info Obj Code", "ecat_mailbox.coe.sdoinfoobjcode",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoname,
      { "Info Name", "ecat_mailbox.coe.sdoinfoname",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfobitlen,
      { "Info Bit Len", "ecat_mailbox.coe.sdoinfobitlen",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfoobjaccess,
      { "Info Obj Access", "ecat_mailbox.coe.sdoinfoobjaccess",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfounittype,
      { "Info Data Type", "ecat_mailbox.coe.sdoinfounittype",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfodefaultvalue,
      { "Info Default Val", "ecat_mailbox.coe.sdoinfodefaultvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfominvalue,
      { "Info Min Val", "ecat_mailbox.coe.sdoinfominvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailbox_coe_sdoinfomaxvalue,
      { "Info Max Val", "ecat_mailbox.coe.sdoinfomaxvalue",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
      { &hf_ecat_mailboxdata,
      { "MB Data", "ecat_mailbox.data",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe,
      { "Foe", "ecat_mailbox.foe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_opmode,
      { "Foe OpMode", "ecat_mailbox.foe_opmode",
      FT_UINT8, BASE_HEX, VALS(FoEOpMode), 0x0, "Op modes", HFILL }
      },
      { &hf_ecat_mailbox_foe_filelength,
      { "Foe FileLength" , "ecat_mailbox.foe_filelength",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_filename,
      { "Foe FileName", "ecat_mailbox.foe_filename",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_packetno,
      { "Foe PacketNo", "ecat_mailbox.foe_packetno",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_errcode,
      { "Foe ErrorCode", "ecat_mailbox.foe_errcode",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_errtext,
      { "Foe ErrorString", "ecat_mailbox.foe_errtext",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_busydone,
      { "Foe BusyDone", "ecat_mailbox.foe_busydone",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_busyentire,
      { "Foe BusyEntire", "ecat_mailbox.foe_busyentire",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_data,
      { "Foe Data", "ecat_mailbox.foe_busydata",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw,
      { "Firmware", "ecat_mailbox.foe.efw",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_cmd,
      { "Cmd", "ecat_mailbox.foe.efw.cmd",
      FT_UINT16, BASE_HEX, VALS(FoEEfwCmd), 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_size,
      { "Size", "ecat_mailbox.foe.efw.size",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_addresslw,
      { "AddressLW", "ecat_mailbox.foe.efw.addresslw",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_addresshw,
      { "AddressHW", "ecat_mailbox.foe.efw.addresshw",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_foe_efw_data,
      { "Data", "ecat_mailbox.foe.efw.data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe,
      { "Soe", "ecat_mailbox.soe",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header,
      { "Soe Header", "ecat_mailbox.soe_header",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_opcode,
      { "SoE OpCode", "ecat_mailbox.soe_opcode",
      FT_UINT16, BASE_DEC, VALS(SoeOpcode), 0x00000007, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_incomplete,
      { "More Follows...", "ecat_mailbox.soe_header_incomplete",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000008, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_error,
      { "Error", "ecat_mailbox.soe_header_error",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000010,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_driveno,
      { "Drive No", "ecat_mailbox.soe_header_driveno",
      FT_UINT16, BASE_DEC, NULL, 0x000000e0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_datastate,
      { "Datastate", "ecat_mailbox.soe_header_datastate",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000100,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_name,
      { "Name", "ecat_mailbox.soe_header_name",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000200,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_attribute,
      { "Attribute", "ecat_mailbox.soe_header_attribute",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000400,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_unit,
      { "Unit", "ecat_mailbox.soe_header_unit",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00000800,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_min,
      { "Min", "ecat_mailbox.soe_header_min",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00001000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_max,
      { "Max", "ecat_mailbox.soe_header_max",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00002000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_value,
      { "Value", "ecat_mailbox.soe_header_value",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00004000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_header_reserved,
      { "Reserved", "ecat_mailbox.soe_header_reserved",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), 0x00008000,
      NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_idn,
      { "SoE IDN", "ecat_mailbox.soe_idn",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_data,
      { "SoE Data", "ecat_mailbox.soe_data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_frag,
      { "SoE FragLeft", "ecat_mailbox.soe_frag",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      },
      { &hf_ecat_mailbox_soe_error,
      { "SoE Error", "ecat_mailbox.soe_error",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
      }
   };

   static gint *ett[] =
   {
      &ett_ecat_mailbox,
      &ett_ecat_mailbox_eoe,
      &ett_ecat_mailbox_eoe_init,
      &ett_ecat_mailbox_eoe_macfilter,
      &ett_ecat_mailbox_eoe_macfilter_filter,
      &ett_ecat_mailbox_eoe_macfilter_filtermask,
      &ett_ecat_mailbox_coe,
      &ett_ecat_mailbox_sdo,
      &ett_ecat_mailbox_coe_sdoccs,
      &ett_ecat_mailbox_coe_sdoscs,
      &ett_ecat_mailbox_foe,
      &ett_ecat_mailbox_foe_efw,
      &ett_ecat_mailbox_soeflag,
      &ett_ecat_mailbox_soe,
      &ett_ecat_mailbox_fraghead,
      &ett_ecat_mailbox_header
   };

   proto_ecat_mailbox = proto_register_protocol("EtherCAT Mailbox Protocol",
      "ECAT_MAILBOX", "ecat_mailbox");
   proto_register_field_array(proto_ecat_mailbox, hf,array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   register_dissector("ecat_mailbox", dissect_ecat_mailbox, proto_ecat_mailbox);
}
