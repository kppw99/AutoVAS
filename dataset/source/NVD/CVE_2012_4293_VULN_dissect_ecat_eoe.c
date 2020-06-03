static void CVE_2012_4293_VULN_dissect_ecat_eoe(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
   proto_tree *ecat_eoe_tree = 0, *ecat_fraghead_tree, *ecat_eoe_init_tree, *ecat_eoe_macfilter_tree,
      *ecat_eoe_macfilter_filter_tree;
   tvbuff_t *next_tvb;
   proto_item *anItem = NULL, *aparent = NULL;
   char szText[200];
   int nMax = sizeof(szText)-1;
   int nCnt;

   guint eoe_length = tvb_reported_length(tvb)-offset;

   if( tree )
   {
      anItem = proto_tree_add_item(tree, hf_ecat_mailbox_eoe, tvb, offset, eoe_length, ENC_NA);
      proto_item_set_text(anItem, "EoE Fragment");

      aparent = proto_item_get_parent(anItem);
      proto_item_append_text(aparent,":EoE ");
   }

   if( eoe_length >= ETHERCAT_EOE_HEADER_LEN )
   {
      ETHERCAT_EOE_HEADER eoe;
      init_eoe_header(&eoe, tvb, offset);
      if ( eoe.anEoeHeaderInfoUnion.v.Type == EOE_TYPE_FRAME_FRAG )
         g_snprintf ( szText, nMax, "EoE-Frag %d", eoe.anEoeHeaderDataUnion.v.Fragment);
      else
         g_snprintf ( szText, nMax, "EoE");
         col_append_str(pinfo->cinfo, COL_INFO, szText);

      { /* Do the following even 'if (tree == NULL)' since a call_dissector() is done */
         ecat_eoe_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe);

         anItem = proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_fraghead, tvb, offset, 4, ENC_NA);
         proto_item_set_text(anItem, "Header");
         ecat_fraghead_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_fraghead);

         anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_type, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.Type);
         EoETypeFormatter(&eoe, szText, nMax);
         proto_item_set_text(anItem, "%s", szText);

         switch ( eoe.anEoeHeaderInfoUnion.v.Type )
         {
         case EOE_TYPE_FRAME_FRAG:
            anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_fragno, tvb, offset, 4, eoe.anEoeHeaderDataUnion.v.Fragment);
            EoEFragNoFormatter(&eoe, szText, nMax);
            proto_item_set_text(anItem, "%s", szText);

            anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_offset, tvb, offset, 4, 32*eoe.anEoeHeaderDataUnion.v.OffsetBuffer);
            EoEOffsetFormatter(&eoe, szText, nMax);
            proto_item_set_text(anItem, "%s", szText);

            anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_frame, tvb, offset, 4, eoe.anEoeHeaderDataUnion.v.FrameNo);
            EoEFrameFormatter(&eoe, szText, nMax);
            proto_item_set_text(anItem, "%s", szText);

            anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_last, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.LastFragment);
            EoELastFormatter(&eoe, szText, nMax);
            proto_item_set_text(anItem, "%s", szText);

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampRequested )
            {
               anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_timestampreq, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.TimeStampRequested);
               proto_item_set_text(anItem, "Time Stamp Requested");
            }

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampAppended )
            {
               anItem = proto_tree_add_uint(ecat_fraghead_tree, hf_ecat_mailbox_eoe_timestampapp, tvb, offset, 4, eoe.anEoeHeaderInfoUnion.v.TimeStampAppended);
               proto_item_set_text(anItem, "Time Stamp Appended");
            }

            offset+=ETHERCAT_EOE_HEADER_LEN;
            proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_fragment, tvb, offset, eoe_length-offset, ENC_NA);

            if ( eoe.anEoeHeaderDataUnion.v.Fragment == 0 )
            {
               next_tvb = tvb_new_subset(tvb, offset, eoe_length-offset, eoe_length-offset);
               call_dissector( eth_handle, next_tvb, pinfo, ecat_eoe_tree);
            }

            if ( eoe.anEoeHeaderInfoUnion.v.TimeStampAppended )
            {
               proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_timestamp, tvb, eoe_length-ETHERCAT_EOE_TIMESTAMP_LEN, ETHERCAT_EOE_TIMESTAMP_LEN, ENC_LITTLE_ENDIAN);
            }
            break;

         case EOE_TYPE_TIMESTAMP_RES:
            proto_tree_add_item(ecat_eoe_tree, hf_ecat_mailbox_eoe_timestamp, tvb, offset+ETHERCAT_EOE_HEADER_LEN, ETHERCAT_EOE_TIMESTAMP_LEN, ENC_LITTLE_ENDIAN);
            break;

         case EOE_TYPE_INIT_REQ:
            offset+=ETHERCAT_EOE_HEADER_LEN;
            anItem = proto_tree_add_item(ecat_fraghead_tree, hf_ecat_mailbox_eoe_init, tvb, offset, MIN(eoe_length-offset,ETHERCAT_EOE_INIT_LEN), ENC_NA);
            if( eoe_length-offset >= ETHERCAT_EOE_INIT_LEN )
            {
               ecat_eoe_init_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_init);

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_macaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_ipaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_subnetmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_defaultgateway, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_dnsserver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_contains_dnsname, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_append_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_macaddr, tvb, offset, ETHERNET_ADDRESS_LEN, ENC_NA);
               offset+=ETHERNET_ADDRESS_LEN;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_ipaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_subnetmask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_defaultgateway, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_dnsserver, tvb, offset, 4, ENC_LITTLE_ENDIAN);
               offset+=4;

               proto_tree_add_item(ecat_eoe_init_tree, hf_ecat_mailbox_eoe_init_dnsname, tvb, offset, 32, ENC_ASCII|ENC_NA);
            }
            else
               proto_item_append_text(anItem, " - Invalid length!");
            break;

         case EOE_TYPE_MACFILTER_REQ:
            {
               EoeMacFilterOptionsUnion options;
               offset+=ETHERCAT_EOE_HEADER_LEN;
               anItem = proto_tree_add_item(ecat_fraghead_tree, hf_ecat_mailbox_eoe_macfilter, tvb, offset, MIN(eoe_length-offset, ETHERCAT_EOE_MACFILTER_LEN), ENC_NA);
               if( eoe_length-offset >= ETHERCAT_EOE_MACFILTER_LEN )
               {
                  proto_tree *ecat_eoe_macfilter_filtermask_tree;

                  ecat_eoe_macfilter_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter);
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_macfiltercount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_maskcount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_nobroadcasts, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                  options.Options = tvb_get_letohs(tvb, offset);
                  offset+=4;

                  anItem = proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_filter, tvb, offset, 16*ETHERNET_ADDRESS_LEN, ENC_NA);
                  ecat_eoe_macfilter_filter_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter_filter);
                  for( nCnt=0; nCnt<options.v.MacFilterCount; nCnt++)
                     proto_tree_add_item(ecat_eoe_macfilter_filter_tree, hf_ecat_mailbox_eoe_macfilter_filters[nCnt], tvb, offset+nCnt*ETHERNET_ADDRESS_LEN, ETHERNET_ADDRESS_LEN, ENC_NA);
                  offset+=16*ETHERNET_ADDRESS_LEN;

                  anItem = proto_tree_add_item(ecat_eoe_macfilter_tree, hf_ecat_mailbox_eoe_macfilter_filtermask, tvb, offset, 4*sizeof(guint32), ENC_NA);
                  ecat_eoe_macfilter_filtermask_tree = proto_item_add_subtree(anItem, ett_ecat_mailbox_eoe_macfilter_filtermask);
                  for( nCnt=0; nCnt<options.v.MacFilterMaskCount; nCnt++)
                     proto_tree_add_item(ecat_eoe_macfilter_filtermask_tree, hf_ecat_mailbox_eoe_macfilter_filtermasks[nCnt], tvb, offset+nCnt*sizeof(guint32), sizeof(guint32), ENC_NA);
               }
               else
                  proto_item_append_text(anItem, " - Invalid length!");
            }
            break;

         case EOE_TYPE_INIT_RES:
         case EOE_TYPE_MACFILTER_RES:
            break;
         }
      }

      col_prepend_fstr(pinfo->cinfo, COL_INFO, "EoE(");

      col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "EoE-");
   }
   else
   {
      col_append_str(pinfo->cinfo, COL_INFO, "EoE - invalid length!");
   }
}
