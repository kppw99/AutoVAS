static void
CVE_2013_4081_VULN_http_payload_subdissector(tvbuff_t *tvb, proto_tree *tree,
			  packet_info *pinfo, http_conv_t *conv_data)
{
	guint32 *ptr = NULL;
 	guint32 dissect_as, saved_port;
	gchar **strings; /* An array for splitting the request URI into hostname and port */
	proto_item *item;
	proto_tree *proxy_tree;

	/* Grab the destination port number from the request URI to find the right subdissector */
	strings = g_strsplit(conv_data->request_uri, ":", 2);

	if(strings[0] != NULL && strings[1] != NULL) {
		/*
		 * The string was successfully split in two
		 * Create a proxy-connect subtree
		 */
		if(tree) {
			item = proto_tree_add_item(tree, proto_http, tvb, 0, -1, ENC_NA);
			proxy_tree = proto_item_add_subtree(item, ett_http);

			item = proto_tree_add_string(proxy_tree, hf_http_proxy_connect_host,
						     tvb, 0, 0, strings[0]);
			PROTO_ITEM_SET_GENERATED(item);

			item = proto_tree_add_uint(proxy_tree, hf_http_proxy_connect_port,
						   tvb, 0, 0, strtol(strings[1], NULL, 10) );
			PROTO_ITEM_SET_GENERATED(item);
		}

		/* We're going to get stuck in a loop if we let process_tcp_payload call
		   us, so call the data dissector instead for proxy connections to http ports. */
		dissect_as = (int)strtol(strings[1], NULL, 10); /* Convert string to a base-10 integer */

		if (value_is_in_range(http_tcp_range, dissect_as)) {
			call_dissector(data_handle, tvb, pinfo, tree);
		} else {
			/* set pinfo->{src/dst port} and call the TCP sub-dissector lookup */
			if ( !ptr && value_is_in_range(http_tcp_range, pinfo->destport) )
				ptr = &pinfo->destport;
			else
				ptr = &pinfo->srcport;

			/* Increase pinfo->can_desegment because we are traversing
			 * http and want to preserve desegmentation functionality for
       			 * the proxied protocol
			 */
			if( pinfo->can_desegment>0 )
				pinfo->can_desegment++;

			saved_port = *ptr;
			*ptr = dissect_as;
			decode_tcp_ports(tvb, 0, pinfo, tree,
				pinfo->srcport, pinfo->destport, NULL);
			*ptr = saved_port;
		}
	}
	g_strfreev(strings); /* Free the result of g_strsplit() above */
}
