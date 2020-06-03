static void
CVE_2013_4081_PATCHED_http_payload_subdissector(tvbuff_t *tvb, proto_tree *tree,
			  packet_info *pinfo, http_conv_t *conv_data)
{
	guint32 *ptr = NULL;
 	guint32 uri_port, saved_port, srcport, destport;
	gchar **strings; /* An array for splitting the request URI into hostname and port */
	proto_item *item;
	proto_tree *proxy_tree;
	conversation_t *conv;

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

		uri_port = (int)strtol(strings[1], NULL, 10); /* Convert string to a base-10 integer */

		if (value_is_in_range(http_tcp_range, pinfo->destport)) {
			srcport = pinfo->srcport;
			destport = uri_port;
		} else {
			srcport = uri_port;
			destport = pinfo->destport;
		}

		conv = find_conversation(PINFO_FD_NUM(pinfo), &pinfo->src, &pinfo->dst, PT_TCP, srcport, destport, 0);

		/* We may get stuck in a recursion loop if we let process_tcp_payload() call us.
		 * So, if the port in the URI is one we're registered for or we have set up a
		 * conversation (e.g., one we detected heuristically or via Decode-As) call the data
		 * dissector directly.
		 */
		if (value_is_in_range(http_tcp_range, uri_port) || (conv && conv->dissector_handle == http_handle)) {
			call_dissector(data_handle, tvb, pinfo, tree);
		} else {
			/* set pinfo->{src/dst port} and call the TCP sub-dissector lookup */
			if (value_is_in_range(http_tcp_range, pinfo->destport))
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
			*ptr = uri_port;
			decode_tcp_ports(tvb, 0, pinfo, tree,
				pinfo->srcport, pinfo->destport, NULL);
			*ptr = saved_port;
		}
	}
	g_strfreev(strings); /* Free the result of g_strsplit() above */
}
