static int CVE_2014_8416_VULN_refer_incoming_invite_request(struct ast_sip_session *session, struct pjsip_rx_data *rdata)
{
	pjsip_dialog *other_dlg = NULL;
	pjsip_tx_data *packet;
	int response = 0;
	RAII_VAR(struct ast_sip_session *, other_session, NULL, ao2_cleanup);
	struct invite_replaces invite;

	/* If a Replaces header is present make sure it is valid */
	if (pjsip_replaces_verify_request(rdata, &other_dlg, PJ_TRUE, &packet) != PJ_SUCCESS) {
		response = packet->msg->line.status.code;
		pjsip_tx_data_dec_ref(packet);
		goto end;
	}

	/* If no other dialog exists then this INVITE request does not have a Replaces header */
	if (!other_dlg) {
		return 0;
	}

	other_session = ast_sip_dialog_get_session(other_dlg);
	pjsip_dlg_dec_lock(other_dlg);

	if (!other_session) {
		response = 481;
		ast_debug(3, "INVITE with Replaces received on channel '%s' from endpoint '%s', but requested session does not exist\n",
			ast_channel_name(session->channel), ast_sorcery_object_get_id(session->endpoint));
		goto end;
	}

	invite.session = other_session;

	if (ast_sip_push_task_synchronous(other_session->serializer, invite_replaces, &invite)) {
		response = 481;
		goto end;
	}

	ast_channel_lock(session->channel);
	ast_setstate(session->channel, AST_STATE_RING);
	ast_channel_unlock(session->channel);
	ast_raw_answer(session->channel);

	if (!invite.bridge) {
		struct ast_channel *chan = session->channel;

		/* This will use a synchronous task but we aren't operating in the serializer at this point in time, so it
		 * won't deadlock */
		if (!ast_channel_move(invite.channel, session->channel)) {
			ast_hangup(chan);
		} else {
			response = 500;
		}
	} else {
		if (ast_bridge_impart(invite.bridge, session->channel, invite.channel, NULL,
			AST_BRIDGE_IMPART_CHAN_INDEPENDENT)) {
			response = 500;
		}
	}

	if (!response) {
		ast_debug(3, "INVITE with Replaces successfully completed on channels '%s' and '%s'\n",
			ast_channel_name(session->channel), ast_channel_name(invite.channel));
	}

	ast_channel_unref(invite.channel);
	ao2_cleanup(invite.bridge);

end:
	if (response) {
		ast_debug(3, "INVITE with Replaces failed on channel '%s', sending response of '%d'\n",
			ast_channel_name(session->channel), response);
		session->defer_terminate = 1;
		ast_hangup(session->channel);
		session->channel = NULL;

		if (pjsip_inv_end_session(session->inv_session, response, NULL, &packet) == PJ_SUCCESS) {
			ast_sip_session_send_response(session, packet);
		}
	}

	return 1;
}
