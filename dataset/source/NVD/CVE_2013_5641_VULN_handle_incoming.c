 * called with p and p->owner locked
 */
static int CVE_2013_5641_VULN_handle_incoming(struct sip_pvt *p, struct sip_request *req, struct ast_sockaddr *addr, int *recount, int *nounlock)
{
	/* Called with p->lock held, as well as p->owner->lock if appropriate, keeping things
	   relatively static */
	const char *cmd;
	const char *cseq;
	const char *useragent;
	const char *via;
	const char *callid;
	int via_pos = 0;
	uint32_t seqno;
	int len;
	int respid;
	int res = 0;
	const char *e;
	int error = 0;
	int oldmethod = p->method;
	int acked = 0;

	/* RFC 3261 - 8.1.1 A valid SIP request must contain To, From, CSeq, Call-ID and Via.
	 * 8.2.6.2 Response must have To, From, Call-ID CSeq, and Via related to the request,
	 * so we can check to make sure these fields exist for all requests and responses */
	cseq = sip_get_header(req, "Cseq");
	cmd = REQ_OFFSET_TO_STR(req, header[0]);
	/* Save the via_pos so we can check later that responses only have 1 Via header */
	via = __get_header(req, "Via", &via_pos);
	/* This must exist already because we've called find_call by now */
	callid = sip_get_header(req, "Call-ID");

	/* Must have Cseq */
	if (ast_strlen_zero(cmd) || ast_strlen_zero(cseq) || ast_strlen_zero(via)) {
		ast_log(LOG_ERROR, "Dropping this SIP message with Call-ID '%s', it's incomplete.\n", callid);
		error = 1;
	}
	if (!error && sscanf(cseq, "%30u%n", &seqno, &len) != 1) {
		ast_log(LOG_ERROR, "No seqno in '%s'. Dropping incomplete message.\n", cmd);
		error = 1;
	}
	if (error) {
		if (!p->initreq.headers) {	/* New call */
			pvt_set_needdestroy(p, "no headers");
		}
		return -1;
	}
	/* Get the command XXX */

	cmd = REQ_OFFSET_TO_STR(req, rlpart1);
	e = ast_skip_blanks(REQ_OFFSET_TO_STR(req, rlpart2));

	/* Save useragent of the client */
	useragent = sip_get_header(req, "User-Agent");
	if (!ast_strlen_zero(useragent))
		ast_string_field_set(p, useragent, useragent);

	/* Find out SIP method for incoming request */
	if (req->method == SIP_RESPONSE) {	/* Response to our request */
		/* ignore means "don't do anything with it" but still have to
		 * respond appropriately.
		 * But in this case this is a response already, so we really
		 * have nothing to do with this message, and even setting the
		 * ignore flag is pointless.
		 */
		if (ast_strlen_zero(e)) {
			return 0;
		}
		if (sscanf(e, "%30d %n", &respid, &len) != 1) {
			ast_log(LOG_WARNING, "Invalid response: '%s'\n", e);
			return 0;
		}
		if (respid <= 0) {
			ast_log(LOG_WARNING, "Invalid SIP response code: '%d'\n", respid);
			return 0;
		}
		/* RFC 3261 - 8.1.3.3 If more than one Via header field value is present in a reponse
		 * the UAC SHOULD discard the message. This is not perfect, as it will not catch multiple
		 * headers joined with a comma. Fixing that would pretty much involve writing a new parser */
		if (!ast_strlen_zero(__get_header(req, "via", &via_pos))) {
			ast_log(LOG_WARNING, "Misrouted SIP response '%s' with Call-ID '%s', too many vias\n", e, callid);
			return 0;
		}
		if (p->ocseq && (p->ocseq < seqno)) {
			ast_debug(1, "Ignoring out of order response %u (expecting %u)\n", seqno, p->ocseq);
			return -1;
		} else {
			if ((respid == 200) || ((respid >= 300) && (respid <= 399))) {
				extract_uri(p, req);
			}

			if (p->owner) {
				struct ast_control_pvt_cause_code *cause_code;
				int data_size = sizeof(*cause_code);
				/* size of the string making up the cause code is "SIP " + cause length */
				data_size += 4 + strlen(REQ_OFFSET_TO_STR(req, rlpart2));
				cause_code = ast_alloca(data_size);

				ast_copy_string(cause_code->chan_name, ast_channel_name(p->owner), AST_CHANNEL_NAME);

				snprintf(cause_code->code, data_size - sizeof(*cause_code) + 1, "SIP %s", REQ_OFFSET_TO_STR(req, rlpart2));

				cause_code->ast_cause = hangup_sip2cause(respid);
				if (global_store_sip_cause) {
					cause_code->emulate_sip_cause = 1;
				}

				ast_queue_control_data(p->owner, AST_CONTROL_PVT_CAUSE_CODE, cause_code, data_size);
				ast_channel_hangupcause_hash_set(p->owner, cause_code, data_size);
			}

			handle_response(p, respid, e + len, req, seqno);
		}
		return 0;
	}

	/* New SIP request coming in
	   (could be new request in existing SIP dialog as well...)
	 */
	p->method = req->method;	/* Find out which SIP method they are using */
	ast_debug(4, "**** Received %s (%d) - Command in SIP %s\n", sip_methods[p->method].text, sip_methods[p->method].id, cmd);

	if (p->icseq && (p->icseq > seqno) ) {
		if (p->pendinginvite && seqno == p->pendinginvite && (req->method == SIP_ACK || req->method == SIP_CANCEL)) {
			ast_debug(2, "Got CANCEL or ACK on INVITE with transactions in between.\n");
		} else {
			ast_debug(1, "Ignoring too old SIP packet packet %u (expecting >= %u)\n", seqno, p->icseq);
			if (req->method == SIP_INVITE) {
				unsigned int ran = (ast_random() % 10) + 1;
				char seconds[4];
				snprintf(seconds, sizeof(seconds), "%u", ran);
				transmit_response_with_retry_after(p, "500 Server error", req, seconds);	/* respond according to RFC 3261 14.2 with Retry-After betwewn 0 and 10 */
			} else if (req->method != SIP_ACK) {
				transmit_response(p, "500 Server error", req);	/* We must respond according to RFC 3261 sec 12.2 */
			}
			return -1;
		}
	} else if (p->icseq &&
		   p->icseq == seqno &&
		   req->method != SIP_ACK &&
		   (p->method != SIP_CANCEL || p->alreadygone)) {
		/* ignore means "don't do anything with it" but still have to
		   respond appropriately.  We do this if we receive a repeat of
		   the last sequence number  */
		req->ignore = 1;
		ast_debug(3, "Ignoring SIP message because of retransmit (%s Seqno %u, ours %u)\n", sip_methods[p->method].text, p->icseq, seqno);
	}

	/* RFC 3261 section 9. "CANCEL has no effect on a request to which a UAS has
	 * already given a final response." */
	if (!p->pendinginvite && (req->method == SIP_CANCEL)) {
		transmit_response(p, "481 Call/Transaction Does Not Exist", req);
		return res;
	}

	if (seqno >= p->icseq)
		/* Next should follow monotonically (but not necessarily
		   incrementally -- thanks again to the genius authors of SIP --
		   increasing */
		p->icseq = seqno;

	/* Find their tag if we haven't got it */
	if (ast_strlen_zero(p->theirtag)) {
		char tag[128];

		gettag(req, "From", tag, sizeof(tag));
		ast_string_field_set(p, theirtag, tag);
	}
	snprintf(p->lastmsg, sizeof(p->lastmsg), "Rx: %s", cmd);

	if (sip_cfg.pedanticsipchecking) {
		/* If this is a request packet without a from tag, it's not
			correct according to RFC 3261  */
		/* Check if this a new request in a new dialog with a totag already attached to it,
			RFC 3261 - section 12.2 - and we don't want to mess with recovery  */
		if (!p->initreq.headers && req->has_to_tag) {
			/* If this is a first request and it got a to-tag, it is not for us */
			if (!req->ignore && req->method == SIP_INVITE) {
				/* Just because we think this is a dialog-starting INVITE with a to-tag
				 * doesn't mean it actually is. It could be a reinvite for an established, but
				 * unknown dialog. In such a case, we need to change our tag to the
				 * incoming INVITE's to-tag so that they will recognize the 481 we send and
				 * so that we will properly match their incoming ACK.
				 */
				char totag[128];
				gettag(req, "To", totag, sizeof(totag));
				ast_string_field_set(p, tag, totag);
				p->pendinginvite = p->icseq;
				transmit_response_reliable(p, "481 Call/Transaction Does Not Exist", req);
				/* Will cease to exist after ACK */
				return res;
			} else if (req->method != SIP_ACK) {
				transmit_response(p, "481 Call/Transaction Does Not Exist", req);
				sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
				return res;
			}
			/* Otherwise, this is an ACK. It will always have a to-tag */
		}
	}

	if (!e && (p->method == SIP_INVITE || p->method == SIP_SUBSCRIBE || p->method == SIP_REGISTER || p->method == SIP_NOTIFY || p->method == SIP_PUBLISH)) {
		transmit_response(p, "400 Bad request", req);
		sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
		return -1;
	}

	/* Handle various incoming SIP methods in requests */
	switch (p->method) {
	case SIP_OPTIONS:
		res = handle_request_options(p, req, addr, e);
		break;
	case SIP_INVITE:
		res = handle_request_invite(p, req, addr, seqno, recount, e, nounlock);

		if (res < 9) {
			sip_report_security_event(p, req, res);
		}

		switch (res) {
		case INV_REQ_SUCCESS:
			res = 1;
			break;
		case INV_REQ_FAILED:
			res = 0;
			break;
		case INV_REQ_ERROR:
			res = -1;
			break;
		default:
			res = 0;
			break;
		}

		break;
	case SIP_REFER:
		res = handle_request_refer(p, req, seqno, nounlock);
		break;
	case SIP_CANCEL:
		res = handle_request_cancel(p, req);
		break;
	case SIP_BYE:
		res = handle_request_bye(p, req);
		break;
	case SIP_MESSAGE:
		res = handle_request_message(p, req, addr, e);
		break;
	case SIP_PUBLISH:
		res = handle_request_publish(p, req, addr, seqno, e);
		break;
	case SIP_SUBSCRIBE:
		res = handle_request_subscribe(p, req, addr, seqno, e);
		break;
	case SIP_REGISTER:
		res = handle_request_register(p, req, addr, e);
		sip_report_security_event(p, req, res);
		break;
	case SIP_INFO:
		if (req->debug)
			ast_verbose("Receiving INFO!\n");
		if (!req->ignore)
			handle_request_info(p, req);
		else  /* if ignoring, transmit response */
			transmit_response(p, "200 OK", req);
		break;
	case SIP_NOTIFY:
		res = handle_request_notify(p, req, addr, seqno, e);
		break;
	case SIP_UPDATE:
		res = handle_request_update(p, req);
		break;
	case SIP_ACK:
		/* Make sure we don't ignore this */
		if (seqno == p->pendinginvite) {
			p->invitestate = INV_TERMINATED;
			p->pendinginvite = 0;
			acked = __sip_ack(p, seqno, 1 /* response */, 0);
			if (find_sdp(req)) {
				if (process_sdp(p, req, SDP_T38_NONE)) {
					return -1;
				}
				if (ast_test_flag(&p->flags[0], SIP_DIRECT_MEDIA)) {
					ast_queue_control(p->owner, AST_CONTROL_SRCCHANGE);
				}
			}
			check_pendings(p);
		} else if (p->glareinvite == seqno) {
			/* handle ack for the 491 pending sent for glareinvite */
			p->glareinvite = 0;
			acked = __sip_ack(p, seqno, 1, 0);
		}
		if (!acked) {
			/* Got an ACK that did not match anything. Ignore
			 * silently and restore previous method */
			p->method = oldmethod;
		}
		if (!p->lastinvite && ast_strlen_zero(p->nonce)) {
			pvt_set_needdestroy(p, "unmatched ACK");
		}
		break;
	default:
		transmit_response_with_allow(p, "501 Method Not Implemented", req, 0);
		ast_log(LOG_NOTICE, "Unknown SIP command '%s' from '%s'\n",
			cmd, ast_sockaddr_stringify(&p->sa));
		/* If this is some new method, and we don't have a call, destroy it now */
		if (!p->initreq.headers) {
			pvt_set_needdestroy(p, "unimplemented method");
		}
		break;
	}
	return res;
}
