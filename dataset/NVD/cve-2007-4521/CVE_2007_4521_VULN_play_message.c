static int CVE_2007_4521_VULN_play_message(struct ast_channel *chan, struct ast_vm_user *vmu, struct vm_state *vms)
{
	BODY *body;
	char *header_content;
	char cid[256];
	char context[256];
	char origtime[32];
	char duration[16];
	char category[32];
	char todir[PATH_MAX];
	int res = 0;
	char *attachedfilefmt;
	char *temp;

	vms->starting = 0; 
	if(option_debug > 2)
		ast_log (LOG_DEBUG,"Before mail_fetchheaders, curmsg is: %d, imap messages is %lu\n",vms->curmsg, vms->msgArray[vms->curmsg]);
	if (vms->msgArray[vms->curmsg] == 0) {
		ast_log (LOG_WARNING,"Trying to access unknown message\n");
		return -1;
	}

	/* This will only work for new messages... */
	header_content = mail_fetchheader (vms->mailstream, vms->msgArray[vms->curmsg]);
	/* empty string means no valid header */
	if (ast_strlen_zero(header_content)) {
		ast_log (LOG_ERROR,"Could not fetch header for message number %ld\n",vms->msgArray[vms->curmsg]);
		return -1;
	}
	snprintf(todir, sizeof(todir), "%s%s/%s/tmp", VM_SPOOL_DIR, vmu->context, vmu->mailbox);
	make_gsm_file(vms->fn, vms->imapuser, todir, vms->curmsg);

	mail_fetchstructure (vms->mailstream,vms->msgArray[vms->curmsg],&body);
	
	/* We have the body, now we extract the file name of the first attachment. */
	if (body->nested.part->next && body->nested.part->next->body.parameter->value) {
		attachedfilefmt = ast_strdupa(body->nested.part->next->body.parameter->value);
	} else {
		ast_log(LOG_ERROR, "There is no file attached to this IMAP message.\n");
		return -1;
	}
	
	/* Find the format of the attached file */

	strsep(&attachedfilefmt, ".");
	if (!attachedfilefmt) {
		ast_log(LOG_ERROR, "File format could not be obtained from IMAP message attachment\n");
		return -1;
	}
	save_body(body, vms, "2", attachedfilefmt);

	adsi_message(chan, vms);
	if (!vms->curmsg)
		res = wait_file2(chan, vms, "vm-first");	/* "First" */
	else if (vms->curmsg == vms->lastmsg)
		res = wait_file2(chan, vms, "vm-last");		/* "last" */
	if (!res) {
		res = wait_file2(chan, vms, "vm-message");	/* "message" */
		if (vms->curmsg && (vms->curmsg != vms->lastmsg)) {
			if (!res)
				res = ast_say_number(chan, vms->curmsg + 1, AST_DIGIT_ANY, chan->language, (char *) NULL);
		}
	}

	/* Get info from headers!! */
	temp = get_header_by_tag(header_content, "X-Asterisk-VM-Caller-ID-Num:");

	if (temp)
		ast_copy_string(cid, temp, sizeof(cid)); 
	else 
		cid[0] = '\0';

	temp = get_header_by_tag(header_content, "X-Asterisk-VM-Context:");

	if (temp)
		ast_copy_string(context, temp, sizeof(context)); 
	else
		context[0] = '\0';

	temp = get_header_by_tag(header_content, "X-Asterisk-VM-Orig-time:");

	if (temp)
		ast_copy_string(origtime, temp, sizeof(origtime));
	else
		origtime[0] = '\0';

	temp = get_header_by_tag(header_content, "X-Asterisk-VM-Duration:");

	if (temp)
		ast_copy_string(duration,temp, sizeof(duration));
	else
		duration[0] = '\0';
	
	temp = get_header_by_tag(header_content, "X-Asterisk-VM-Category:");
	
	if (temp)
		ast_copy_string(category,temp, sizeof(category));
	else
		category[0] = '\0';

	/*if (!strncasecmp("macro",context,5))  Macro names in contexts are useless for our needs */
	/*	context = ast_variable_retrieve(msg_cfg, "message","macrocontext"); */
	if (res == '1')
		res = 0;

	if ((!res) && !ast_strlen_zero(category)) {
		res = play_message_category(chan, category);
	}

	if ((!res) && (ast_test_flag(vmu, VM_ENVELOPE)) && origtime[0] != '\0')
		res = play_message_datetime(chan, vmu, origtime, "IMAP_STORAGE");
	if ((!res) && (ast_test_flag(vmu, VM_SAYCID)) && cid[0] !='\0' && context[0] !='\0')
		res = play_message_callerid(chan, vms, cid, context, 0);

	if ((!res) && (ast_test_flag(vmu, VM_SAYDURATION)) && duration[0] != '\0')
		res = play_message_duration(chan, vms, duration, vmu->saydurationm);

	/* Allow pressing '1' to skip envelope / callerid */
	/* if (res == '1')
		res = 0;
	*/
	/*ast_config_destroy(msg_cfg);*/
	res = 0;

	if (!res) {
		vms->heard[vms->curmsg] = 1;
		res = wait_file(chan, vms, vms->fn);
	}
	DISPOSE(vms->curdir, vms->curmsg);
	DELETE(0, 0, vms->fn);
	return res;
}
