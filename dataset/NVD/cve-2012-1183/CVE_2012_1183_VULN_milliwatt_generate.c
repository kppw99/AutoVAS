static int CVE_2012_1183_VULN_milliwatt_generate(struct ast_channel *chan, void *data, int len, int samples)
{
	unsigned char buf[AST_FRIENDLY_OFFSET + 640];
	const int maxsamples = ARRAY_LEN(buf);
	int i, *indexp = (int *) data;
	struct ast_frame wf = {
		.frametype = AST_FRAME_VOICE,
		.offset = AST_FRIENDLY_OFFSET,
		.src = __FUNCTION__,
	};
	ast_format_set(&wf.subclass.format, AST_FORMAT_ULAW, 0);
	wf.data.ptr = buf + AST_FRIENDLY_OFFSET;

	/* Instead of len, use samples, because channel.c generator_force
	* generate(chan, tmp, 0, 160) ignores len. In any case, len is
	* a multiple of samples, given by number of samples times bytes per
	* sample. In the case of ulaw, len = samples. for signed linear
	* len = 2 * samples */
	if (samples > maxsamples) {
		ast_log(LOG_WARNING, "Only doing %d samples (%d requested)\n", maxsamples, samples);
		samples = maxsamples;
	}

	len = samples * sizeof (buf[0]);
	wf.datalen = len;
	wf.samples = samples;

	/* create a buffer containing the digital milliwatt pattern */
	for (i = 0; i < len; i++) {
		buf[AST_FRIENDLY_OFFSET + i] = digital_milliwatt[(*indexp)++];
		*indexp &= 7;
	}

	if (ast_write(chan,&wf) < 0) {
		ast_log(LOG_WARNING,"Failed to write frame to '%s': %s\n",chan->name,strerror(errno));
		return -1;
	}

	return 0;
}
