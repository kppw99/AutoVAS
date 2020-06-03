static void *CVE_2009_1243_PATCHED_udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct udp_iter_state *state = seq->private;
	state->bucket = UDP_HTABLE_SIZE;

	return *pos ? udp_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
}
