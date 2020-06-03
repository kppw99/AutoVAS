static void CVE_2005_3848_VULN_icmp_push_reply(struct icmp_bxm *icmp_param,
			    struct ipcm_cookie *ipc, struct rtable *rt)
{
	struct sk_buff *skb;

	ip_append_data(icmp_socket->sk, icmp_glue_bits, icmp_param,
		       icmp_param->data_len+icmp_param->head_len,
		       icmp_param->head_len,
		       ipc, rt, MSG_DONTWAIT);

	if ((skb = skb_peek(&icmp_socket->sk->sk_write_queue)) != NULL) {
		struct icmphdr *icmph = skb->h.icmph;
		unsigned int csum = 0;
		struct sk_buff *skb1;

		skb_queue_walk(&icmp_socket->sk->sk_write_queue, skb1) {
			csum = csum_add(csum, skb1->csum);
		}
		csum = csum_partial_copy_nocheck((void *)&icmp_param->data,
						 (char *)icmph,
						 icmp_param->head_len, csum);
		icmph->checksum = csum_fold(csum);
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(icmp_socket->sk);
	}
}
