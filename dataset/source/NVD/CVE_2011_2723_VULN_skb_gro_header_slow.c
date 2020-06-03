static inline void *CVE_2011_2723_VULN_skb_gro_header_slow(struct sk_buff *skb, unsigned int hlen,
					unsigned int offset)
{
	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;
	return pskb_may_pull(skb, hlen) ? skb->data + offset : NULL;
}
